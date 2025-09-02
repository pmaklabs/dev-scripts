#!/usr/bin/env bash
# infer-metadata-url.sh  —  Heuristically guess the metadata URL from a metadata XML
# Usage: infer-metadata-url.sh <metadata.xml|->

set -euo pipefail
XML="${1:-}"
[[ -z "$XML" ]] && { echo "Usage: $0 <metadata.xml|->" >&2; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
META="$TMP/meta.xml"
if [[ "$XML" == "-" ]]; then cat > "$META"; else cp "$XML" "$META"; fi

# Helpers (prefer xmllint; fallback to grep/sed if missing)
xget() {
  local xp="$1"
  if command -v xmllint >/dev/null 2>&1; then
    xmllint --xpath "string($xp)" "$META" 2>/dev/null || true
  else
    # very rough fallback for entityID and Location (best-effort)
    case "$xp" in
      '/*[local-name()="EntityDescriptor"]/@entityID')
        grep -o 'entityID="[^"]*"' "$META" | head -n1 | sed -E 's/.*entityID="([^"]*)".*/\1/' ;;
      '//*[local-name()="IDPSSODescriptor"]/*[local-name()="SingleSignOnService"][1]/@Location')
        tr -d '\r\n' < "$META" | sed -E 's/>/>\n/g' \
        | grep -o '<[^>]*SingleSignOnService[^>]*>' | head -n1 \
        | sed -E 's/.*Location="([^"]*)".*/\1/' ;;
      *) ;;
    esac
  fi
}

ENTITY_ID="$(xget '/*[local-name()="EntityDescriptor"]/@entityID')"
SSO_LOC="$(xget '//*[local-name()="IDPSSODescriptor"]/*[local-name()="SingleSignOnService"][1]/@Location')"

echo "entityID: ${ENTITY_ID:-<none found>}"
echo "SSO URL : ${SSO_LOC:-<none found>}"

host() { python3 - "$1" << 'PY' 2>/dev/null || echo ""
import sys, urllib.parse as u
print(u.urlparse(sys.argv[1]).hostname or "")
PY
}
HOST="$(host "${SSO_LOC:-}")"

echo
echo "Heuristic guesses:"
if [[ "$ENTITY_ID" =~ ^https?://sts\.windows\.net/([0-9a-fA-F-]+)/?$ ]] || [[ "$HOST" == "login.microsoftonline.com" ]]; then
  TENANT="${BASH_REMATCH[1]:-}"
  [[ -z "$TENANT" ]] && TENANT="$(echo "$SSO_LOC" | sed -nE 's#.*/login\.microsoftonline\.com/([^/]+)/.*#\1#p')"
  echo "- Azure AD:"
  [[ -n "$TENANT" ]] && echo "    Likely: https://login.microsoftonline.com/${TENANT}/federationmetadata/2007-06/federationmetadata.xml"
  echo "    Note: If you used an app-specific URL, it may have '?appid=GUID' which is NOT recoverable from metadata."
elif [[ "$HOST" =~ (^|.*\.)okta\.(com|gov|emea)$ ]]; then
  echo "- Okta:"
  echo "    Common: https://${HOST}/idp/metadata"
  echo "    App-specific: https://${HOST}/app/<appId>/sso/saml/metadata (appId not recoverable from XML)"
elif [[ "$HOST" =~ (^|.*\.)onelogin\.com$ ]]; then
  echo "- OneLogin:"
  echo "    App-specific: https://${HOST}/saml/metadata/<appId> (appId not in XML)"
elif [[ "$HOST" =~ (^|.*\.)auth0\.com$ ]]; then
  echo "- Auth0:"
  echo "    App/client-specific: https://${HOST}/samlp/metadata/<client-id>"
elif [[ "$HOST" =~ (^|.*\.)ping( identity|one)?\.com$ ]] || [[ "$SSO_LOC" =~ /idp/SSO\.saml2 ]]; then
  echo "- PingFederate/PingOne:"
  echo "    Likely: https://${HOST}/idp/metadata"
elif [[ "$HOST" =~ (^|.*\.)adfs\..*$ ]] || [[ "$SSO_LOC" =~ /adfs/ ]] || grep -qi 'Microsoft ADFS' "$META" 2>/dev/null; then
  echo "- ADFS:"
  echo "    Canonical: https://${HOST}/FederationMetadata/2007-06/FederationMetadata.xml"
else
  echo "- Unknown/other IdP:"
  echo "    Try the IdP’s UI or docs. If you know the host (${HOST:-?}), common patterns include:"
  echo "      https://${HOST}/FederationMetadata/2007-06/FederationMetadata.xml"
  echo "      https://${HOST}/idp/metadata"
fi

# Bonus: print first signing cert fingerprint (for matching against a known feed)
if command -v openssl >/dev/null 2>&1; then
  CERT_B64="$(
    tr -d '\r\n' < "$META" \
    | grep -o '<[[:alnum:]:]*X509Certificate[^>]*>[^<]*</[[:alnum:]:]*X509Certificate>' \
    | head -n1 \
    | sed -E 's#.*<[^>]*X509Certificate[^>]*>([^<]*)</[^>]*X509Certificate>.*#\1#' \
    | tr -d '[:space:]' || true
  )"
  if [[ -n "$CERT_B64" ]]; then
    echo
    echo "First signing cert SHA-256 (for matching against a known feed):"
    {
      printf '%s\n' '-----BEGIN CERTIFICATE-----'
      printf '%s\n' "$CERT_B64" | fold -w 64
      printf '%s\n' '-----END CERTIFICATE-----'
    } > "$TMP/c.pem"
    openssl x509 -in "$TMP/c.pem" -noout -fingerprint -sha256
  fi
fi