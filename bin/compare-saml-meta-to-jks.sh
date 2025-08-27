#!/usr/bin/env bash
# Compare SAML metadata certs vs a Java keystore (JKS/PKCS12)
# Usage: compare-saml-meta-to-jks.sh <SAML_METADATA_URL> <KEYSTORE.jks|.p12>
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: compare-saml-meta-to-jks.sh <SAML_METADATA_URL> <KEYSTORE.jks|.p12>

Requires: curl, openssl, keytool (from a JRE/JDK). perl is optional.
- Password comes from env SAML_JKS_PASSWORD or will be prompted.
Outputs:
  1) Keystore aliases -> serial
  2) Metadata certs FOUND in keystore (PEM + serial + alias)
  3) Metadata certs NOT FOUND in keystore (PEM + serial)
EOF
}

(( $# == 2 )) || { usage; exit 1; }

META_URL="$1"
KS_PATH="$2"
[[ -f "$KS_PATH" ]] || { echo "ERROR: keystore not found: $KS_PATH" >&2; exit 2; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing dependency: $1" >&2; exit 3; }; }
need_cmd curl
need_cmd openssl
need_cmd keytool

# Get password (env or prompt)
STOREPASS="${SAML_JKS_PASSWORD-}"
if [[ -z "${STOREPASS}" ]]; then
  read -s -p "Keystore password: " STOREPASS; echo
fi

# Portable mktemp (works on macOS/Linux)
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/samlmeta.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

JKS_INDEX="$WORKDIR/jks_index.txt"     # SERIAL|ALIAS|PEMFILE
META_INDEX="$WORKDIR/meta_index.txt"   # SERIAL|PEMFILE
: >"$JKS_INDEX"; : >"$META_INDEX"

normalize_serial() {
  # stdin: "serial=00a1..." or "00A1..."
  # stdout: uppercase hex, no leading zeros (leave single 0 if all zeros)
  awk '{ s=$0; sub(/^serial=/,"",s); toupper(s);
         gsub(/^[0]+/,"",s); if (s=="") s="0"; print toupper(s) }'
}

echo "==[1/5] Downloading metadata..."
curl -sSL "$META_URL" -o "$WORKDIR/meta.xml"

echo "==[2/5] Extracting certs from metadata..."
if command -v perl >/dev/null 2>&1; then
  # Robust XML-ish grab; trims whitespace inside base64
  EXTRACTED="$WORKDIR/b64.list"
  perl -0777 -ne '
    while (/<[[:alnum:]:]*X509Certificate[^>]*>([^<]+)<\/[[:alnum:]:]*X509Certificate>/gi) {
      $c=$1; $c=~s/\s+//g; print "$c\n";
    }' "$WORKDIR/meta.xml" | awk '!seen[$0]++' > "$EXTRACTED"
else
  # Fallback: flatten + grep/sed (handles <ds:X509Certificate>)
  EXTRACTED="$WORKDIR/b64.list"
  tr -d '\r\n' < "$WORKDIR/meta.xml" \
  | grep -o '<[[:alnum:]:]*X509Certificate[^>]*>[^<]*</[[:alnum:]:]*X509Certificate>' \
  | sed -E 's#.*<[^>]*X509Certificate[^>]*>([^<]*)</[^>]*X509Certificate>.*#\1#' \
  | sed -E 's/[[:space:]]+//g' \
  | awk '!seen[$0]++' > "$EXTRACTED"
fi

# Write unique PEMs + serials
i=0
while IFS= read -r b64; do
  [[ -z "$b64" ]] && continue
  i=$((i+1))
  pem="$WORKDIR/meta_${i}.pem"
  {
    printf '%s\n' '-----BEGIN CERTIFICATE-----'
    printf '%s\n' "$b64" | fold -w 64
    printf '%s\n' '-----END CERTIFICATE-----'
  } > "$pem"
  serial="$(openssl x509 -in "$pem" -noout -serial | normalize_serial)"
  # de-dup by serial too
  if ! grep -q "^${serial}|" "$META_INDEX"; then
    printf '%s|%s\n' "$serial" "$pem" >> "$META_INDEX"
  else
    rm -f "$pem"
  fi
done < "$EXTRACTED"
META_COUNT=$(wc -l < "$META_INDEX" | tr -d ' ')
echo "   -> Found $META_COUNT unique certificate(s) in metadata."

echo "==[3/5] Detecting keystore type..."
STORETYPE_FLAG=""
# Try default first; if it fails, fall back to PKCS12 (newer Java defaults)
if ! keytool -list -keystore "$KS_PATH" -storepass "$STOREPASS" >/dev/null 2>&1; then
  STORETYPE_FLAG="-storetype PKCS12"
  # Try again with PKCS12; if still bad, bail with keytool error
  keytool -list $STORETYPE_FLAG -keystore "$KS_PATH" -storepass "$STOREPASS" >/dev/null
fi

echo "==[4/5] Reading keystore (aliases, serials, PEM)..."
# Grab aliases; keytool -list lines look like: "<alias>, <date>, <type>,"
keytool -list $STORETYPE_FLAG -keystore "$KS_PATH" -storepass "$STOREPASS" 2>/dev/null \
| awk -F, '/^[^,]+, /{print $1}' \
| while IFS= read -r alias; do
    [[ -z "$alias" ]] && continue
    safe_alias="$(printf '%s' "$alias" | tr -cd '[:alnum:]_.-@' | cut -c1-64)"
    pem="$WORKDIR/jks_${safe_alias}.pem"
    if keytool -exportcert -rfc $STORETYPE_FLAG -keystore "$KS_PATH" -storepass "$STOREPASS" -alias "$alias" > "$pem" 2>/dev/null; then
      serial="$(openssl x509 -in "$pem" -noout -serial | normalize_serial)"
      printf '%s|%s|%s\n' "$serial" "$alias" "$pem" >> "$JKS_INDEX"
    fi
  done
JKS_COUNT=$(wc -l < "$JKS_INDEX" | tr -d ' ')
echo "   -> Keystore contains $JKS_COUNT certificate(s)."

echo "==[5/5] Comparing..."

echo
echo "=== Certificates PRESENT in keystore (by serial) ==="
FOUND=0
while IFS='|' read -r mserial mpem; do
  if grep -q "^${mserial}|" "$JKS_INDEX"; then
    FOUND=$((FOUND+1))
    jline="$(grep "^${mserial}|" "$JKS_INDEX" | head -n1)"
    jalias="$(printf '%s' "$jline" | cut -d'|' -f2)"
    printf '## alias: %s\n## serial: %s\n' "$jalias" "$mserial"
    cat "$mpem"
    echo
  fi
done < "$META_INDEX"
(( FOUND == 0 )) && echo "(none)"

echo
echo "=== Certificates NOT FOUND in keystore (by serial) ==="
MISSING=0
while IFS='|' read -r mserial mpem; do
  if ! grep -q "^${mserial}|" "$JKS_INDEX"; then
    MISSING=$((MISSING+1))
    printf '## serial: %s (NOT IN KEYSTORE)\n' "$mserial"
    cat "$mpem"
    echo
  fi
done < "$META_INDEX"
(( MISSING == 0 )) && echo "(none)"

echo
echo "=== Keystore summary (alias -> serial) ==="
if [[ -s "$JKS_INDEX" ]]; then
  awk -F'|' '{printf "- %s  (serial %s)\n", $2, $1}' "$JKS_INDEX" | sort
else
  echo "(none)"
fi