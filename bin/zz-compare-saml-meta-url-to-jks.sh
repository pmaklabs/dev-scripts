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
  1) Keystore aliases -> serial + sha256
  2) Metadata certs FOUND in keystore (PEM + serial + sha256 + alias)
  3) Metadata certs NOT FOUND in keystore (PEM + serial + sha256)
  4) Final summary: NOT FOUND (serial, sha256) one-per-line
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

# Portable mktemp (macOS/Linux)
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/samlmeta.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

# Index formats:
#   META_INDEX: SERIAL|SHA256|PEMFILE
#   JKS_INDEX : SERIAL|SHA256|ALIAS|PEMFILE
JKS_INDEX="$WORKDIR/jks_index.txt"
META_INDEX="$WORKDIR/meta_index.txt"
MISSING_SUMMARY="$WORKDIR/missing_serial_sha256.txt"   # serial sha256
: >"$JKS_INDEX"; : >"$META_INDEX"; : >"$MISSING_SUMMARY"

normalize_serial() {
  # stdin: "serial=00a1..." or "00A1..."
  # stdout: UPPERCASE hex, no leading zeros (keep single 0 if all zeros)
  awk '{ s=$0; sub(/^serial=/,"",s); gsub(/^[0]+/,"",s); if (s=="") s="0"; print toupper(s) }'
}
sha256fp() {
  # stdout: UPPERCASE hex without colons
  openssl x509 -noout -fingerprint -sha256 -in "$1" \
    | awk -F= '{print toupper($2)}' | tr -d ':'
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

# Write unique PEMs + (serial, sha256) for metadata
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
  fp="$(sha256fp "$pem")"
  # De-dup by fingerprint (exact identity)
  if ! grep -q "^[^|]*|${fp}|" "$META_INDEX"; then
    printf '%s|%s|%s\n' "$serial" "$fp" "$pem" >> "$META_INDEX"
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
  keytool -list $STORETYPE_FLAG -keystore "$KS_PATH" -storepass "$STOREPASS" >/dev/null
fi

echo "==[4/5] Reading keystore (aliases, serials, sha256, PEM)..."
# keytool -list lines look like: "<alias>, <date>, <type>,"
keytool -list $STORETYPE_FLAG -keystore "$KS_PATH" -storepass "$STOREPASS" 2>/dev/null \
| awk -F, '/^[^,]+, /{print $1}' \
| while IFS= read -r alias; do
    [[ -z "$alias" ]] && continue
    safe_alias="$(printf '%s' "$alias" | tr -cd '[:alnum:]_.-@' | cut -c1-64)"
    pem="$WORKDIR/jks_${safe_alias}.pem"
    if keytool -exportcert -rfc $STORETYPE_FLAG -keystore "$KS_PATH" -storepass "$STOREPASS" -alias "$alias" > "$pem" 2>/dev/null; then
      serial="$(openssl x509 -in "$pem" -noout -serial | normalize_serial)"
      fp="$(sha256fp "$pem")"
      printf '%s|%s|%s|%s\n' "$serial" "$fp" "$alias" "$pem" >> "$JKS_INDEX"
    fi
  done
JKS_COUNT=$(wc -l < "$JKS_INDEX" | tr -d ' ')
echo "   -> Keystore contains $JKS_COUNT certificate(s)."

echo "==[5/5] Comparing..."

echo
echo "=== Certificates PRESENT in keystore (match by SHA256 or SERIAL) ==="
FOUND=0
# META_INDEX lines: SERIAL|SHA256|PEM
while IFS='|' read -r mserial mfp mpem; do
  if grep -q "^[^|]*|${mfp}|" "$JKS_INDEX" || grep -q "^${mserial}|" "$JKS_INDEX"; then
    FOUND=$((FOUND+1))
    # Prefer match by fingerprint
    jline="$(grep "^[^|]*|${mfp}|" "$JKS_INDEX" || true)"
    [[ -z "$jline" ]] && jline="$(grep "^${mserial}|" "$JKS_INDEX" | head -n1)"
    jalias="$(printf '%s' "$jline" | cut -d'|' -f3)"
    printf '## alias: %s\n## serial: %s\n## sha256: %s\n' "$jalias" "$mserial" "$mfp"
    cat "$mpem"
    echo
  fi
done < "$META_INDEX"
(( FOUND == 0 )) && echo "(none)"

echo
echo "=== Certificates NOT FOUND in keystore (by SHA256+SERIAL) ==="
MISSING=0
while IFS='|' read -r mserial mfp mpem; do
  if ! grep -q "^[^|]*|${mfp}|" "$JKS_INDEX" && ! grep -q "^${mserial}|" "$JKS_INDEX"; then
    MISSING=$((MISSING+1))
    printf '## serial: %s (NOT IN KEYSTORE)\n## sha256: %s\n' "$mserial" "$mfp"
    cat "$mpem"
    echo
    # record for final summary
    printf '%s %s\n' "$mserial" "$mfp" >> "$MISSING_SUMMARY"
  fi
done < "$META_INDEX"
(( MISSING == 0 )) && echo "(none)"

echo
echo "=== Keystore summary (alias -> serial, sha256) ==="
if [[ -s "$JKS_INDEX" ]]; then
  awk -F'|' '{printf "- %s  (serial %s, sha256 %s)\n", $3, $1, $2}' "$JKS_INDEX" | sort
else
  echo "(none)"
fi

echo
echo "=== Final summary: NOT FOUND (serial, sha256) ==="
if [[ -s "$MISSING_SUMMARY" ]]; then
  awk '{printf "- serial %s, sha256 %s\n", $1, $2}' "$MISSING_SUMMARY"
else
  echo "(none)"
fi