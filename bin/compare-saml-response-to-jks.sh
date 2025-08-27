#!/usr/bin/env bash
# Compare certs embedded in a SAMLResponse (POST binding) vs a Java keystore (JKS/PKCS12).
# Usage:
#   compare-saml-response-to-jks.sh <SAML_RESPONSE_FILE|-> <KEYSTORE.jks|.p12>
#   cat response.b64 | compare-saml-response-to-jks.sh - saml.jks
#
# Notes:
# - The first arg can be: a file containing Base64 or XML, or '-' to read from STDIN.
# - Tries to auto-detect Base64 vs XML and decode accordingly.
# - Requires: bash, curl (not used here but handy), openssl, keytool; perl optional.
# - Compares by normalized serial (and also shows SHA-256 thumbprints).
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: compare-saml-response-to-jks.sh <SAML_RESPONSE_FILE|-> <KEYSTORE.jks|.p12>

Reads a SAMLResponse (Base64 or XML). Extracts all <ds:X509Certificate> values and
compares them with the certificates in the keystore (JKS/PKCS12).

Environment:
  SAML_JKS_PASSWORD   Keystore password; if unset, prompts interactively.

Output sections:
  1) Certificates PRESENT in keystore (alias, serial, SHA256 + full PEM)
  2) Certificates NOT FOUND in keystore (serial, SHA256 + full PEM)
  3) Keystore summary (alias -> serial)
EOF
}

(( $# == 2 )) || { usage; exit 1; }

SRC="$1"
KS_PATH="$2"
[[ -f "$KS_PATH" ]] || { echo "ERROR: keystore not found: $KS_PATH" >&2; exit 2; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing dependency: $1" >&2; exit 3; }; }
need_cmd openssl
need_cmd keytool

STOREPASS="${SAML_JKS_PASSWORD-}"
if [[ -z "${STOREPASS}" ]]; then
  read -s -p "Keystore password: " STOREPASS; echo
fi

# Portable tmp dir
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/samlresp.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

RESP_RAW="$WORKDIR/resp.input"
RESP_XML="$WORKDIR/resp.xml"
META_INDEX="$WORKDIR/resp_index.txt"   # SERIAL|SHA256|PEMFILE
JKS_INDEX="$WORKDIR/jks_index.txt"     # SERIAL|SHA256|ALIAS|PEMFILE
: >"$META_INDEX"; : >"$JKS_INDEX"

normalize_serial() {
  # stdin: serial=00a1... or 00A1...
  awk '{
    s=$0; sub(/^serial=/,"",s);
    gsub(/^[0]+/,"",s);
    if (s=="") s="0";
    print toupper(s);
  }'
}

sha256fp() {
  # prints uppercase hex SHA256 (no colons)
  openssl x509 -noout -fingerprint -sha256 -in "$1" \
    | awk -F= '{print toupper($2)}' | tr -d ':'
}

is_base64_like() {
  # quick heuristic: long lines with only base64url chars
  awk 'BEGIN{ok=1}
       { if (length($0)>0 && $0 !~ /^[A-Za-z0-9+\/%=]+$/) ok=0 }
       END{exit ok?0:1}' "$1"
}

# --- 1) Read and decode the SAMLResponse into XML ---
if [[ "$SRC" == "-" ]]; then
  cat > "$RESP_RAW"
else
  cat "$SRC" > "$RESP_RAW"
fi

# If file already looks like XML, copy; else try URL-decode then Base64-decode.
if grep -q "<\?xml\|<samlp:\|<saml2p:\|<saml:" "$RESP_RAW" 2>/dev/null; then
  cp "$RESP_RAW" "$RESP_XML"
else
  # Optional URL-decode (best-effort): try python3, else perl, else skip
  URLDEC="$WORKDIR/resp.urldec"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$RESP_RAW" > "$URLDEC" <<'PY'
import sys, urllib.parse, pathlib
p = pathlib.Path(sys.argv[1]).read_text()
sys.stdout.write(urllib.parse.unquote_plus(p))
PY
  elif command -v perl >/dev/null 2>&1; then
    perl -MURI::Escape -0777 -ne 'print uri_unescape($_)' "$RESP_RAW" > "$URLDEC" || cp "$RESP_RAW" "$URLDEC"
  else
    cp "$RESP_RAW" "$URLDEC"
  fi

  # Detect base64 (-d on GNU, -D on macOS). Try both.
  if base64 -d < "$URLDEC" > "$RESP_XML" 2>/dev/null || base64 -D < "$URLDEC" > "$RESP_XML" 2>/dev/null; then
    :
  else
    echo "ERROR: Could not base64-decode input; is it a valid SAMLResponse?" >&2
    exit 4
  fi
fi

# --- 2) Extract X509Certificate blocks from the XML (ds or non-namespaced) ---
echo "==[1/4] Extracting certificates from SAMLResponse..."
EXTRACTED="$WORKDIR/b64.list"
if command -v perl >/dev/null 2>&1; then
  perl -0777 -ne '
    while (/<[[:alnum:]:]*X509Certificate[^>]*>([^<]+)<\/[[:alnum:]:]*X509Certificate>/gi) {
      $c=$1; $c=~s/\s+//g; print "$c\n";
    }' "$RESP_XML" | awk '!seen[$0]++' > "$EXTRACTED"
else
  tr -d '\r\n' < "$RESP_XML" \
  | grep -o '<[[:alnum:]:]*X509Certificate[^>]*>[^<]*</[[:alnum:]:]*X509Certificate>' \
  | sed -E 's#.*<[^>]*X509Certificate[^>]*>([^<]*)</[^>]*X509Certificate>.*#\1#' \
  | sed -E 's/[[:space:]]+//g' \
  | awk '!seen[$0]++' > "$EXTRACTED"
fi

i=0
while IFS= read -r b64; do
  [[ -z "$b64" ]] && continue
  i=$((i+1))
  pem="$WORKDIR/resp_${i}.pem"
  {
    printf '%s\n' '-----BEGIN CERTIFICATE-----'
    printf '%s\n' "$b64" | fold -w 64
    printf '%s\n' '-----END CERTIFICATE-----'
  } > "$pem"
  serial="$(openssl x509 -in "$pem" -noout -serial | normalize_serial)"
  fp="$(sha256fp "$pem")"
  # de-dup by serial+fp
  if ! grep -q "^${serial}|${fp}|" "$META_INDEX"; then
    printf '%s|%s|%s\n' "$serial" "$fp" "$pem" >> "$META_INDEX"
  else
    rm -f "$pem"
  fi
done < "$EXTRACTED"

RESP_COUNT=$(wc -l < "$META_INDEX" | tr -d ' ')
echo "   -> Found $RESP_COUNT certificate(s) embedded in SAMLResponse."
if (( RESP_COUNT == 0 )); then
  echo "WARN: No <X509Certificate> found in Response. Some IdPs send only <KeyValue> or omit KeyInfo." >&2
fi

# --- 3) Read the keystore (aliases + exported PEM + serial/fp) ---
echo "==[2/4] Reading keystore..."
STORETYPE_FLAG=""
if ! keytool -list -keystore "$KS_PATH" -storepass "$STOREPASS" >/dev/null 2>&1; then
  STORETYPE_FLAG="-storetype PKCS12"
  keytool -list $STORETYPE_FLAG -keystore "$KS_PATH" -storepass "$STOREPASS" >/dev/null
fi

# Export each alias cert (PEM). For trust entries, it's a single cert; for key entries, -exportcert returns the end-entity cert.
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

# --- 4) Compare and print ---
echo
echo "=== Certificates PRESENT in keystore (match by SERIAL or SHA256) ==="
FOUND=0
while IFS='|' read -r sserial sfp spem; do
  if grep -q "^${sserial}|" "$JKS_INDEX" || grep -q "^[^|]*|${sfp}|" "$JKS_INDEX"; then
    FOUND=$((FOUND+1))
    jline="$(grep "^${sserial}|" "$JKS_INDEX" || true)"
    [[ -z "$jline" ]] && jline="$(grep "^[^|]*|${sfp}|" "$JKS_INDEX" | head -n1)"
    jserial="$(printf '%s' "$jline" | cut -d'|' -f1)"
    jfp="$(    printf '%s' "$jline" | cut -d'|' -f2)"
    jalias="$( printf '%s' "$jline" | cut -d'|' -f3)"
    printf '## alias: %s\n## serial: %s\n## sha256: %s\n' "${jalias:-?}" "${jserial:-$sserial}" "${jfp:-$sfp}"
    cat "$spem"
    echo
  fi
done < <(cut -d'|' -f1-3 "$META_INDEX")
(( FOUND == 0 )) && echo "(none)"

echo
echo "=== Certificates NOT FOUND in keystore (by serial+SHA256) ==="
MISSING=0
while IFS='|' read -r sserial sfp spem; do
  if ! grep -q "^${sserial}|" "$JKS_INDEX" && ! grep -q "^[^|]*|${sfp}|" "$JKS_INDEX"; then
    MISSING=$((MISSING+1))
    printf '## serial: %s (NOT IN KEYSTORE)\n## sha256: %s\n' "$sserial" "$sfp"
    cat "$spem"
    echo
  fi
done < <(cut -d'|' -f1-3 "$META_INDEX")
(( MISSING == 0 )) && echo "(none)"

echo
echo "=== Keystore summary (alias -> serial, sha256) ==="
if [[ -s "$JKS_INDEX" ]]; then
  awk -F'|' '{printf "- %s  (serial %s, sha256 %s)\n", $3, $1, $2}' "$JKS_INDEX" | sort
else
  echo "(none)"
fi