#!/usr/bin/env bash
# dump-saml-certs.sh  (now supports --keep-dups)
# Usage:
#   ./dump-saml-certs.sh url  <METADATA_URL> [--keep-dups]
#   ./dump-saml-certs.sh xml  <metadata.xml> [--keep-dups]
#   ./dump-saml-certs.sh resp <response.xml> [--keep-dups]

set -Eeuo pipefail
usage(){ cat <<'EOF'
Usage:
  dump-saml-certs.sh url  <METADATA_URL> [--keep-dups]
  dump-saml-certs.sh xml  <metadata.xml> [--keep-dups]
  dump-saml-certs.sh resp <response.xml> [--keep-dups]

Notes:
- Default: unique certs (deduped by SHA-256).
- --keep-dups: print every occurrence (no dedupe) and a frequency summary.
EOF
}

(( $# >= 2 && $# <= 3 )) || { usage; exit 1; }
MODE="$1"; SRC="$2"; KEEP_DUPS="${3:-}"
KEEP_DUPLICATES=0; [[ "$KEEP_DUPS" == "--keep-dups" ]] && KEEP_DUPLICATES=1

need(){ command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing $1" >&2; exit 2; }; }
need openssl
HAVE_KEYTOOL=0; command -v keytool >/dev/null 2>&1 && HAVE_KEYTOOL=1
HAVE_PERL=0;    command -v perl    >/dev/null 2>&1 && HAVE_PERL=1
[[ "$MODE" == "url" ]] && need curl

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/saml-dump.XXXXXX")"; trap 'rm -rf "$WORKDIR"' EXIT
XML="$WORKDIR/input.xml"; OUTDIR="$WORKDIR/pems"; mkdir -p "$OUTDIR"

case "$MODE" in
  url)  curl -sSL "$SRC" -o "$XML" ;;
  xml|resp) [[ -f "$SRC" ]] || { echo "ERROR: file not found: $SRC" >&2; exit 3; }; cp "$SRC" "$XML" ;;
  *) usage; exit 1 ;;
esac

B64LIST="$WORKDIR/certs.b64"
if (( HAVE_PERL )); then
  perl -0777 -ne '
    while (/<[[:alnum:]:]*X509Certificate[^>]*>([^<]+)<\/[[:alnum:]:]*X509Certificate>/gi) {
      $c=$1; $c=~s/\s+//g; print "$c\n";
    }' "$XML" > "$B64LIST"
else
  tr -d '\r\n' < "$XML" \
  | grep -o '<[[:alnum:]:]*X509Certificate[^>]*>[^<]*</[[:alnum:]:]*X509Certificate>' \
  | sed -E 's#.*<[^>]*X509Certificate[^>]*>([^<]*)</[^>]*X509Certificate>.*#\1#' \
  | sed -E 's/[[:space:]]+//g' > "$B64LIST"
fi

sha256fp(){ openssl x509 -in "$1" -noout -fingerprint -sha256 | awk -F= '{print toupper($2)}' | tr -d ':'; }

COUNT=0
while IFS= read -r b64; do
  [[ -z "$b64" ]] && continue
  COUNT=$((COUNT+1))
  pem="$OUTDIR/raw_${COUNT}.pem"
  { printf '%s\n' '-----BEGIN CERTIFICATE-----'; printf '%s\n' "$b64" | fold -w 64; printf '%s\n' '-----END CERTIFICATE-----'; } > "$pem"
  fp=$(sha256fp "$pem")
  if (( KEEP_DUPLICATES )); then
    mv "$pem" "$OUTDIR/cert_${COUNT}.${fp}.pem"
  else
    # dedupe by fingerprint
    if ls "$OUTDIR"/*."$fp".pem >/dev/null 2>&1; then rm -f "$pem"; else mv "$pem" "$OUTDIR/cert_${COUNT}.${fp}.pem"; fi
  fi
done < "$B64LIST"

UNIQ=( "$OUTDIR"/*.pem )
[[ -e "${UNIQ[0]}" ]] || { echo "No X509Certificate elements found."; exit 0; }

i=0
for pem in "${UNIQ[@]}"; do
  i=$((i+1))
  fp_sha256=$(basename "$pem" | sed -E 's/.*\.([0-9A-F]+)\.pem/\1/')
  serial=$(openssl x509 -in "$pem" -noout -serial | sed 's/^serial=//' | tr '[:lower:]' '[:upper:]')
  echo "============================================================"
  echo "Certificate #$i  (sha256=$fp_sha256, serial=$serial)"
  echo "Source: $MODE -> $SRC"
  echo
  if (( HAVE_KEYTOOL )); then
    keytool -printcert -file "$pem" || true
  else
    openssl x509 -in "$pem" -noout -subject -issuer -serial -startdate -enddate
    echo "SHA1:   $(openssl x509 -in "$pem" -noout -fingerprint -sha1    | awk -F= '{print $2}')"
    echo "SHA256: $(openssl x509 -in "$pem" -noout -fingerprint -sha256  | awk -F= '{print $2}')"
    # Signature alg + key size (first occurrence)
    openssl x509 -in "$pem" -text -noout \
      | awk '/Signature Algorithm:/ && ++sa==1 {print "Signature algorithm name: " $0}
             /Public-Key:/ {gsub(/^ +/,""); print "Subject Public Key " $0; exit}'
  fi
  echo
done

if (( KEEP_DUPLICATES )); then
  echo "================== Duplicate summary (by SHA-256) =================="
  (ls "$OUTDIR"/*.pem | sed -E 's/.*\.([0-9A-F]+)\.pem/\1/' | sort | uniq -c \
    | awk '{printf "%5d  %s\n",$1,$2}')
fi