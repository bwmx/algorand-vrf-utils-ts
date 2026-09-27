#!/bin/sh
# Builds wasm/vrf.wasm from tmc/vrf/draft03 and refreshes the files shipped with it (requires Go 1.24+).
set -e
cd "$(dirname "$0")"
GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -ldflags='-s -w' -o ../wasm/vrf.wasm .
install -m 644 "$(go env GOROOT)/lib/wasm/wasm_exec.js" ../wasm/
# vrf.wasm embeds the Go runtime and these modules; their BSD licenses require shipping the notices.
{
  echo '# Third-party notices'
  echo
  echo '`wasm/vrf.wasm` and `wasm/wasm_exec.js` are built from the following components.'
  printf '\n## Go (%s)\n\n```\n' "$(go env GOVERSION)"
  cat "$(go env GOROOT)/LICENSE"
  echo '```'
  GOOS=js GOARCH=wasm go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' . |
    sort -u | while read -r path version dir; do
      printf '\n## %s %s\n\n```\n' "$path" "$version"
      cat "$dir/LICENSE"
      echo '```'
    done
} >../THIRD_PARTY_NOTICES.md
