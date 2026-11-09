#!/bin/sh
# Build Alatyr.
#   ./build.sh        -> ./alatyr and ./awg-tester for this machine
#   ./build.sh all    -> dist/alatyr-<os>-<arch>/ for Windows, macOS and Linux,
#                        plus dist/alatyr-windows-*.zip ready to hand out
#
# Distribution extras live in packaging/<os>/ and are copied as is.
set -e
cd "$(dirname "$0")"
VERSION=$(date +%Y.%m.%d)
LDFLAGS="-s -w -X main.version=$VERSION"
export CGO_ENABLED=0

if [ "$1" != "all" ]; then
  go build -trimpath -ldflags "$LDFLAGS" -o alatyr .
  go build -trimpath -ldflags "-s -w" -o awg-tester ./cmd/awg-tester
  echo "built ./alatyr ($VERSION) and ./awg-tester"
  exit 0
fi

# Only our own outputs are replaced; anything else in dist/ is left alone.
mkdir -p dist
rm -rf dist/alatyr-*
for target in windows/amd64 windows/arm64 darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm; do
  os=${target%/*}; arch=${target#*/}
  name="alatyr-$os-$arch"
  [ "$target" = windows/amd64 ] && name=alatyr-windows-x64
  out="dist/$name"
  ext=""; [ "$os" = windows ] && ext=.exe
  mkdir -p "$out"
  GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "$out/alatyr$ext" .
  GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$out/awg-tester$ext" ./cmd/awg-tester
  cp README.md "$out/"
  if [ "$os" = windows ]; then
    cp run.bat run-hidden.vbs stop.bat autostart-windows.vbs "$out/"
    cp packaging/windows/* "$out/"
    # Hidden start has no console: log to a file. CRLF for Notepad.
    sed -e 's/^# log_file: alatyr.log/log_file: alatyr.log/' config.yaml | perl -pe 's/\r?\n/\r\n/' > "$out/config.yaml"
    (cd dist && zip -qr "$name.zip" "$name")
    echo "built $out (+ dist/$name.zip)"
  else
    cp config.yaml run.sh service.sh "$out/"
    echo "built $out"
  fi
done
