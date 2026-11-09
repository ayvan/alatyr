#!/bin/sh
# Start alatyr in the foreground from the folder this script lives in.
cd "$(dirname "$0")" || exit 1
exec ./alatyr --config config.yaml "$@"
