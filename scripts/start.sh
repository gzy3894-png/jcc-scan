#!/system/bin/sh
# alias entry (ASCII name, safe on all devices)
DIR="$(cd "$(dirname "$0")" && pwd)"
exec sh "$DIR/run-on-phone.sh" "$@"
