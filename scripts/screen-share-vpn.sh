#!/bin/sh
# Start the built app with VPN isolation for outgoing screen-share media only.
set -eu
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 /path/to/wireguard.conf [Serein executable] [app arguments...]" >&2
    exit 2
fi
SEREIN_SCREEN_WIREGUARD_CONFIG=$1
export SEREIN_SCREEN_WIREGUARD_CONFIG
shift
if [ "$#" -gt 0 ]; then
    screen_vpn_executable=$1
    shift
else
    screen_vpn_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
    screen_vpn_executable="$screen_vpn_root/dist/Serein.app/Contents/MacOS/serein"
fi
exec "$screen_vpn_executable" "$@"
