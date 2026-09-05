#!/bin/sh
set -eu

LAN_DEVICE=$(ip -o -4 addr show | awk '$4 ~ /^172\.30\./ {print $2; exit}')
WAN_DEVICES=$(ip -o -4 addr show | awk '$4 ~ /^172\.31\./ {print $2}')
test -n "$LAN_DEVICE"
test -n "$WAN_DEVICES"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

while uci -q delete firewall.@defaults[0]; do :; done
while uci -q delete firewall.@zone[0]; do :; done
while uci -q delete firewall.@forwarding[0]; do :; done
while uci -q delete firewall.@rule[0]; do :; done
uci -q batch <<EOF
set firewall.defaults=defaults
set firewall.defaults.input='ACCEPT'
set firewall.defaults.output='ACCEPT'
set firewall.defaults.forward='REJECT'
add firewall zone
set firewall.@zone[-1].name='lan'
set firewall.@zone[-1].device='$LAN_DEVICE'
set firewall.@zone[-1].input='ACCEPT'
set firewall.@zone[-1].output='ACCEPT'
set firewall.@zone[-1].forward='REJECT'
add firewall zone
set firewall.@zone[-1].name='wan'
set firewall.@zone[-1].input='ACCEPT'
set firewall.@zone[-1].output='ACCEPT'
set firewall.@zone[-1].forward='REJECT'
EOF
for device in $WAN_DEVICES; do
  uci add_list firewall.@zone[1].device="$device"
done
uci commit firewall
fw4 print | nft -f -

mkdir -p /var/state/osmud/mudfiles /var/state/osmud/db /run/osmud
: > /run/osmud/dnswhitelist
cp /artifacts/dhcp_event.txt /run/osmud/dhcp_event.txt
/usr/sbin/osmud -d -i -m DEBUG -e /run/osmud/dhcp_event.txt \
  -w /run/osmud/dnswhitelist -b /var/state/osmud/mudfiles \
  -x /run/osmud/osmud.pid -l /artifacts/osmud.log
