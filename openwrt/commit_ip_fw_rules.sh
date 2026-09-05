#!/bin/sh
set -eu
uci commit firewall
fw4 print | nft -f -
