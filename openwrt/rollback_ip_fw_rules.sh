#!/bin/sh
set -eu
uci revert firewall
fw4 print | nft -f -
