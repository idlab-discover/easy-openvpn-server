#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Error: please run as root!"
  exit 1
fi

if [[ "$1" == "tcp" ]]; then
    cat "$SNAP_DATA/tcp-server-status.log"
elif [[ "$1" == "udp" ]]; then
    cat "$SNAP_DATA/udp-server-status.log"
else
    echo "# TCP SERVER STATUS"
    cat "$SNAP_DATA/tcp-server-status.log"
    echo
    echo "# UDP server status:"
    cat "$SNAP_DATA/udp-server-status.log"
fi
