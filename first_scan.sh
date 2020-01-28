#!/usr/bin/bash

if [ $# -lt 1 ]; then
  echo "Invalid usage: $0 <host>"
  exit
fi

if [ "$EUID" -ne 0 ]; then
  echo "[-] Script requires root permissions (e.g. nmap scan)"
  exit
fi

IP_ADDRESS=$1

echo "[+] Checking online status…"
ping -c1 -W1 -q "${IP_ADDRESS}" &>/dev/null
status=$(echo $?)

if ! [[ $status == 0 ]] ; then
  echo "[-] Target not reachable"
  exit
fi

echo "[+] Scanning for open ports…"
nmap -A "${IP_ADDRESS}" -p 1-65535 -T 5 --stats-every 30s
