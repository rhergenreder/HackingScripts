#!/bin/bash

if [ $# -lt 1 ]; then
  echo "Invalid usage: $0 <domain>"
  exit
fi

DOMAIN=$1

echo "[ ] Resolving IP-Address…"
output=$(resolveip $DOMAIN 2>&1)
status=$(echo $?)
if ! [[ $status == 0 ]] ; then
  echo "[-] ${output}"
  exit
fi

IP_ADDRESS=$(echo $output | head -n 1 |  awk '{print $NF}')
echo "[+] IP-Address: ${IP_ADDRESS}"

echo "[ ] Retrieving default site…"
charcount=$(curl -s -L $DOMAIN | wc -m)
echo "[+] Chars: ${charcount}"
echo "[ ] Fuzzing…"

wfuzz --hh ${charcount} --ip "${IP_ADDRESS}" --hc 400,500 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt "http://FUZZ.${DOMAIN}"
