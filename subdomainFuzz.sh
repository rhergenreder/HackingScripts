#!/bin/bash

if [ $# -lt 1 ]; then
  echo "Invalid usage: $0 <domain>"
  exit
fi

DOMAIN=$1
PROTOCOL="http"

if [[ $DOMAIN = https://* ]]; then
   PROTOCOL="https"
fi

DOMAIN=$(echo $DOMAIN | sed -e 's|^[^/]*//||' -e 's|/.*$||')

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
charcountDomain=$(curl -s "${PROTOCOL}://${DOMAIN}" -k -m 5 | wc -m)
charcountIpAddress=$(curl -s "${PROTOCOL}://${IP_ADDRESS}" -k -m 5 | wc -m)
charcountNonExistent=$(curl -s "${PROTOCOL}://$(uuidgen).${DOMAIN}" -k -m 5 | wc -m)
echo "[+] Chars: ${charcountDomain}, ${charcountIpAddress}, ${charcountNonExistent}"
echo "[ ] Fuzzing…"

ffuf --fs ${charcountDomain},${charcountIpAddress},${charcountNonExistent} --fc 400 --mc all \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u "${PROTOCOL}://${IP_ADDRESS}" -H "Host: FUZZ.${DOMAIN}" "${@:2}"
