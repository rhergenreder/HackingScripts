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

function sni () {
  protocol=$1
  sni=$2
  if ! [[ "$sni" =~ ".*:[0-9]+" ]]; then
    if [[ $protocol == "https" ]]; then
      sni="$sni:443"
    else
      sni="$sni:80"
    fi
  fi

  echo $sni
}

IP_ADDRESS=$(echo $output | head -n 1 |  awk '{print $NF}')
echo "[+] IP-Address: ${IP_ADDRESS}"
echo "[ ] Retrieving default site…"
rnd=$(uuidgen)
sni=$(sni ${PROTOCOL} ${rnd}.${DOMAIN})
charcountDomain=$(curl -s "${PROTOCOL}://${DOMAIN}" -k -m 5 | wc -m)
charcountIpAddress=$(curl -s "${PROTOCOL}://${IP_ADDRESS}" -k -m 5 | wc -m)
charcountNonExistent=$(curl -s "${PROTOCOL}://${rnd}.${DOMAIN}" --resolve "${sni}:${IP_ADDRESS}" -k -m 5 | wc -m)
echo "[+] Chars: ${charcountDomain}, ${charcountIpAddress}, ${charcountNonExistent}"
echo "[ ] Fuzzing…"

(set -x; ffuf --fs ${charcountDomain},${charcountIpAddress},${charcountNonExistent} --fc 400 --mc all \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u "${PROTOCOL}://${DOMAIN}" -H "Host: FUZZ.${DOMAIN}" "${@:2}")