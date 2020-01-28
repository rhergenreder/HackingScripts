#!/usr/bin/bash

if [ $# -lt 1 ]; then
  echo "Invalid usage: $0 <host>"
  exit
fi

HOST=$1
EXTENSIONS=""

if [ $# -gt 1 ]; then
  EXTENSIONS="-x ${2}"
fi

gobuster dir --url="${HOST}" --wordlist="/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt" \
  -k "${EXTENSIONS}" -b "403,404"
