#!/bin/bash

download () {
  tmpfile=$(mktemp /tmp/wget.XXXXXX)
  wget --no-verbose "$1" -O "$tmpfile"
  status=$?
  if [ $status -eq 0 ]; then
    old_permissions=$(stat -c "%a" "$2")
    mv "$tmpfile" "$2"
    chmod "$old_permissions" "$2"
  fi
}

get_latest_version () {
  repository=$1
  prefix=$2
  location=$(curl -s -I https://github.com/$repository/releases/latest | grep -i "location: " | awk '{ print $2 }')
  if [[ "$location" =~ ^https://github.com/$repository/releases/tag/$prefix(.*) ]]; then
    version=${BASH_REMATCH[1]}
    version=${version%%[[:space:]]}
    echo $version
  fi
}

echo "Updating scripts…"
download https://raw.githubusercontent.com/initstring/uptux/master/uptux.py uptux.py
download https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/upc.sh unix-privesc-check.sh
download https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 pspy64
download https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32 pspy
download https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php p0wny-shell.php
download https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh lse.sh
download https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh linux-exploit-suggester.sh
download https://github.com/rebootuser/LinEnum/raw/master/LinEnum.sh LinEnum.sh
download https://github.com/stealthcopter/deepce/raw/main/deepce.sh deepce.sh

echo "Updating LinPEAS + WinPEAS…"
peas_version=$(get_latest_version carlospolop/PEASS-ng)
if [ ! -z "$peas_version" ]; then
  echo "Got PEAS version: $peas_version"
  download https://github.com/carlospolop/PEASS-ng/releases/download/$peas_version/linpeas.sh linpeas.sh
  download https://github.com/carlospolop/PEASS-ng/releases/download/$peas_version/winPEASx86.exe win/winPEAS.exe
  download https://github.com/carlospolop/PEASS-ng/releases/download/$peas_version/winPEASx64.exe win/winPEASx64.exe
  download https://github.com/carlospolop/PEASS-ng/releases/download/$peas_version/winPEAS.bat win/winPEAS.bat
else
  echo "Unable to determine latest PEAS version"
fi

echo "Updating Chisel…"
chisel_version=$(get_latest_version jpillora/chisel v)
if [ ! -z "$peas_version" ]; then
  echo "Got Chisel version: $chisel_version"
  curl -s -L "https://github.com/jpillora/chisel/releases/download/v${chisel_version}/chisel_${chisel_version}_linux_386.gz" | gzip -d > chisel
  curl -s -L "https://github.com/jpillora/chisel/releases/download/v${chisel_version}/chisel_${chisel_version}_linux_amd64.gz" | gzip -d > chisel64
  curl -s -L "https://github.com/jpillora/chisel/releases/download/v${chisel_version}/chisel_${chisel_version}_windows_386.gz" | gzip -d > win/chisel.exe
  curl -s -L "https://github.com/jpillora/chisel/releases/download/v${chisel_version}/chisel_${chisel_version}_windows_amd64.gz" | gzip -d > win/chisel64.exe
else 
  echo "Unable to determine latest chisel version"
fi

# TODO: add others
echo "Updating windows tools…"
download https://live.sysinternals.com/accesschk.exe win/accesschk.exe
download https://live.sysinternals.com/accesschk64.exe win/accesschk64.exe
