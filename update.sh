#!/bin/bash

# Usage: download <url> <destination file>
download () {
  tmpfile=$(mktemp /tmp/wget.XXXXXX)
  wget --no-verbose "$1" -O "$tmpfile"
  status=$?
  if [ $status -eq 0 ]; then
    if [ -f "$2" ]; then
      old_permissions=$(stat -c "%a" "$2")
      mv "$tmpfile" "$2"
      chmod "$old_permissions" "$2"
    else
      mv "$tmpfile" "$2"
    fi
  fi
}

# Usage: download_zip <url> <destination directory> [files]
download_zip () {
  tmpfile=$(mktemp /tmp/wget.XXXXXX)
  wget --no-verbose "$1" -O "$tmpfile"
  status=$?
  if [ $status -eq 0 ]; then
    unzip -o "$tmpfile" -d $2 "${@:3}"
  fi
}

# Usage: get_latest_version <url> <version prefix>
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
download https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py PetitPotam.py

echo ""
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

# TODO: add others
echo ""
echo "Updating windows tools…"
download https://live.sysinternals.com/accesschk.exe win/accesschk.exe
download https://live.sysinternals.com/accesschk64.exe win/accesschk64.exe
download https://github.com/int0x33/nc.exe/raw/master/nc.exe win/nc.exe
download https://github.com/int0x33/nc.exe/raw/master/nc64.exe win/nc64.exe
download https://github.com/k4sth4/Juicy-Potato/raw/main/x86/jp32.exe win/JuicyPotato.exe
download https://github.com/k4sth4/Juicy-Potato/raw/main/x64/jp.exe win/JuicyPotato64.exe
download https://github.com/uknowsec/SweetPotato/raw/master/SweetPotato-Webshell-new/bin/Release/SweetPotato.exe win/SweetPotato.exe
download https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe win/GodPotato.exe
download https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py win/PetitPotam.py

echo ""
chisel_version=$(get_latest_version jpillora/chisel v)
if [ ! -z "$chisel_version" ]; then
  echo "Got Chisel version: $chisel_version"
  curl -s -L "https://github.com/jpillora/chisel/releases/download/v${chisel_version}/chisel_${chisel_version}_linux_386.gz" | gzip -d > chisel
  curl -s -L "https://github.com/jpillora/chisel/releases/download/v${chisel_version}/chisel_${chisel_version}_linux_amd64.gz" | gzip -d > chisel64
  curl -s -L "https://github.com/jpillora/chisel/releases/download/v${chisel_version}/chisel_${chisel_version}_windows_386.gz" | gzip -d > win/chisel.exe
  curl -s -L "https://github.com/jpillora/chisel/releases/download/v${chisel_version}/chisel_${chisel_version}_windows_amd64.gz" | gzip -d > win/chisel64.exe
else 
  echo "Unable to determine latest chisel version"
fi

sharphound_version=$(get_latest_version BloodHoundAD/SharpHound v)
if [ ! -z "$sharphound_version" ]; then
  echo "Got Sharphound version: $sharphound_version"
  download_zip https://github.com/BloodHoundAD/SharpHound/releases/download/v${sharphound_version}/SharpHound-v${sharphound_version}.zip win/ SharpHound.exe SharpHound.ps1
fi

socat_version=$(get_latest_version "3ndG4me/socat" v)
if [ ! -z "$socat_version" ]; then
  echo "Got socat version: $socat_version"
  download https://github.com/3ndG4me/socat/releases/download/v${socat_version}/socatx86.bin socat
  download https://github.com/3ndG4me/socat/releases/download/v${socat_version}/socatx64.bin socat64
  download https://github.com/3ndG4me/socat/releases/download/v${socat_version}/socatx86.exe win/socat.exe
  download https://github.com/3ndG4me/socat/releases/download/v${socat_version}/socatx64.exe win/socat64.exe
fi