# HackingScripts

This repository contains self-made and common scripts for information gathering, enumeration and more.

### Enumeration: Initial Scans
- first_scan.sh: Performs initial nmap scan (-A, -T5, -p-)
- gobuster.sh: Performs gobuster dir scan with raft-large-words-lowercase.txt
- ssh-check-username.py: Check if user enumeration works for ssh

### Enumeration: Privilege Escalation
- LinEnum.sh
- linpeas.sh
- lse.sh
- unix-privesc-check.sh
- uptux.py
- pspy64

### Reverse Shell: Payloads
- genRevShell.py: Generates a reverse shell command (e.g. netcat, python, ...)
- php-reverse-shell.php
- p0wny-shell.php

### Miscellaneous
- upload_file.py: Starts a local tcp server, for netcat usage
