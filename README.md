# HackingScripts

This repository contains self-made and common scripts for information gathering, enumeration and more.

### Enumeration: Initial Scans
- first_scan.sh: Performs initial nmap scan (-A, -T5, -p-)
- gobuster.sh: Performs gobuster dir scan with raft-large-words-lowercase.txt
- ssh-check-username.py: Check if user enumeration works for ssh
- GitHack.py
- [autorecon.py](https://github.com/Tib3rius/AutoRecon)
- subdomainFuzz.sh: Fuzzes subdomains for a given domain

### Enumeration: Privilege Escalation
- [LinEnum.sh](https://github.com/rebootuser/LinEnum)
- [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
- lse.sh
- unix-privesc-check.sh
- [uptux.py](https://github.com/initstring/uptux)
- [pspy64](https://github.com/DominicBreuker/pspy)

### Reverse Shell: Payloads
- genRevShell.py: Generates a reverse shell command (e.g. netcat, python, ...)
- [php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell)
- [p0wny-shell.php](https://github.com/flozz/p0wny-shell)
- [powercat.ps1][https://github.com/besimorhino/powercat]

### Miscellaneous
- upload_file.py: Starts a local tcp server, for netcat usage
- xss_handler.py: Starts a local http server and generates xss payload to steal cookies
- [padBuster.pl](https://github.com/AonCyberLabs/PadBuster)
