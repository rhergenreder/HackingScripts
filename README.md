# HackingScripts

This repository contains self-made and common scripts for information gathering, enumeration and more.

### What is this?
I use this repository mostly for automated exploit chains. HackTheBox machines often involve steps like spawning a http server, serving a file, extracting content, steal data through custom DNS/FTP/SSH servers, spawning a reverse shell etc. Using this library I implement a script-to-root mechanism to chain all these steps together. Since the repository also includes lots of common payloads and binaries, I didn't want to put it on PyPI. If you got any recommendations for me, feel free to contact me!

### Installation
```bash
PYTHON_DIR=$(python -c "import sys;print(sys.path[-1])")

# clone directly into python site-packages
git clone https://git.romanh.de/Roman/HackingScripts.git $PYTHON_DIR/hackingscripts
# or use a symlink
git clone https://git.romanh.de/Roman/HackingScripts.git
sudo ln -s $(pwd)/HackingScripts $PYTHON_DIR/hackingscripts

# Install requirements
pip3 install -r $PYTHON_DIR/hackingscripts/requirements.txt
```

### Enumeration: Initial Scans
- first_scan.sh: Performs initial nmap scan
- gobuster.sh: Performs gobuster dir scan with raft-large-words-lowercase.txt
- subdomainFuzz.sh: Fuzzes subdomains for a given domain
- [ssh-check-username.py](https://www.exploit-db.com/exploits/45939): Check if user enumeration works for ssh
- [git-dumper.py](https://github.com/arthaud/git-dumper)

### Enumeration: Privilege Escalation & Pivoting
- [LinEnum.sh](https://github.com/rebootuser/LinEnum)
- [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
- lse.sh
- unix-privesc-check.sh
- [uptux.py](https://github.com/initstring/uptux)
- [pspy64](https://github.com/DominicBreuker/pspy)
- portscan.py: small python script, which scans open TCP ports natively with multithread support.
Can be deployed on victim machines to scan the intranet.
- pingscan.py: small python script, which can detect internal hosts via ping probes natively.
Can be deployed on victim machines to scan the intranet.
- [deepce.sh](https://github.com/stealthcopter/deepce): Docker Privilege Escalation (e.g. exposed socket)
- [socat](https://github.com/3ndG4me/socat)

### Reverse Shell: Payloads
- rev_shell.py: Generates a reverse shell command (e.g. netcat, python, ...)
- [php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell)
- [p0wny-shell.php](https://github.com/flozz/p0wny-shell)
- [aspx-reverse-shell.aspx](https://github.com/borjmz/aspx-reverse-shell)
- jsp-webshell.jsp: webshell for Java servlets

### Miscellaneous
- upload_file.py: Starts a local tcp server, for netcat usage
- xss_handler.py: Starts a local http server and generates xss payload to steal cookies
- [padBuster.pl](https://github.com/AonCyberLabs/PadBuster)
- sql.php: Execute sql queries passed via GET/POST
- util.py: Collection of some small functions
- fileserver.py: Create a temporary http server serving in-memory files
- dnsserver.py: Create a temporary dns server responding dynamically to basic DNS requests (in-memory)
- sshserver.py: Create a temporary ssh server to intercept credentials (TODO: relay) (in-memory)
- smtpserver.py: Create a temporary smtp server (in-memory)
- ftpserver.py: Create a temporary ftp server (in-memory, thanks to [@benzammour](https://github.com/benzammour))
- template.py: Creates a template for web exploits, similar to pwnlib's template
- pcap_file_extract.py: Lists and extracts files from http connections found in pcap files
- find_git_commit.py: Compares a local repository (e.g. downloaded from a remote server) with another git repository to guess the commit hash. Useful to find used versions
- TODO: smb
- sqli.py: An sqlmap-like abstract class for automizing SQL-Injections (WIP)

### [Windows](win/)
 - nc.exe/nc64.exe: netcat standalone binary
 - [mimikatz.exe](https://github.com/gentilkiwi/mimikatz)
 - [plink.exe](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html): command line PuTTY client for port forwarding
 - [powercat.ps1](https://github.com/besimorhino/powercat)
 - [winPEAS.bat](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
 - PowerView.ps1
 - [SharpHound.exe](https://github.com/BloodHoundAD/SharpHound3): BloodHound Ingestor
 - [windows-exploit-suggester.py](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
 - [aspx-reverse-shell.aspx](https://github.com/borjmz/aspx-reverse-shell)
 - [xp_cmdshell.py](https://github.com/0xalwayslucky/pentesting-tools) (thanks to [@alwayslucky](https://github.com/0xalwayslucky))
 - [PetitPotam.py](https://github.com/topotam/PetitPotam)
 - [socat.exe](https://github.com/3ndG4me/socat)
 - TODO: add all Potatoes

### Example API-Usage
TODO: Add some example code or bash commands on how to use the custom libraries, e.g. fileserver, xss_handler, etc.