#!/bin/bash

# ───────────────────────────────────────────────
# Advanced Linux Threat Hunt
# Author: mr.cyberchef
# ───────────────────────────────────────────────

OUTFILE="threat_hunt_$(hostname)_$(date +%F_%H%M%S).log"
exec > >(tee -a "$OUTFILE") 2>&1
echo "[*] Linux Threat Hunt Started: $(date)"
echo "--------------------------------------------------"

# ───────────────────────────────────────
# BASIC SYSTEM INFO
# ───────────────────────────────────────
echo -e "\n[+] Basic System Info"
hostnamectl 2>/dev/null || uname -a
echo "[*] OS:"; cat /etc/*release 2>/dev/null | grep -Ei 'name|version'
echo "[*] Uptime:"; uptime

# ───────────────────────────────────────
# USER CONTEXT
# ───────────────────────────────────────
echo -e "\n[+] User Information and Sessions"
echo "[*] Currently logged-in users:"; who
echo "[*] Recently logged-in users:"; last -a | head -n 20
echo "[*] Users with UID 0:"; awk -F: '$3 == 0 { print $1 }' /etc/passwd

echo "[*] Suspicious /etc/passwd or /etc/shadow permissions:"
ls -l /etc/passwd /etc/shadow

# ───────────────────────────────────────
# SHELL HISTORIES
# ───────────────────────────────────────
echo -e "\n[+] Checking Shell Histories"
for h in $(find /home /root -name ".*_history" -o -name ".bash_history" 2>/dev/null); do
    echo "[*] History from $h:"; tail -n 20 "$h"
done

# ───────────────────────────────────────
# PROCESS ENUMERATION
# ───────────────────────────────────────
echo -e "\n[+] Running Processes and Anomalies"
echo "[*] Top memory consumers:"
ps aux --sort=-%mem | head -n 10

echo "[*] Processes without full paths:"
ps -eo pid,ppid,cmd | awk '$3 !~ /^\// { print }' | grep -v 'grep'

echo "[*] Processes with deleted executables:"
lsof | grep '(deleted)' | grep -vE 'bash|history'

# ───────────────────────────────────────
# NETWORK & LISTENING SERVICES
# ───────────────────────────────────────
echo -e "\n[+] Network Services and Connections"
echo "[*] Listening Ports:"
ss -tulpen 2>/dev/null || netstat -tulpen

echo "[*] Connections to External IPs:"
ss -antu | grep -v '127.0.0.1' | grep ESTAB

echo "[*] Suspicious binaries using networking:"
lsof -i -nP | grep -vE 'sshd|nginx|apache|systemd|dns'

# ───────────────────────────────────────
# CRON, SYSTEMD, & AUTORUN
# ───────────────────────────────────────
echo -e "\n[+] Persistence Mechanisms"

echo "[*] System Crontab:"
cat /etc/crontab 2>/dev/null
ls -al /etc/cron* 2>/dev/null

echo "[*] User Crontabs:"
for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u "$u" 2>/dev/null && echo "---"; done

echo "[*] Suspicious systemd units:"
grep -r "ExecStart" /etc/systemd/system/ 2>/dev/null | grep -vE 'sshd|network|dbus|cron'

echo "[*] rc.local content (legacy autorun):"
[ -f /etc/rc.local ] && cat /etc/rc.local

# ───────────────────────────────────────
# FILESYSTEM THREATS
# ───────────────────────────────────────
echo -e "\n[+] Searching Suspicious Files"

echo "[*] Executables in writable/temp paths:"
find /tmp /var/tmp /dev/shm -type f -perm -111 -exec ls -lah {} \; 2>/dev/null

echo "[*] SUID/SGID binaries not in standard dirs:"
find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/bin/*" -not -path "/usr/bin/*" 2>/dev/null

echo "[*] Hidden files across system:"
find / -name ".*" -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -n 20

echo "[*] Recently modified binaries in /bin, /usr/bin, /sbin:"
find /bin /usr/bin /sbin -type f -mtime -3 -ls 2>/dev/null

# ───────────────────────────────────────
# ENCODED / OBFUSCATED FILES
# ───────────────────────────────────────
echo -e "\n[+] Looking for Base64/Obfuscation Signs"

echo "[*] Files with long base64-looking strings:"
grep -rE '[A-Za-z0-9+/]{100,}={0,2}' /tmp /dev/shm /var/tmp /home 2>/dev/null | head -n 10

echo "[*] Scanning encoded bash payloads (base64/echo|eval chains):"
grep -rEi 'echo.*base64.*\|.*bash' /tmp /dev/shm /var/tmp /home 2>/dev/null | head -n 10

# ───────────────────────────────────────
# LOG FILES & AUTH EVENTS
# ───────────────────────────────────────
echo -e "\n[+] Authentication & Security Logs"
LOGFILE=""
[[ -f /var/log/auth.log ]] && LOGFILE="/var/log/auth.log"
[[ -f /var/log/secure ]] && LOGFILE="/var/log/secure"
echo "[*] Using: $LOGFILE"
tail -n 50 "$LOGFILE" 2>/dev/null

echo "[*] Unsuccessful login attempts:"
grep -i 'fail\|invalid' "$LOGFILE" 2>/dev/null | tail -n 10

echo "[*] Sudo usage:"
grep -i 'sudo' "$LOGFILE" 2>/dev/null | tail -n 10

# ───────────────────────────────────────
# SHELL PROFILE ABUSE
# ───────────────────────────────────────
echo -e "\n[+] Shell RC File Abuse"

for u in $(cut -f1 -d: /etc/passwd); do
    H=$(eval echo ~$u)
    for f in ".bashrc" ".bash_profile" ".profile"; do
        [ -f "$H/$f" ] && echo "[*] $H/$f:" && grep -Ev '^#|^$' "$H/$f"
    done
done

# ───────────────────────────────────────
# ALIASES & ENV MANIPULATION
# ───────────────────────────────────────
echo -e "\n[+] Checking for Suspicious Aliases & Environment Vars"
alias
env | grep -i 'LD_PRELOAD\|LD_LIBRARY_PATH'

# ───────────────────────────────────────
# DNS & NETWORK CONTEXT
# ───────────────────────────────────────
echo -e "\n[+] DNS and Network Info"
echo "[*] /etc/resolv.conf:"; cat /etc/resolv.conf
echo "[*] Routing table:"; ip r 2>/dev/null || route -n

# ───────────────────────────────────────
# FINAL
# ───────────────────────────────────────
echo -e "\n[✔] Threat Hunt Complete!"
echo "[*] Full results saved to: $OUTFILE"
