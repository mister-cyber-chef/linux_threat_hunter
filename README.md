# Advanced Linux Threat Hunt

A simple script that helps perform a basic Linux threat hunt and gather forensic clues.

---

## What This Script Does

This script runs some useful checks to help identify possible security issues, suspicious behavior, or IoCs on a Linux system.

- System info & uptime
- Logged-in users and suspicious account details
- Shell histories
- Running processes and memory usage
- Network services and external connections
- Cron jobs, systemd units, and autoruns
- etc.

Everything is logged to a file named like:  
`threat_hunt_<hostname>_<timestamp>.log`

---

## How to Use

```bash
chmod 775 linux_threat_hunter.sh
```
then
```bash
./linux_threat_hunter.sh
```
