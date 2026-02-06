# Simple SSH Honeypot

A lightweight Python honeypot that emulates an SSH server and logs all authentication attempts to a JSONL file for threat intelligence and monitoring.

## Features

- Captures password authentication attempts (username + password)
- Captures public key authentication attempts (username + key fingerprint)
- Logs client SSH version strings
- JSONL output format for easy parsing
- Auto-generates RSA host key on first run
- Multi-threaded (handles concurrent connections)
- Mimics Ubuntu OpenSSH server banner

## Requirements

- Python 3.6+
- paramiko

## Installation

```bash
pip install paramiko --break-system-packages
```

## Usage

```bash
# Basic usage (listens on port 22, requires sudo)
sudo python3 ssh_honeypot.py

# Custom port (no sudo needed for ports > 1024)
python3 ssh_honeypot.py --port 2222

# Custom log file location
sudo python3 ssh_honeypot.py --logfile /var/log/ssh_honeypot.jsonl

# Name your honeypot (useful for multiple instances)
sudo python3 ssh_honeypot.py --name "vps-01"

# All options
sudo python3 ssh_honeypot.py --port 22 --logfile /var/log/ssh_honeypot.jsonl --name "my-honeypot"
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --port` | 22 | Port to listen on |
| `-l, --logfile` | ssh_honeypot.jsonl | Path to log file |
| `-n, --name` | default | Honeypot identifier for logs |

## Important: Move Your Real SSH First

Before running the honeypot on port 22, move your real SSH server to a different port:

1. Edit SSH config:
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```

2. Change the port:
   ```
   Port 2222
   ```

3. Restart SSH (keep your current session open!):
   ```bash
   sudo systemctl restart sshd
   ```

4. Open the new port in firewall:
   ```bash
   sudo ufw allow 2222/tcp
   ```

5. Test from another terminal before closing your session:
   ```bash
   ssh -p 2222 user@your-server
   ```

6. Now run the honeypot on port 22.

## Log Format

Each authentication attempt is logged as a JSON object on its own line:

```json
{
  "timestamp": "2025-02-05T14:30:00+00:00",
  "unix_timestamp": 1738765800,
  "honeypot_name": "my-honeypot",
  "remote_addr": "192.168.1.100",
  "auth_type": "password",
  "username": "root",
  "password": "admin123",
  "client_version": "SSH-2.0-libssh2_1.4.3"
}
```

### Auth Types

| Type | Description |
|------|-------------|
| `password` | Standard username/password attempt |
| `publickey` | SSH key auth (password field contains key fingerprint) |
| `none` | Client checking if auth is required |

## Analyzing Logs

```bash
# Watch logs in real-time
tail -f ssh_honeypot.jsonl

# Pretty print with jq
tail -f ssh_honeypot.jsonl | jq .

# Top 10 usernames attempted
jq -r '.username' ssh_honeypot.jsonl | sort | uniq -c | sort -rn | head -10

# Top 10 passwords attempted
jq -r '.password' ssh_honeypot.jsonl | sort | uniq -c | sort -rn | head -10

# Top 10 attacking IPs
jq -r '.remote_addr' ssh_honeypot.jsonl | sort | uniq -c | sort -rn | head -10

# All passwords tried for root
jq -r 'select(.username == "root") | .password' ssh_honeypot.jsonl | sort | uniq -c | sort -rn

# Unique username:password combinations
jq -r '"\(.username):\(.password)"' ssh_honeypot.jsonl | sort -u

# Filter by specific IP
jq 'select(.remote_addr == "45.33.12.5")' ssh_honeypot.jsonl

# Get unique SSH client versions
jq -r '.client_version' ssh_honeypot.jsonl | sort -u

# Count attempts per hour
jq -r '.timestamp[:13]' ssh_honeypot.jsonl | sort | uniq -c
```

## Running as a Service

Create `/etc/systemd/system/ssh-honeypot.service`:

```ini
[Unit]
Description=SSH Honeypot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/honeypot
ExecStart=/usr/bin/python3 /opt/honeypot/ssh_honeypot.py --port 22 --logfile /var/log/ssh_honeypot.jsonl --name "my-vps"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Setup:

```bash
# Create directory and copy files
sudo mkdir -p /opt/honeypot
sudo cp ssh_honeypot.py /opt/honeypot/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable ssh-honeypot
sudo systemctl start ssh-honeypot

# Check status
sudo systemctl status ssh-honeypot

# View logs
sudo tail -f /var/log/ssh_honeypot.jsonl
```

## Files Generated

| File | Description |
|------|-------------|
| `ssh_honeypot.jsonl` | Log file with all auth attempts |
| `honeypot_rsa.key` | Auto-generated RSA host key |

## Security Notes

- The honeypot always rejects authentication — no one can actually log in
- Host key is generated on first run and reused (consistent fingerprint)
- Runs as root only because port 22 requires it; the honeypot itself is safe
- No shell access is ever granted

## Expected Traffic

Port 22 is constantly scanned. You should see:

| Timeframe | What to expect |
|-----------|---------------|
| Minutes | First connection attempts |
| Hours | Hundreds of attempts |
| Days | Common credential lists (root/admin/test) |

Common usernames you'll see: `root`, `admin`, `ubuntu`, `test`, `guest`, `oracle`, `postgres`, `pi`, `ftpuser`

Common passwords: `123456`, `admin`, `password`, `root`, `1234`, `12345678`, `test`, `guest`

## License

MIT
