#!/usr/bin/env python3
"""
Simple SSH Honeypot

A lightweight honeypot that emulates an SSH server and logs all authentication attempts.
Captures: IP address, username, password, client version, timestamp.

Requirements:
    pip install paramiko --break-system-packages

Usage:
    python ssh_honeypot.py [--port PORT] [--logfile LOGFILE] [--name NAME]

First run will generate SSH host keys automatically.
"""

import argparse
import json
import socket
import threading
import paramiko
from datetime import datetime, timezone
from pathlib import Path


# Generate or load host key
def get_host_key(key_file="honeypot_rsa.key"):
    key_path = Path(key_file)
    if key_path.exists():
        print(f"[*] Loading existing host key: {key_file}")
        return paramiko.RSAKey(filename=key_file)
    else:
        print(f"[*] Generating new host key: {key_file}")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_file)
        return key


class HoneypotSSHServer(paramiko.ServerInterface):
    """SSH Server interface that rejects all auth but logs attempts."""
    
    def __init__(self, client_ip, log_file, honeypot_name):
        self.client_ip = client_ip
        self.log_file = log_file
        self.honeypot_name = honeypot_name
        self.client_version = None
        self.event = threading.Event()
    
    def log_attempt(self, username, password=None, auth_type="password"):
        """Log authentication attempt to JSONL file."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unix_timestamp": int(datetime.now(timezone.utc).timestamp()),
            "honeypot_name": self.honeypot_name,
            "remote_addr": self.client_ip,
            "auth_type": auth_type,
            "username": username,
            "password": password,
            "client_version": self.client_version
        }
        
        with open(self.log_file, "a") as f:
            f.write(json.dumps(record) + "\n")
        
        # Console output
        if password:
            print(f"[{record['timestamp']}] {self.client_ip} - {username}:{password}")
        else:
            print(f"[{record['timestamp']}] {self.client_ip} - {username} ({auth_type})")
        
        return record
    
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username, password):
        """Log password auth attempts - always reject."""
        self.log_attempt(username, password, "password")
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """Log public key auth attempts - always reject."""
        key_type = key.get_name()
        key_fingerprint = key.get_fingerprint().hex()
        self.log_attempt(
            username, 
            password=f"PUBKEY:{key_type}:{key_fingerprint}", 
            auth_type="publickey"
        )
        return paramiko.AUTH_FAILED
    
    def check_auth_none(self, username):
        """Log none auth attempts - always reject."""
        self.log_attempt(username, None, "none")
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        """Allow password and publickey auth methods."""
        return "password,publickey"
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, 
                                   pixelwidth, pixelheight, modes):
        return True


def handle_connection(client_socket, client_addr, host_key, log_file, honeypot_name):
    """Handle a single SSH connection."""
    client_ip = client_addr[0]
    
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        transport.add_server_key(host_key)
        
        server = HoneypotSSHServer(client_ip, log_file, honeypot_name)
        
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            print(f"[!] SSH negotiation failed from {client_ip}: {e}")
            return
        
        # Get client version after connection
        server.client_version = transport.remote_version
        
        # Wait for auth attempts (timeout after 60 seconds)
        channel = transport.accept(60)
        
        if channel is not None:
            # If somehow they get a channel, just close it
            channel.close()
    
    except socket.error as e:
        print(f"[!] Socket error from {client_ip}: {e}")
    except EOFError:
        print(f"[!] Connection closed by {client_ip}")
    except Exception as e:
        print(f"[!] Error handling {client_ip}: {e}")
    finally:
        try:
            transport.close()
        except:
            pass
        client_socket.close()


def run_honeypot(port=22, log_file="ssh_honeypot.jsonl", honeypot_name="default"):
    """Start the SSH honeypot server."""
    
    # Get or generate host key
    host_key = get_host_key()
    
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(("", port))
    except PermissionError:
        print(f"[!] Permission denied binding to port {port}")
        print(f"[!] Try running with sudo or use a port > 1024")
        return
    except OSError as e:
        print(f"[!] Could not bind to port {port}: {e}")
        return
    
    server_socket.listen(100)
    
    print("=" * 55)
    print("  SSH Honeypot Starting")
    print("=" * 55)
    print(f"  Name:      {honeypot_name}")
    print(f"  Port:      {port}")
    print(f"  Log file:  {log_file}")
    print(f"  Host key:  honeypot_rsa.key")
    print("=" * 55)
    print("  Listening for connections...\n")
    
    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            print(f"[+] Connection from {client_addr[0]}:{client_addr[1]}")
            
            # Handle each connection in a new thread
            thread = threading.Thread(
                target=handle_connection,
                args=(client_socket, client_addr, host_key, log_file, honeypot_name)
            )
            thread.daemon = True
            thread.start()
    
    except KeyboardInterrupt:
        print("\n\n[*] Shutting down honeypot...")
    finally:
        server_socket.close()


def main():
    parser = argparse.ArgumentParser(
        description="Simple SSH Honeypot - Logs all authentication attempts"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=22,
        help="Port to listen on (default: 22)"
    )
    parser.add_argument(
        "-l", "--logfile",
        type=str,
        default="ssh_honeypot.jsonl",
        help="Log file path (default: ssh_honeypot.jsonl)"
    )
    parser.add_argument(
        "-n", "--name",
        type=str,
        default="default",
        help="Honeypot name for identification (default: default)"
    )
    
    args = parser.parse_args()
    run_honeypot(port=args.port, log_file=args.logfile, honeypot_name=args.name)


if __name__ == "__main__":
    main()
