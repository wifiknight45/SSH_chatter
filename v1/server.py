#!/usr/bin/env python3
"""
server.py - Minimal, hardened SSH chat server using Paramiko.

Features:
- Password and public-key authentication (authorized_keys file)
- Thread-safe broadcast to all connected channels
- Max connections, per-connection idle timeout
- Host key generation if missing
- Graceful error handling and logging
"""

import argparse
import logging
import os
import socket
import threading
import time
from typing import List

import paramiko

# Configuration defaults
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 2222
DEFAULT_HOST_KEY = "host_rsa.key"
DEFAULT_AUTHORIZED_KEYS = "authorized_keys"
MAX_CONNECTIONS = 16
IDLE_TIMEOUT = 300  # seconds

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ssh-chat-server")

# Global state
clients_lock = threading.Lock()
clients: List[paramiko.Channel] = []
active_transports = set()
active_transports_lock = threading.Lock()


def load_or_create_host_key(path: str) -> paramiko.RSAKey:
    if os.path.exists(path):
        logger.info("Loading host key from %s", path)
        return paramiko.RSAKey(filename=path)
    logger.info("Generating new host key at %s", path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    os.chmod(path, 0o600)
    return key


def load_authorized_keys(path: str) -> List[str]:
    """Return list of base64 key blobs from an OpenSSH authorized_keys file."""
    keys = []
    if not os.path.exists(path):
        logger.warning("authorized_keys file not found at %s; public-key auth will be disabled", path)
        return keys
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                # parts[0] is type (ssh-rsa, ssh-ed25519, etc.), parts[1] is base64 blob
                keys.append(parts[1])
    logger.info("Loaded %d authorized public keys", len(keys))
    return keys


class ChatServer(paramiko.ServerInterface):
    def __init__(self, password_map: dict, authorized_key_blobs: List[str]):
        self.event = threading.Event()
        self.password_map = password_map
        self.authorized_key_blobs = authorized_key_blobs

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        methods = []
        if username in self.password_map:
            methods.append("password")
        if self.authorized_key_blobs:
            methods.append("publickey")
        return ",".join(methods) if methods else "none"

    def check_auth_password(self, username, password):
        expected = self.password_map.get(username)
        if expected is not None and password == expected:
            logger.info("Password auth success for %s", username)
            return paramiko.AUTH_SUCCESSFUL
        logger.warning("Password auth failed for %s", username)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        try:
            blob = key.get_base64()
            if blob in self.authorized_key_blobs:
                logger.info("Publickey auth success for %s", username)
                return paramiko.AUTH_SUCCESSFUL
            logger.warning("Publickey auth failed for %s", username)
            return paramiko.AUTH_FAILED
        except Exception:
            logger.exception("Error checking public key for %s", username)
            return paramiko.AUTH_FAILED


def broadcast_message(sender_chan: paramiko.Channel, message: str):
    with clients_lock:
        dead = []
        for c in clients:
            try:
                if c is sender_chan:
                    continue
                c.send(message.encode("utf-8"))
            except Exception:
                dead.append(c)
        for d in dead:
            try:
                clients.remove(d)
                d.close()
            except Exception:
                pass


def handle_client_channel(chan: paramiko.Channel, username: str):
    logger.info("Channel handler started for %s", username)
    with clients_lock:
        clients.append(chan)
    chan.settimeout(1.0)
    last_activity = time.time()
    try:
        chan.send(f"Welcome to SSH chat, {username}!\n".encode())
        while True:
            try:
                data = chan.recv(1024)
                if not data:
                    # remote closed
                    break
                last_activity = time.time()
                text = data.decode("utf-8", errors="replace")
                # Normalize newlines and broadcast line-by-line
                for line in text.splitlines():
                    msg = f"[{username}] {line}\n"
                    logger.debug("Broadcasting: %s", msg.strip())
                    broadcast_message(chan, msg)
            except socket.timeout:
                # check idle timeout
                if time.time() - last_activity > IDLE_TIMEOUT:
                    chan.send(b"Idle timeout, closing connection.\n")
                    break
                continue
            except Exception:
                logger.exception("Error in channel for %s", username)
                break
    finally:
        with clients_lock:
            if chan in clients:
                clients.remove(chan)
        try:
            chan.close()
        except Exception:
            pass
        logger.info("Channel closed for %s", username)


def handle_transport(t: paramiko.Transport, addr):
    username = None
    try:
        t.set_keepalive(30)
        chan = t.accept(20)
        if chan is None:
            logger.warning("No channel from %s", addr)
            return
        # Attempt to get username from transport (best-effort)
        username = t.get_username() or f"{addr[0]}:{addr[1]}"
        handle_client_channel(chan, username)
    except Exception:
        logger.exception("Transport handler error for %s", addr)
    finally:
        try:
            t.close()
        except Exception:
            pass
        with active_transports_lock:
            active_transports.discard(t)
        logger.info("Transport ended for %s", addr)


def serve(bind_addr: str, port: int, host_key_path: str, authorized_keys_path: str, password_map: dict, max_conn: int):
    host_key = load_or_create_host_key(host_key_path)
    authorized_blobs = load_authorized_keys(authorized_keys_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_addr, port))
    sock.listen(100)
    logger.info("Listening on %s:%d", bind_addr, port)

    try:
        while True:
            client, addr = sock.accept()
            with active_transports_lock:
                if len(active_transports) >= max_conn:
                    logger.warning("Max connections reached; rejecting %s", addr)
                    try:
                        client.close()
                    except Exception:
                        pass
                    continue
            logger.info("Incoming connection from %s", addr)
            try:
                t = paramiko.Transport(client)
                t.add_server_key(host_key)
                server = ChatServer(password_map, authorized_blobs)
                t.start_server(server=server)
                with active_transports_lock:
                    active_transports.add(t)
                threading.Thread(target=handle_transport, args=(t, addr), daemon=True).start()
            except Exception:
                logger.exception("Failed to start SSH transport for %s", addr)
                try:
                    client.close()
                except Exception:
                    pass
    except KeyboardInterrupt:
        logger.info("Shutting down server (KeyboardInterrupt)")
    finally:
        sock.close()
        logger.info("Server socket closed")


def parse_password_map(s: str) -> dict:
    """
    Parse a simple comma-separated username:password list.
    Example: "alice:pass1,bob:pass2"
    """
    out = {}
    if not s:
        return out
    for pair in s.split(","):
        if ":" in pair:
            u, p = pair.split(":", 1)
            out[u.strip()] = p.strip()
    return out


def main():
    parser = argparse.ArgumentParser(description="SSH chat server (Paramiko)")
    parser.add_argument("--bind", default=DEFAULT_HOST, help="Bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to listen on")
    parser.add_argument("--host-key", default=DEFAULT_HOST_KEY, help="Host private key file")
    parser.add_argument("--authorized-keys", default=DEFAULT_AUTHORIZED_KEYS, help="authorized_keys file path")
    parser.add_argument("--max-connections", type=int, default=MAX_CONNECTIONS, help="Maximum concurrent connections")
    parser.add_argument("--passwords", default="", help="Comma-separated username:password pairs for password auth")
    args = parser.parse_args()

    password_map = parse_password_map(args.passwords)
    serve(args.bind, args.port, args.host_key, args.authorized_keys, password_map, args.max_connections)


if __name__ == "__main__":
    main()
