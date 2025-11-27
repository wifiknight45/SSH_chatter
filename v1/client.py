#!/usr/bin/env python3
"""
client.py - Simple SSH chat client using Paramiko.

Features:
- Password or private-key authentication
- Reconnect attempts
- Non-blocking read of stdin and SSH channel (select)
- Clean shutdown on Ctrl-C
"""

import argparse
import logging
import select
import socket
import sys
import threading
import time

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ssh-chat-client")


def interactive_session(host, port, username, password, key_filename, reconnect_attempts, reconnect_delay):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    attempts = 0
    while True:
        try:
            logger.info("Connecting to %s:%d as %s", host, port, username)
            client.connect(hostname=host, port=port, username=username, password=password,
                           key_filename=key_filename, timeout=10, banner_timeout=10, auth_timeout=10)
            transport = client.get_transport()
            if not transport or not transport.is_active():
                raise RuntimeError("Transport not active after connect")
            chan = transport.open_session()
            chan.get_pty()
            chan.invoke_shell()
            logger.info("Connected. Type messages and press Enter to send. Ctrl-C to quit.")
            run_io_loop(chan)
            # If run_io_loop returns, channel closed
            logger.info("Channel closed, disconnecting")
            client.close()
            return
        except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException) as e:
            logger.error("SSH error: %s", e)
            attempts += 1
        except (socket.error, OSError) as e:
            logger.error("Network error: %s", e)
            attempts += 1
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            try:
                client.close()
            except Exception:
                pass
            return

        if reconnect_attempts and attempts >= reconnect_attempts:
            logger.error("Max reconnect attempts reached (%d). Exiting.", reconnect_attempts)
            return
        logger.info("Reconnect in %d seconds...", reconnect_delay)
        time.sleep(reconnect_delay)


def run_io_loop(chan: paramiko.Channel):
    chan.setblocking(0)
    stdin_fd = sys.stdin.fileno()
    try:
        while True:
            r, w, x = select.select([stdin_fd, chan], [], [], 0.5)
            if chan in r:
                try:
                    data = chan.recv(4096)
                    if not data:
                        logger.info("Server closed connection")
                        break
                    sys.stdout.write(data.decode("utf-8", errors="replace"))
                    sys.stdout.flush()
                except Exception:
                    logger.exception("Error reading from channel")
                    break
            if stdin_fd in r:
                line = sys.stdin.readline()
                if not line:
                    # EOF
                    break
                try:
                    chan.send(line.encode("utf-8"))
                except Exception:
                    logger.exception("Error sending to channel")
                    break
    except KeyboardInterrupt:
        logger.info("User requested shutdown")
    finally:
        try:
            chan.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="SSH chat client (Paramiko)")
    parser.add_argument("--host", required=True, help="Server hostname or IP")
    parser.add_argument("--port", type=int, default=2222, help="Server port")
    parser.add_argument("--username", required=True, help="Username to authenticate as")
    parser.add_argument("--password", help="Password (optional if using key)")
    parser.add_argument("--key", help="Private key file (optional)")
    parser.add_argument("--reconnect-attempts", type=int, default=5, help="Reconnect attempts (0 = infinite)")
    parser.add_argument("--reconnect-delay", type=int, default=5, help="Seconds between reconnect attempts")
    args = parser.parse_args()

    interactive_session(args.host, args.port, args.username, args.password, args.key, args.reconnect_attempts, args.reconnect_delay)


if __name__ == "__main__":
    main()
