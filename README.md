# SSH_chatter
 minimal, hardened SSH chat server using Paramiko
# ssh-chat-py

Minimal SSH-based chat implemented in Python using Paramiko.  
Designed as a simple, secure chat for small groups: run the server on a reachable host and connect with the client from Windows or Linux.

## Features
- **Password and public-key authentication** (supports `authorized_keys` file)
- **Thread-safe broadcasting** to all connected clients
- **Connection limits**, **idle timeouts**, and robust error handling
- Works on **Windows** (client) and **Debian live** systems (server/client run from USB or `/tmp`)

## Quick start

### 1. Install dependencies
```bash

pip install -r requirements.txt

### 2. Prepare server


Place server.py and authorized_keys (optional) on the host.


Optionally provide password accounts via --passwords (format: alice:pass1,bob:pass2).


### Start server:


python3 server.py --bind 0.0.0.0 --port 2222 --host-key host_rsa.key --authorized-keys authorized_keys --passwords "alice:secret"


On first run the server will generate host_rsa.key if missing.


### 3. Connect with client


From any machine with Python and Paramiko:


bash

python3 client.py --host your.server.ip --port 2222 --username alice --password secret


OR using a private key:


python3 client.py --host your.server.ip --username alice --key /path/to/id_rsa

Security notes
Prefer public-key auth: add your public key to the server's authorized_keys.

Keep the host key (host_rsa.key) private and protected (chmod 600).

On non-persistent systems (live USB), keep scripts and keys on the USB or re-copy them each session.

Configuration hints
Max connections: change --max-connections on the server.

Idle timeout: edit IDLE_TIMEOUT in server.py or modify the code to accept a CLI flag.

Logging: uses Python logging; adjust basicConfig level for more/less verbosity.

Possible additions

TLS-wrapped control channel or additional encryption layers

Systemd unit and Windows service installer for persistent deployment
