# Saharo

**Saharo** is a self-hosted platform for deploying and managing VPN infrastructure using a single CLI.

It handles everything that is usually painful:
Docker, configuration files, bootstrap, server registration, protocol setup, and updates — all automated.

> You control everything from your local machine.  
> All infrastructure runs on Linux servers.

---

## ✨ Features

- 🚀 One-command **host (Hub API) bootstrap**
- 🌍 **Remote server (agent) deployment** over SSH
- 🔐 License and configuration stored centrally on the host
- 📦 Fully Docker-based (no manual config editing)
- 🔌 Protocol bootstrapping (Xray / VLESS Reality, Amnezia-WG, etc.)
- 🧠 Clear, human-readable CLI output (not raw tracebacks)
- 🖥️ Works perfectly from Windows, Linux, or macOS (CLI only)

---

## 🧩 Architecture Overview

- Your machine (CLI)
- ├─ Windows / Linux / macOS
- │
- ▼
- Host (Hub API, Linux)
- ├─ API + Database
- │
- ▼
- Servers (Agents, Linux)
- ├─ VPN services


- **CLI** — control plane only
- **Host** — central API + state + license storage
- **Servers** — VPN runtime nodes

---

## ⚙️ Requirements

### Local machine (CLI)
- Windows / Linux / macOS
- SSH access to servers


---

### Remote servers
- Linux (Ubuntu LTS 22.04 or higher / Debian 11 or higher recommended)
- Docker + Docker Compose
- Open ports depending on selected protocols

---

## 📥 Installing the CLI

### Option 1: Prebuilt binary (recommended)
1. Download the `saharo` binary for your platform
2. Add it to your `PATH`
3. Verify installation:
   ```bash
   saharo --help

Option 2: Python package (advanced users)

pip install saharo

🚀 Quick Start
1️⃣ Prepare a Host server

    Clean Linux VPS

    Root or sudo access

    Ports 80 and 443 open

2️⃣ Bootstrap the Host (Hub API)

saharo host bootstrap --ssh-host root@HOST_IP

What this does:

    Generates Docker config and .env

    Deploys and starts the Hub API

    Stores the license directly in the host database

✅ No separate license activation step required.
3️⃣ Initialize local CLI settings

saharo settings init

Provide the public API URL (e.g. api.example.com).
4️⃣ Login

saharo auth login

Use the admin credentials created during host bootstrap.
5️⃣ Bootstrap a Server (Agent)

saharo servers bootstrap \
  --ssh root@SERVER_IP \
  --name my-server \
  --host my-server.example.com

The server will:

    Deploy runtime containers

    Register itself with the host

    Appear online automatically

Check status:

saharo servers status

🔌 Deploying VPN Protocols

Example: bootstrap Xray (VLESS Reality) on server 2:

saharo servers protocol bootstrap xray --server 2

Check job status:

saharo jobs get 4

🧾 Common Commands
List servers

saharo servers status

Inspect a job

saharo jobs get <job_id>

View host logs (on the host server)

docker compose -f /opt/saharo/host/docker-compose.yml logs -f api

❓ FAQ
Can I run the host or agents on Windows?

No.

Windows is supported only as a CLI controller.
All runtime components must run on Linux.
Do I need saharo auth activate?

No.

License activation is handled automatically during host bootstrap and stored on the host.
Where is data stored?

    Host: /opt/saharo/host

    Agents: /opt/saharo/agent

🧠 Design Philosophy

    CLI-first

    Zero manual configuration

    Explicit commands, predictable behavior

    Friendly errors instead of cryptic failures

    Windows is a controller, Linux is the execution environment

🛠 Developer Notes

    Written in Python (Typer)

    Docker-based architecture

    Strict separation of local vs remote paths

    POSIX paths are always used for remote execution

📄 License

See LICENSE for details.