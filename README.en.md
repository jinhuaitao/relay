<p align="right">
   <strong>English</strong> | <a href="./README.md">中文</a>
</p>

# 🌐 GoRelay Pro

<p align="center">
<strong>Secure, Lightweight & Powerful Distributed Intranet Penetration & Port Forwarding Console</strong>
</p>

<p align="center">

[![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat&logo=go)](https://golang.org/dl/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Alpine-lightgrey)](https://www.alpinelinux.org/)
[![Architecture](https://img.shields.io/badge/Architecture-Master%2FAgent-blue)](https://github.com/jinhuaitao/relay)
[![Database](https://img.shields.io/badge/Database-SQLite3-003B57?style=flat&logo=sqlite)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Stars](https://img.shields.io/github/stars/jinhuaitao/relay?style=flat&color=gold)](https://github.com/jinhuaitao/relay/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/jinhuaitao/relay?style=flat)](https://github.com/jinhuaitao/relay/commits)

</p>

---

**GoRelay Pro** is a distributed intranet penetration and port forwarding console written entirely in Go. Built on a Master-Agent architecture, it requires no complex configuration files. With just a single binary, you can deploy a modern web-based panel to manage all network nodes, schedule traffic, and monitor performance in real-time.

<p align="center">
<a href="https://gorelay.888021.xyz">
<img src="https://img.shields.io/badge/🚀-Visit_Website-c71a36" alt="Website"/>
</a>
<a href="https://github.com/jinhuaitao/relay">
<img src="https://img.shields.io/badge/📂-View_Source-2088ff" alt="GitHub"/>
</a>
<a href="https://github.com/jinhuaitao/relay/releases">
<img src="https://img.shields.io/badge/⬇️-Download_Latest-4kbhit" alt="Download"/>
</a>
</p>

---

## 📑 Table of Contents

- [✨ Key Features](#-key-features)
- [🏗️ System Architecture](#️-system-architecture)
- [📚 Quick Start](#-quick-start)
- [🔧 Deployment Guide](#-deployment-guide)
- [🛠️ Common Commands](#️-common-commands)
- [⚠️ FAQ](#️-faq)
- [🖥️ Interface Preview](#️-interface-preview)

---

## ✨ Key Features

### 🚀 Powerful Forwarding & Traffic Scheduling

| Feature | Description |
|---------|-------------|
| **Full Protocol Support** | Supports TCP, UDP, and dual-stack (TCP+UDP) port forwarding, fully compatible with IPv4 & IPv6 environments |
| **High-Availability Load Balancing** | Built-in 4 intelligent distribution strategies for multi-target IP scenarios |
| **Precise Rate Limiting** | Supports exact traffic limits per rule (auto circuit breaker when threshold is reached) and maximum bandwidth peak limiting |

**Load Balancing Strategies:**
- `Random` — Random distribution
- `Round Robin` — Sequential distribution
- `Least Conn` — Least connections first
- `Fastest` — Lowest latency/Ping priority (ideal for active-passive failover)

### 🛡️ Enterprise-Grade Security

| Feature | Description |
|---------|-------------|
| **Auto TLS** | Automatic Let's Encrypt certificate issue and renewal. Panel access and Agent communication both use high-strength TLS encrypted tunnels by default |
| **Multi-Factor Authentication** | Built-in GitHub OAuth one-click login. Supports Google Authenticator (2FA) two-factor dynamic verification code |
| **Anti-Brute Force** | Built-in brute force protection. Consecutive password failures will automatically ban the source IP |

### 📱 Modern Web UI & PWA

| Feature | Description |
|---------|-------------|
| **Real-time Monitoring Dashboard** | WebSocket-based millisecond-level status sync. Dynamic charts show global Tx/Rx real-time rates, node load, and traffic rankings |
| **PWA Native Experience** | Supports one-click "Add to Home Screen". Transforms into a standalone app with immersive fullscreen experience, dynamic vector icons, and persistent login even after background termination |

### 🤖 Telegram Bot Assistant

| Feature | Description |
|---------|-------------|
| **Inline Keyboard** | Send `/menu` to bring up the full keyboard menu. No need to type commands on mobile — one-click status check, seamless start/stop of forwarding rules |
| **Automated Traffic Management** | Set monthly billing reset day. System automatically executes network-wide traffic reset at midnight |
| **Tiered Alerts** | Warning triggered at 80% and 95% traffic usage; auto precise circuit breaker at 100% with alert notification |
| **Scheduled Cloud Backup** | Every Monday at midnight, core database is automatically packaged and sent to your Telegram as an encrypted file |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Internet                                   │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          │                                 │
    ┌─────▼─────┐              ┌─────▼─────┐
    │   Panel   │   TLS/HTTPS  │   Node    │
    │  (Master) │◄────────────►│  (Agent)  │
    │   :443    │  Encrypted   │   :8888   │
    └─────┬─────┘              └───────────┘
          │
    ┌─────▼─────┐
    │ SQLite DB │
    │ (data.db) │
    └───────────┘
```

| Component | Role | Description |
|-----------|------|-------------|
| **Master** | Relay Server | Server with public IP, used to deploy the control panel |
| **Agent** | Node Server | Server(s) used for actual traffic forwarding (one or multiple) |

---

## 📚 Quick Start

### ⚡ One-Click Installation (Recommended)

```bash
curl -o relay.sh https://raw.githubusercontent.com/jinhuaitao/relay/master/relay.sh && chmod +x relay.sh && ./relay.sh
```

### 🐳 Docker Deployment

```bash
mkdir -p gorelay && cd gorelay
docker run -d --name relay-master \
 --restart=always \
 --net=host \
 -v relay_data:/app \
 jhtone/relay -mode master
```

### 🔨 Build from Source

```bash
# 1. Clone the repository
git clone https://github.com/jinhuaitao/relay.git
cd relay

# 2. Build for Linux 64-bit
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o relay main.go

# 3. Make executable
chmod +x relay

# 4. First run (will auto-enter setup wizard)
./relay -mode master
```

---

## 🔧 Deployment Guide

### 📋 Step 1: Prepare Servers

| Server | Requirements |
|--------|--------------|
| **Master (Relay Server)** | Must have a public IP, used to deploy the control panel |
| **Agent (Node Server)** | Server(s) used for actual traffic forwarding (one or multiple) |

> 💡 **Recommendation**: Prepare two subdomains, for example:
> - `panel.yourdomain.com` — For panel access
> - `node.yourdomain.com` — For node communication

---

### 📋 Step 2: Initialize Master

After first run, visit **http://your-server-ip:8888** to enter the setup wizard and create the initial admin account.

After logging into the panel, go to **"System Settings"** → Configure your domain:

| Setting | Description |
|---------|-------------|
| **Panel Access Domain** | Enter `panel.yourdomain.com` (you can enable Cloudflare orange cloud ☁️ to hide the panel IP) |
| **Node Communication Domain** | Enter `node.yourdomain.com` (must resolve to real IP, **do NOT** enable Cloudflare cloud) |

> ⚠️ **Important**: Services will auto-restart after saving. The panel will automatically bind ports 80 and 443, and apply for a valid HTTPS certificate!

---

### 📋 Step 3: Configure Telegram Notifications (Optional)

1. Apply for a Telegram Bot and get the Token
2. Enter the Bot Token and Chat ID in the panel
3. Send `/menu` to the bot to activate the smart interaction center
4. Set auto traffic reset day (e.g., 1st of each month)

---

### 📋 Step 4: Add Agent Nodes

1. Log into the HTTPS panel with the green secure lock
2. Go to **"Node Deployment"** page
3. Enter node name, architecture, and generate the one-click installation command
4. Copy the script to the target server and execute

> 🔒 Nodes will automatically connect to Master via secure TLS tunnel

---

## 🛠️ Common Commands

### 🐧 Debian / Ubuntu

```bash
# Check status
systemctl status relay

# Restart panel
systemctl restart relay

# Stop/Start service
systemctl stop relay
systemctl start relay

# View real-time logs
journalctl -u relay -f

# View last 50 lines of logs
journalctl -u relay -n 50

# Completely uninstall
/root/relay -service uninstall -mode master
```

### ⛰️ Alpine Linux

```bash
# Check status
rc-service relay status

# Restart panel
rc-service relay restart

# Stop/Start service
rc-service relay stop
rc-service relay start

# View real-time logs
tail -f /var/log/relay.log

# View last 50 lines of logs
tail -n 50 /var/log/relay.log

# Uninstall and disable auto-start
/root/relay -service uninstall -mode master
```

---

## ⚠️ FAQ

### 🔐 Port Firewall Rules

| Port | Purpose |
|------|---------|
| `80` / `443` | HTTPS and certificate application |
| `8888` | Default Web when no domain is configured |
| `9999` | Agent communication |

### ☁️ Cloudflare CDN Pitfalls

- ✅ Web panel domain can use CDN (enable orange cloud)
- ❌ Node communication domain must be direct connection (gray cloud), otherwise nodes will never come online

### 🔗 IP Connection Restriction

To prevent man-in-the-middle attacks, if your generated Agent command ends with `-tls` parameter, you must use domain connection and cannot change it to IP connection.

For pure IP internal network connection, manually remove `-tls` from the command end.

### 💾 Security Note

Please keep the `data.db` database file and node credentials generated in the backend secure. They are critical to your entire forwarding network security.

---

## 🖥️ Interface Preview

<img width="800" height="592" alt="mmexport1778420608453" src="https://github.com/user-attachments/assets/e14f1e06-2c6d-4f37-9195-7bb77ceec5c4" />


---

## 📄 License

This project is open source under the [MIT](LICENSE) license.

---

<div align="center">
  <h3>💖 Thank you to our sponsors / ForZTN </h3>
  <a href="https://sponsorship.forztn.com/github/jinhuaitao/relay" target="_blank">
    <img src="https://img.shields.io/badge/Sponsor-forztn-blue?style=for-the-badge&logo=github" alt="Sponsor" />
  </a>
</div>


---

## License

This project is open-sourced under the [MIT](LICENSE) license.

---
<p align="center">
<sub>Built with ❤️ by <a href="https://github.com/jinhuaitao">jinhuaitao</a></sub>
</p>
