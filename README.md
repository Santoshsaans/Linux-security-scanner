# 🔐 Linux Security Scanner

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2-orange.svg)](https://ubuntu.com/wsl)

> **An automated Linux security auditing tool with a web dashboard that performs 20+ security checks, assigns risk levels, and generates professional reports.**

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Security Checks](#-security-checks)
- [Risk Scoring](#-risk-scoring)
- [Project Structure](#-project-structure)
- [Sample Output](#-sample-output)
- [Technologies Used](#-technologies-used)
- [Common Fixes](#-common-fixes)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

---

## 📋 Overview

**Linux Security Scanner** is a comprehensive security auditing tool that automatically checks Linux systems for vulnerabilities and misconfigurations. It performs **20+ security checks**, assigns **risk levels** (PASS/LOW/MEDIUM/HIGH/CRITICAL), calculates a **security score (0-100)**, and provides **step-by-step fix recommendations**.

### Why Use This Tool?

| Benefit | Description |
|---------|-------------|
| ⏱️ **Saves Time** | Manual security checks take 1-2 hours, this does it in 30 seconds |
| 💰 **Saves Money** | Free alternative to expensive commercial tools ($2,500+/year) |
| 🔍 **Finds Vulnerabilities** | Detects issues before hackers exploit them |
| 📈 **Tracks Progress** | Shows security improvements over time |
| 📄 **Professional Reports** | TXT, CSV, and JSON formats |
| 🌐 **Web Dashboard** | Beautiful interface for real-time monitoring |

---

## ✨ Features

### Phase 1: Basic System Information (8 Checks)
| Check | Description |
|-------|-------------|
| Operating System | OS name and version |
| Hostname | System network name |
| Logged-in User | Current session user |
| Kernel Version | Linux kernel release |
| System Uptime | How long system has been running |
| Disk Usage | Root partition usage with status |
| Memory Usage | RAM usage with status |
| CPU Usage | CPU utilization with status |

### Phase 2: Security Checks (6 Checks)
| Check | Risk if Failed | Recommendation |
|-------|----------------|----------------|
| Firewall Status | 🔴 HIGH | `sudo ufw enable` |
| SSH Root Login | 🔴 HIGH | `PermitRootLogin no` |
| SSH Password Auth | 🟡 MEDIUM | Use SSH keys |
| Open Ports | 🟡 MEDIUM | Close unnecessary ports |
| Running Services | 🟡 MEDIUM | Remove risky services |
| System Updates | 🔴 HIGH | `sudo apt upgrade -y` |
| Password Policy | 🟡 MEDIUM | Set PASS_MIN_LEN 12 |

### Phase 3: Advanced Security Checks (6 Checks)
| Check | Risk if Failed | Recommendation |
|-------|----------------|----------------|
| World Writable Files | 🔴 HIGH | `chmod o-w /path/to/file` |
| SUID Files | 🟡 MEDIUM | Review SUID programs |
| Cron Jobs | 🟢 LOW | Monitor for suspicious tasks |
| Failed Logins | 🟢 LOW | Implement fail2ban |
| USB Devices | 🟢 LOW | Monitor for unauthorized |
| Mounted Drives | 🟢 LOW | Check network shares |

### Risk Scoring System
- 📊 **5 Risk Levels:** PASS 🟢 | LOW 🔵 | MEDIUM 🟡 | HIGH 🔴 | CRITICAL 🚨
- 📈 **Security Score:** 0-100 scale
- 📋 **Executive Summary:** Clear breakdown of findings

### Reporting & Dashboard
- 📄 **TXT Reports** - Human-readable format
- 📊 **CSV Reports** - Excel/Google Sheets compatible
- 💻 **JSON Reports** - Machine-readable format
- 🌐 **Web Dashboard** - Real-time scanning with visual cards
- 📥 **One-Click Download** - All reports downloadable
- 📅 **Report History** - Track improvements over time

---

## 🚀 Installation

### Prerequisites

| Requirement | Description |
|-------------|-------------|
| Operating System | Ubuntu/Debian Linux (or WSL2 on Windows) |
| Python | 3.12 or higher |
| Git | For cloning the repository |
| pip3 | Python package manager |

### Step-by-Step Installation

#### 1️⃣ Clone the Repository

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

python3 scanner.py

python3 app.py
# Then open http://localhost:5000 in your browser
