# P1-NPM-JS-LEAKS

# Apex Prowler 🦅

**Apex Prowler** is a professional-grade, concurrent security reconnaissance tool for red teamers, bug bounty hunters, and security engineers. It orchestrates a suite of best-in-class open-source tools to perform a multi-layered hunt for two of the most critical external security risks: **Hardcoded Secrets** and **Dependency Confusion** vulnerabilities.

Built for speed and accuracy, Apex Prowler delivers verified, high-impact findings directly to your Slack workspace, transforming noisy scanner output into actionable intelligence.

---

## 🔑 Key Features

- ✅ **Concurrent Scanning**: Multi-threaded modules dramatically reduce scan time.  
- 🌐 **Comprehensive JS Discovery**: Combines `katana`, `subjs`, and optionally `gau` for deep asset coverage.  
- 🔐 **Layered Secret Detection**: Uses `nuclei`, `secretfinder`, and `gitleaks` after JS beautification.  
- 🤖 **Automated Secret Verification**: `keyscope` validates secrets, cutting false positives.  
- ⛓️ **Dependency Confusion Detection**: Identifies unregistered, private-looking packages in `package.json`.  
- 📢 **Real-time Slack Alerts**: Clean, actionable notifications as soon as findings are made.  
- 🧠 **Flexible Input Handling**: Accepts domains, URLs, or IPs without issue.  

---

## ⚙️ Installation

### 1. Prerequisites

- Python 3.8+  
- Go (1.18+)

### 2. Clone the Repository

```bash
git clone https://github.com/7ealvivek/apex-prowler.git
cd apex-prowler
```

### 3. Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### 4. Install Required Go Tools

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/lc/subjs@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### 5. Install Other Tools

#### Gitleaks

**macOS:**

```bash
brew install gitleaks
```

**Linux:**

```bash
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz
tar -xzf gitleaks_8.18.2_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

#### Python CLI Tools

```bash
pip3 install jsbeautifier keyscope
```

#### SecretFinder

```bash
git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
sudo ln -s ~/tools/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder
```

---

## 🔧 Final Configuration

Open `apex_prowler.py` in a text editor and set your Slack Webhook URL:

```python
SLACK_WEBHOOK_URL = "YOUR_SLACK_WEBHOOK_URL_HERE"
```

---

## 🚀 Usage

Create a file named `targets.txt` with one target per line:

```text
example.com
https://api.example.com/v1/
dev.example.com
192.168.1.1
```

### Basic Scan (Secrets only)

```bash
python3 apex_prowler.py -t targets.txt
```

### Secrets + Dependency Confusion

```bash
python3 apex_prowler.py -t targets.txt -p
```

### Deep JS Discovery (GAU)

```bash
python3 apex_prowler.py -t targets.txt -g
```

### Paranoid Mode (Everything)

```bash
python3 apex_prowler.py -t targets.txt -g -p
```

---

## 🧩 Command-line Arguments

| Flag               | Argument | Description                                               |
|--------------------|----------|-----------------------------------------------------------|
| `-t`, `--targets`  | `FILE`   | **Required.** Path to a file containing target assets     |
| `-p`, `--dep-confusion` |      | Optional. Enables Dependency Confusion scanning           |
| `-g`, `--use-gau`  |          | Optional. Enables GAU for deeper JS discovery             |
| `--no-secrets`     |          | Optional. Disables the hardcoded secrets module           |

---

## 📬 Result Formats

All findings are sent as **Slack alerts** and stored in a `results/` directory with timestamps.

### Slack Alert: Verified Secret

```
🔥 VERIFIED CRITICAL Finding  
Scanner: Gitleaks  
Source: https://cdn.example.com/assets/app-v3.min.js  
Vulnerability/Package: Github Personal Access Token  
Details: ghp_123abcDEF456ghiJKL789...
```

### Slack Alert: Dependency Confusion

```
⛓️ CRITICAL Finding  
Scanner: Package Prowler  
Source: https://dev.example.com/package.json  
Vulnerability/Package: example-internal-api-client  
Details: High-confidence private package 'example-internal-api-client' is NOT registered on public NPM. It was found in an exposed package.json and matches private naming heuristics.
```

---

## 👨‍💻 Author

**Vivek Kashyap (P1)**  
🔗 Bugcrowd: [bugcrowd.com/realvivek](https://bugcrowd.com/realvivek)  
🐦 X/Twitter: [x.com/starkcharry](https://x.com/starkcharry)  
💻 GitHub: [github.com/7ealvivek](https://github.com/7ealvivek)

---

## 🙏 Tool Acknowledgements

A huge thank you to the developers and communities behind:

- **ProjectDiscovery** (Katana, httpx, Nuclei, SubJS)  
- **Tom Hudson** and other pioneers in bug bounty tooling  
- **lc** (gau)  
- **zricethezav** (Gitleaks)  
- **shofill** (Keyscope)  
- And all other open-source contributors whose work makes tools like this possible
