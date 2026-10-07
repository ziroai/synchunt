<div align="center">

# ⚔️ SyncHunt — Automated Bug Hunting Recon Framework

<img src="https://img.shields.io/badge/Python-3.8%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
<img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Status">
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-black?style=for-the-badge&logo=linux" alt="Platform">

> 🎯 **Modular, automated reconnaissance framework for professional bug bounty hunters and security researchers**

[Features](#-features) • [Setup](#-quick-setup) • [Usage](#-usage) • [Requirements](#-requirements) • [Contributing](#-contributing)

</div>

---

## 🎯 Features

### 🔍 Subdomain Enumeration
Multiple intelligence sources for maximum coverage
- Subfinder • Amass • Assetfinder • Findomain • crt.sh • Sublist3r

### ✅ Subdomain Validation
Verify live and responsive assets efficiently
- httpx • dnsx • massdns

### 🔓 Port Scanning
Enumerate open ports and services
- Naabu • Nmap • Masscan

### 🧩 Web Fingerprinting
Identify technologies and exposed stacks
- WhatWeb • wafw00f • webanalyze

### 🌐 Content Discovery
Find hidden files, paths, and endpoints
- Katana • GoSpider • Hakrawler • waybackurls • gau • ParamSpider • dirsearch • feroxbuster

### 🔬 JavaScript Analysis
Uncover exposed secrets and patterns in front-end code
- LinkFinder • SecretFinder • Custom regex detection

### 🚨 Vulnerability Scanning
Automated testing against common vulnerabilities
- Nuclei • Nikto • Dalfox • SQLMap • CRLFuzz • Corsy

### 🔑 Sensitive Information Discovery
Search for exposed credentials, tokens, and misconfigurations
- S3Scanner • GitHub Dorking • Shodan • Google Dorks

### 📸 Visual Verification
Capture screenshots for quick manual review
- Gowitness • Aquatone

### 📊 Professional Reporting
Generate structured results with actionable intelligence
- HTML reports • Markdown summaries • Findings tracking

---

## 🚀 Quick Setup

```bash
# 📥 Clone the repository
git clone https://github.com/ziroai/synchunt.git
cd synchunt

# 📦 Install Python dependencies
pip3 install -r requirements.txt

# ✔️ Verify tool dependencies
python3 main.py --check-deps
```

---

## 💻 Usage

### Full Reconnaissance Scan
```bash
python3 main.py -d target.com --full
```

### Specific Scanning Phases
```bash
python3 main.py -d target.com --phase subdomain,validation,vulnscan
```

### Multiple Targets
```bash
python3 main.py -l targets.txt --full
```

### Verbose Output
```bash
python3 main.py -d target.com --full -v
```

### Custom Config
```bash
python3 main.py -d target.com --full --config custom_config.yaml
```

---

## ⚙️ Requirements

| Requirement | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.8+ | Core framework |
| **Go** | 1.19+ | Go-based reconnaissance tools |
| **OS** | Kali Linux / Ubuntu | Recommended environment |
| **Memory** | 4GB+ | Better scan performance |
| **Disk Space** | 10GB+ | Tool installation + reports |

### Recommended Environment
- 🐧 Kali Linux 2024+
- 🐧 Ubuntu 22.04 LTS
- 🍎 macOS 12+ (limited support)

---

## 📋 Phases Overview

| Phase | Description | Tools |
|-------|-------------|-------|
| 🔍 Reconnaissance | Gather initial intelligence | Subfinder, Amass, crt.sh |
| ✅ Validation | Confirm live assets | httpx, dnsx, massdns |
| 🔓 Scanning | Port and service discovery | Naabu, Nmap, Masscan |
| 🧩 Fingerprinting | Identify tech stack | WhatWeb, wafw00f, webanalyze |
| 🌐 Crawling | Enumerate endpoints and paths | Katana, GoSpider, Hakrawler |
| 🔬 Analysis | Deep code inspection | LinkFinder, SecretFinder |
| 🚨 Vulnerability | Security assessment | Nuclei, Dalfox, SQLMap |
| 📸 Verification | Visual confirmation | Gowitness, Aquatone |

---

## 🔒 Legal & Ethical Disclaimer

⚠️ **IMPORTANT**: This tool is intended for **authorized security testing only**.

- ✅ Test systems you own or have explicit written permission to assess
- ❌ Do not use unauthorized access or intrusive testing
- 📜 Comply with local laws, regulations, and program scope rules
- 🤝 Respect bug bounty policies and responsible disclosure practices

**By using this project, you agree to use it legally and responsibly.**

---

## 🤝 Contributing

We welcome contributions from the security community.

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/amazing-feature`)
3. 💾 Commit your changes (`git commit -m 'Add amazing feature'`)
4. 📤 Push the branch (`git push origin feature/amazing-feature`)
5. 🔄 Open a Pull Request

### Guidelines
- Follow Python style best practices
- Add tests for new features
- Update documentation when needed
- Keep changes focused and readable

---

## 📚 Resources

- 📖 Full docs
- 🔧 Configuration guide
- 🎓 Tutorials and examples
- 🐛 Troubleshooting

---

## 📞 Support & Issues

- 🐛 [Report a bug](https://github.com/ziroai/synchunt/issues/new)
- 💡 [Request a feature](https://github.com/ziroai/synchunt/issues/new)
- 💬 [Discussions](https://github.com/ziroai/synchunt/discussions)

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- 🔧 Built with community-driven security tools
- 👥 Inspired by the bug bounty and red team ecosystem
- ⭐ Thanks to contributors and ethical researchers everywhere

---

<div align="center">

### 🌟 If you find SyncHunt useful, please consider starring the project.

[![GitHub stars](https://img.shields.io/github/stars/ziroai/synchunt?style=social)](https://github.com/ziroai/synchunt)
[![GitHub watchers](https://img.shields.io/github/watchers/ziroai/synchunt?style=social)](https://github.com/ziroai/synchunt)

**Happy hunting! 🎯**

</div>
