# 🐻‍❄️ Honeypot Detector

**A beautiful CLI tool for scanning smart contracts for common honeypot (buy-only scam) patterns. Protect yourself and your friends from scam tokens!**

---

## ✨ Features

- Colorful, easy-to-read CLI output (with [rich](https://github.com/Textualize/rich))
- Detects sell-blocking, blacklists, excessive taxes, anti-bot logic, and more
- Prints clear explanations for every flagged pattern
- Exports results as clean JSON
- Works on ParrotOS, Linux, Mac, Windows

---
![honeypot-detector-cli-demo](demo_screenshot.png)

## 🚀 Quick Start

```bash
git clone https://github.com/Jxnesyy/honeypot-detector.git
cd honeypot-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python honeypot_detector.py <contract_address> <bsc|eth>
