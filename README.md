# Ransomware Dataset Curation Pipeline for arm64 linux VMs

# Setup

### 1. One-time setup (installs everything including QEMU, Xvfb, etc.)
sudo ./monitor.sh setup

### 2. Run a native ARM64 binary
sudo ./monitor.sh run ./my_arm_ransomware ./logs_arm ./test_corpus

### 3. Run an x86_64 binary (auto-detected, uses QEMU)
sudo ./monitor.sh run ./conti_ransomware.elf ./logs_conti ./test_corpus

### 4. Run with custom arguments and a 60s timeout
sudo ./monitor.sh run ./ransom ./logs_custom ./corpus --timeout 60 -- -p /tmp/targets -e

### 5. Parse the logs into the ML CSV
python3 parse_logs.py --logdir ./logs_conti --out ./logs_conti/features.csv

### 6. Verify
head -5 ./logs_conti/features.csv
wc -l ./logs_conti/features.csv

---
##### *Note: For some binaries they may require different .so files for execution so if any error occurs please carefully download the required .so files and other dependencies as the monitor.sh file only downloads the bare minimum dependencies and measurement tools.*
---

This pipeline was created using coding assistance of Qwen 3.7 Plus
