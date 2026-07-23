#!/usr/bin/env python3
import os
import subprocess
import sys

# Configuration
PIPELINE_DIR = "/home/ubuntu/ransomware_pipeline"
MONITOR_SCRIPT = os.path.join(PIPELINE_DIR, "monitor.sh")
CORPUS_BASE = "/home/ubuntu/goodware_corpus"

def run_command(cmd):
    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def seed_corpus(folder_name, num_files=10000):
    """Creates a folder with dummy files."""
    path = os.path.join(CORPUS_BASE, folder_name)
    os.makedirs(path, exist_ok=True)
    print(f"[*] Seeding {num_files} files into {path}...")
    for i in range(num_files):
        with open(os.path.join(path, f"data_{i}.txt"), "w") as f:
            f.write(f"Sensitive data block {i}\n" * 10)

def run_goodware(name, binary, args, outdir_suffix, timeout=300):
    """Runs a goodware binary through the monitor."""
    corpus_path = os.path.join(CORPUS_BASE, name)
    outdir = os.path.join(PIPELINE_DIR, f"logs_goodware_{outdir_suffix}")
    
    print(f"\n[🚀] Starting Goodware Capture: {name}")
    
    cmd = [
        "sudo", "bash", MONITOR_SCRIPT, "run",
        binary,
        outdir,
        corpus_path,
        "--num-files", "0", 
        "--timeout", str(timeout),
        "--no-gui",
        "--"
    ] + args
    
    try:
        run_command(cmd)
        print(f"[✅] {name} completed. Logs in {outdir}")
    except subprocess.CalledProcessError as e:
        print(f"[!] {name} failed: {e}")

if __name__ == "__main__":
    os.makedirs(CORPUS_BASE, exist_ok=True)

    # 1. OPENSSL SPEED (Sustained Crypto Activity - ~5-10 mins)
    # This will generate hundreds of rows of pure computational syscalls
    seed_corpus("openssl_test", num_files=100)
    run_goodware(
        name="openssl", 
        binary="/usr/bin/openssl", 
        args=["speed", "-multi", "4", "aes-256-cbc"],
        outdir_suffix="openssl",
        timeout=600
    )

    # 2. FFMPEG TRANSCODING (Heavy I/O + CPU - ~5-10 mins)
    # We create a dummy raw video file first
    seed_corpus("ffmpeg_test", num_files=1)
    raw_video = os.path.join(CORPUS_BASE, "ffmpeg_test", "input.raw")
    if not os.path.exists(raw_video):
        print("[*] Generating dummy raw video for ffmpeg...")
        run_command(["dd", "if=/dev/urandom", f"of={raw_video}", "bs=1M", "count=50"])
    
    run_goodware(
        name="ffmpeg",
        binary="/usr/bin/ffmpeg",
        args=["-y", "-f", "rawvideo", "-pixel_format", "rgb24", "-video_size", "320x240", 
              "-i", raw_video, "-c:v", "libx264", "/tmp/output.mp4"],
        outdir_suffix="ffmpeg",
        timeout=600
    )

    # 3. PYTHON HTTP SERVER + WGET (Network + File Serving - ~2 mins)
    # We start the server in the background, then wget files from it
    seed_corpus("http_test", num_files=1000)
    
    # Note: This is a two-step process. We'll use a wrapper script for this.
    wrapper_script = "/home/ubuntu/http_wrapper.sh"
    with open(wrapper_script, "w") as f:
        f.write(f"""#!/bin/bash
cd {CORPUS_BASE}/http_test
python3 -m http.server 8080 &
SERVER_PID=$!
sleep 2
wget -r -l 1 -np -nH --cut-dirs=1 http://localhost:8080/ -P /tmp/wget_download/
kill $SERVER_PID
""")
    os.chmod(wrapper_script, 0o755)

    run_goodware(
        name="http_server",
        binary="/bin/bash",
        args=[wrapper_script],
        outdir_suffix="http",
        timeout=300
    )

    # 4. GREP RECURSIVE (High Read Activity - ~1-2 mins)
    seed_corpus("grep_test", num_files=10000)
    run_goodware(
        name="grep",
        binary="/usr/bin/grep",
        args=["-r", "Sensitive", "/home/ubuntu/goodware_corpus/grep_test"],
        outdir_suffix="grep",
        timeout=300
    )

    # 5. TAR ARCHIVING (High I/O - ~1-2 mins)
    seed_corpus("tar_test", num_files=10000)
    run_goodware(
        name="tar", 
        binary="/usr/bin/tar", 
        args=["-czf", "/tmp/backup.tar.gz", "-C", "/home/ubuntu/goodware_corpus/tar_test", "."],
        outdir_suffix="tar",
        timeout=300
    )

    print("\n[🏁] Heavy Goodware Suite Complete!")
