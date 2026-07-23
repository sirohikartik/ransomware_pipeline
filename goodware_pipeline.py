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
    """Creates a folder with dummy files for the goodware to process."""
    path = os.path.join(CORPUS_BASE, folder_name)
    os.makedirs(path, exist_ok=True)
    print(f"[*] Seeding {num_files} files into {path}...")
    
    # Create some text files
    for i in range(num_files):
        with open(os.path.join(path, f"data_{i}.txt"), "w") as f:
            f.write(f"Sensitive data block {i}\n" * 10)
            
    # Create a few dummy images for ffmpeg/tar variety
    for i in range(100):
        with open(os.path.join(path, f"img_{i}.raw"), "wb") as f:
            f.write(b'\x00' * 1024) # 1KB dummy raw data

def run_goodware(name, binary, args, outdir_suffix):
    """Runs a goodware binary through the monitor."""
    corpus_path = os.path.join(CORPUS_BASE, name)
    outdir = os.path.join(PIPELINE_DIR, f"logs_goodware_{outdir_suffix}")
    
    print(f"\n[🚀] Starting Goodware Capture: {name}")
    
    # Command structure: sudo bash monitor.sh run <binary> <outdir> <watchdir> -- <args>
    cmd = [
        "sudo", "bash", MONITOR_SCRIPT, "run",
        binary,
        outdir,
        corpus_path,
        "--num-files", "0", # We already seeded manually
        "--timeout", "300",
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

    # 1. TAR (Archiving - High I/O, Low Entropy Change)
    seed_corpus("tar_test")
    run_goodware(
        name="tar", 
        binary="/usr/bin/tar", 
        args=["-czf", "/tmp/backup.tar.gz", "-C", "/home/ubuntu/goodware_corpus/tar_test", "."],
        outdir_suffix="tar"
    )

    # 2. DD (Raw Disk/File Copy - Pure Write Bursts)
    seed_corpus("dd_test", num_files=1) # DD usually works on single large files or streams
    # Let's create one large file for dd
    large_file = os.path.join(CORPUS_BASE, "dd_test", "large_input.bin")
    run_command(["dd", "if=/dev/urandom", f"of={large_file}", "bs=1M", "count=100"])
    run_goodware(
        name="dd",
        binary="/usr/bin/dd",
        args=[f"if={large_file}", "of=/tmp/dd_output.bin", "bs=1M"],
        outdir_suffix="dd"
    )

    # 3. FIND (Directory Traversal - High Execve/Stat activity)
    seed_corpus("find_test")
    run_goodware(
        name="find",
        binary="/usr/bin/find",
        args=["/home/ubuntu/goodware_corpus/find_test", "-type", "f", "-name", "*.txt"],
        outdir_suffix="find"
    )

    # 4. GREP (Content Scanning - High Read Activity)
    seed_corpus("grep_test")
    run_goodware(
        name="grep",
        binary="/usr/bin/grep",
        args=["-r", "Sensitive", "/home/ubuntu/goodware_corpus/grep_test"],
        outdir_suffix="grep"
    )

    # 5. CP (Bulk File Copying - High Read/Write + Rename)
    seed_corpus("cp_test")
    dest_dir = "/tmp/cp_destination"
    os.makedirs(dest_dir, exist_ok=True)
    run_goodware(
        name="cp",
        binary="/usr/bin/cp",
        args=["-r", "/home/ubuntu/goodware_corpus/cp_test/.", dest_dir],
        outdir_suffix="cp"
    )

    print("\n[🏁] Goodware Suite Complete! You can now parse these logs.")
