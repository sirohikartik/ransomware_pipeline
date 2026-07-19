#!/usr/bin/env python3
"""
parse_logs.py — Extract 31 temporal features from monitor.sh output.

Reads:
  - strace.log (or ltrace.log)
  - entropy_timeline.csv
  - proc_timeline.csv
  - meta.json

Outputs a single CSV with 100ms-windowed features.
"""
import argparse
import csv
import json
import math
import os
import re
import sys
from collections import defaultdict

WINDOW_SIZE = 0.1  # 100ms

TARGET_EXTENSIONS = {
    '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.zip', '.rar',
    '.kitty', '.locked', '.conti', '.wasted', '.encrypted', '.spooky'
}

# Regex handles BOTH formats:
#   "TIMESTAMP SYSCALL(...)"              (native)
#   "PID TIMESTAMP SYSCALL(...)"          (strace -f)
LINE_PAT = re.compile(r'^\s*(?:(\d+)\s+)?((?:\d+:){0,2}\d+\.\d+)\s+([a-zA-Z_]\w*)\(')
RET_PAT  = re.compile(r'\)\s*=\s*(-?\d+)')
PATH_PAT = re.compile(r'"([^"]*)"')
IP_PAT   = re.compile(r'inet_addr\("([^"]+)"\)')
PORT_PAT = re.compile(r'sin_port=htons\((\d+)\)')
MMAP_SIZE_PAT = re.compile(r'mmap\([^,]+,\s*(\d+),')


def parse_strace(log_path):
    """Parse strace.log into per-100ms-window feature dicts."""
    windows = defaultdict(lambda: {
        'bytes_read': 0, 'bytes_written': 0, 'file_deletions': 0,
        'file_renames': 0, 'target_extensions': 0, 'lseek_calls': 0,
        'urandom_bytes': 0, 'mmap_bytes': 0, 'mprotect_calls': 0,
        'futex_waits': 0, 'net_packets': 0, 'net_bytes': 0,
        'unique_ips': set(), 'dns_queries': 0, 'conn_failures': 0,
        'child_processes': 0, 'execve_calls': 0, 'syscall_types': [],
        'dir_ops': 0, 'drop_rate': 0, 'library_calls': 0,
    })

    first_ts = None
    total_bytes_written = []  # (timestamp, bytes) for slope calc
    first_encryption_ts = None
    parsed = 0

    print(f"[*] Parsing {log_path}...")
    with open(log_path, 'r', errors='ignore') as f:
        for line in f:
            m = LINE_PAT.match(line)
            if not m:
                continue

            parsed += 1
            ts_str = m.group(2)
            if ':' in ts_str:
                parts = ts_str.split(':')
                ts = float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2])
            else:
                ts = float(ts_str)
            sc = m.group(3)

            ret_m = RET_PAT.search(line)
            ret = int(ret_m.group(1)) if ret_m else 0

            if first_ts is None:
                first_ts = ts

            wid = int((ts - first_ts) / WINDOW_SIZE)
            w = windows[wid]
            w['syscall_types'].append(sc)

            # Bytes read/written
            if sc in ('read', 'pread', 'readv') and ret > 0:
                w['bytes_read'] += ret
                if 'urandom' in line or 'random' in line:
                    w['urandom_bytes'] += ret
            if sc in ('write', 'pwrite', 'writev') and ret > 0:
                w['bytes_written'] += ret
                total_bytes_written.append((ts, ret))

                # Detect first encryption (write to target extension)
                if first_encryption_ts is None:
                    pm = PATH_PAT.search(line)
                    if pm and any(pm.group(1).endswith(ext) for ext in TARGET_EXTENSIONS):
                        first_encryption_ts = ts

            # Network
            if sc in ('sendto', 'sendmsg', 'send', 'recvfrom', 'recvmsg', 'recv') and ret > 0:
                w['net_bytes'] += ret
                w['net_packets'] += 1

            # File ops
            if sc in ('unlink', 'unlinkat'):
                w['file_deletions'] += 1
            if sc in ('rename', 'renameat'):
                w['file_renames'] += 1

            # Target extensions
            if sc in ('open', 'openat'):
                pm = PATH_PAT.search(line)
                if pm:
                    path = pm.group(1)
                    if any(path.endswith(ext) for ext in TARGET_EXTENSIONS):
                        w['target_extensions'] += 1
                        if first_encryption_ts is None:
                            first_encryption_ts = ts

            # Directory ops
            if sc in ('getdents', 'getdents64', 'opendir'):
                w['dir_ops'] += 1

            # Sequential vs random (lseek proxy)
            if sc == 'lseek':
                w['lseek_calls'] += 1

            # Memory
            if sc == 'mmap':
                sm = MMAP_SIZE_PAT.search(line)
                if sm:
                    try:
                        w['mmap_bytes'] += int(sm.group(1))
                    except ValueError:
                        pass
            if sc in ('brk', 'mremap'):
                w['mmap_bytes'] += 0  # counted separately if needed
            if sc == 'mprotect':
                w['mprotect_calls'] += 1

            # Futex
            if sc == 'futex' and 'FUTEX_WAIT' in line:
                w['futex_waits'] += 1

            # Network details
            if sc == 'connect':
                im = IP_PAT.search(line)
                if im:
                    w['unique_ips'].add(im.group(1))
                pm = PORT_PAT.search(line)
                if pm and pm.group(1) == '53':
                    w['dns_queries'] += 1
                if ret == -1:
                    w['conn_failures'] += 1

            # Process
            if sc in ('fork', 'vfork', 'clone', 'clone3'):
                w['child_processes'] += 1
            if sc == 'execve':
                w['execve_calls'] += 1

    print(f"    Parsed {parsed} syscall lines across {len(windows)} windows")
    return windows, first_ts, first_encryption_ts, total_bytes_written


def load_entropy_timeline(path):
    """Load entropy_timeline.csv into a dict keyed by epoch."""
    data = {}
    if not os.path.exists(path):
        return data
    with open(path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                data[float(row['epoch'])] = {
                    'mean_entropy': float(row['mean_entropy']),
                    'file_count': int(row['file_count']),
                    'total_bytes': int(row['total_bytes']),
                }
            except (ValueError, KeyError):
                continue
    return data


def load_proc_timeline(path):
    """Load proc_timeline.csv into a dict keyed by epoch."""
    data = {}
    if not os.path.exists(path):
        return data
    with open(path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                data[float(row['epoch'])] = {
                    'vmrss_kb': int(row['vmrss_kb']),
                    'read_bytes': int(row['read_bytes']),
                    'write_bytes': int(row['write_bytes']),
                }
            except (ValueError, KeyError):
                continue
    return data


def load_meta(path):
    """Load meta.json safely."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[!] Warning: meta.json is malformed ({e}). Continuing without it.")
        return {}


def compute_encryption_slope(total_bytes_written):
    """Linear regression of bytes_written over time."""
    if len(total_bytes_written) < 2:
        return 0.0
    n = len(total_bytes_written)
    t0 = total_bytes_written[0][0]
    sum_x = sum(t - t0 for t, _ in total_bytes_written)
    sum_y = sum(b for _, b in total_bytes_written)
    sum_xy = sum((t - t0) * b for t, b in total_bytes_written)
    sum_xx = sum((t - t0) ** 2 for t, _ in total_bytes_written)
    denom = n * sum_xx - sum_x ** 2
    if denom == 0:
        return 0.0
    return (n * sum_xy - sum_x * sum_y) / denom


def main():
    parser = argparse.ArgumentParser(description="Parse monitor.sh logs into ML features")
    parser.add_argument("--logdir", required=True, help="Directory containing monitor.sh output")
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()

    logdir = args.logdir
    out_path = args.out

    # Locate strace or ltrace log
    strace_path = os.path.join(logdir, "strace.log")
    ltrace_path = os.path.join(logdir, "ltrace.log")
    if os.path.exists(strace_path):
        log_file = strace_path
    elif os.path.exists(ltrace_path):
        log_file = ltrace_path
    else:
        print(f"[!] No strace.log or ltrace.log found in {logdir}")
        sys.exit(1)

    # Load auxiliary data
    meta = load_meta(os.path.join(logdir, "meta.json"))
    entropy_data = load_entropy_timeline(os.path.join(logdir, "entropy_timeline.csv"))
    proc_data = load_proc_timeline(os.path.join(logdir, "proc_timeline.csv"))

    # Parse main trace
    windows, first_ts, first_enc_ts, total_bytes_written = parse_strace(log_file)

    if not windows:
        print(f"[!] No syscalls parsed from {log_file}. Output will be empty.")
        with open(out_path, 'w') as f:
            f.write("window_idx,window_start_s,bytes_read_per_sec,bytes_written_per_sec,"
                    "rw_volume_ratio,file_deletion_rate,file_rename_rate,"
                    "target_extension_velocity,seq_vs_random_disk_ratio,"
                    "urandom_bytes_per_sec,mmap_brk_rate,mprotect_rate,futex_rate,"
                    "net_packet_rate,net_byte_volume,unique_dest_ip_rate,dns_query_rate,"
                    "connection_failure_rate,child_spawn_rate,execve_rate,"
                    "syscall_sequence_entropy,io_burstiness_std,dir_ops,drop_rate,"
                    "ransom_note_hits,library_call_rate_openssl,vmrss_kb,mean_file_entropy,"
                    "time_to_first_encryption_s,encryption_slope,file_entropy_delta\n")
        return

    # Global features
    time_to_first_enc = (first_enc_ts - first_ts) if first_enc_ts else 0.0
    enc_slope = compute_encryption_slope(total_bytes_written)

    # Compute file entropy delta from entropy_timeline
    entropy_epochs = sorted(entropy_data.keys())
    file_entropy_delta = 0.0
    if len(entropy_epochs) >= 2:
        file_entropy_delta = (entropy_data[entropy_epochs[-1]]['mean_entropy'] -
                              entropy_data[entropy_epochs[0]]['mean_entropy'])

    # Build output rows
    print(f"[*] Writing features to {out_path}...")
    max_window = max(windows.keys())
    bytes_written_history = []  # for IO burstiness

    header = [
        'window_idx', 'window_start_s',
        'bytes_read_per_sec', 'bytes_written_per_sec', 'rw_volume_ratio',
        'file_deletion_rate', 'file_rename_rate', 'target_extension_velocity',
        'seq_vs_random_disk_ratio', 'urandom_bytes_per_sec',
        'mmap_brk_rate', 'mprotect_rate', 'futex_rate',
        'net_packet_rate', 'net_byte_volume', 'unique_dest_ip_rate',
        'dns_query_rate', 'connection_failure_rate',
        'child_spawn_rate', 'execve_rate',
        'syscall_sequence_entropy', 'io_burstiness_std',
        'dir_ops', 'drop_rate', 'ransom_note_hits', 'library_call_rate_openssl',
        'vmrss_kb', 'mean_file_entropy',
        'time_to_first_encryption_s', 'encryption_slope', 'file_entropy_delta',
    ]

    with open(out_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(header)

        for wid in range(max_window + 1):
            d = windows[wid]
            # Ensure set exists for unique_ips
            if 'unique_ips' not in d:
                d['unique_ips'] = set()

            # Scale to per-second (window is 0.1s)
            br = d['bytes_read'] * 10
            bw = d['bytes_written'] * 10
            rw_ratio = br / bw if bw > 0 else 0.0

            # Syscall entropy
            sc_counts = {}
            for sc in d['syscall_types']:
                sc_counts[sc] = sc_counts.get(sc, 0) + 1
            total_sc = len(d['syscall_types'])
            entropy = 0.0
            if total_sc > 0:
                entropy = -sum((c / total_sc) * math.log2(c / total_sc)
                               for c in sc_counts.values() if c > 0)

            # IO burstiness (rolling std dev over last 5 windows)
            bytes_written_history.append(d['bytes_written'])
            if len(bytes_written_history) > 5:
                bytes_written_history.pop(0)
            if len(bytes_written_history) > 1:
                mean_bw = sum(bytes_written_history) / len(bytes_written_history)
                burstiness = math.sqrt(
                    sum((x - mean_bw) ** 2 for x in bytes_written_history) / len(bytes_written_history)
                )
            else:
                burstiness = 0.0

            # Sample entropy and VmRSS at this window's timestamp
            window_epoch = (first_ts or 0) + wid * WINDOW_SIZE
            mean_ent = 0.0
            vmrss = 0
            # Find closest entropy sample within ±0.5s
            for ep in entropy_epochs:
                if abs(ep - window_epoch) < 0.5:
                    mean_ent = entropy_data[ep]['mean_entropy']
                    break
            # Find closest proc sample
            for ep, pd in proc_data.items():
                if abs(ep - window_epoch) < 0.5:
                    vmrss = pd['vmrss_kb']
                    break

            # Ransom note hits (heuristic: writes to files named README/HELP/DECRYPT)
            ransom_note_hits = 0  # would need per-window file path tracking; placeholder

            w.writerow([
                wid,
                round(wid * WINDOW_SIZE, 4),
                br, bw, round(rw_ratio, 4),
                d['file_deletions'] * 10,
                d['file_renames'] * 10,
                d['target_extensions'] * 10,
                d['lseek_calls'] * 10,
                d['urandom_bytes'] * 10,
                d['mmap_bytes'],
                d['mprotect_calls'] * 10,
                d['futex_waits'] * 10,
                d['net_packets'] * 10,
                d['net_bytes'],
                len(d['unique_ips']),
                d['dns_queries'] * 10,
                d['conn_failures'] * 10,
                d['child_processes'] * 10,
                d['execve_calls'] * 10,
                round(entropy, 4),
                round(burstiness, 4),
                d['dir_ops'] * 10,
                d['drop_rate'] * 10,
                ransom_note_hits,
                d['library_calls'] * 10,
                vmrss,
                round(mean_ent, 4),
                round(time_to_first_enc, 4),
                round(enc_slope, 4),
                round(file_entropy_delta, 4),
            ])

    print(f"[*] Wrote {max_window + 1} rows x {len(header)} columns -> {out_path}")


if __name__ == "__main__":
    main()
