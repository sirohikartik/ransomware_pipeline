#!/usr/bin/env bash
#
# monitor.sh — Full behavioral instrumentation for Linux ransomware analysis
# Supports: native ARM64 binaries AND x86_64 binaries via QEMU user-mode
#
# Usage:
#   sudo ./monitor.sh setup                                       # install tools
#   sudo ./monitor.sh run <binary> [outdir] [watch_dir] [flags]   # run sample
#
# Flags:
#   --tracer strace|ltrace   (default: strace; ltrace auto-disabled under QEMU)
#   --no-gui                 skip Xvfb fake display
#   --no-dummy               skip dummy file seeding
#   --num-files N            number of dummy files to seed (default: 85)
#   --timeout N              kill after N seconds (default: 120)
#   -- args...               arguments passed to the target binary
#
set -uo pipefail

MODE="${1:-}"

# ============================================================================
# SETUP PHASE
# ============================================================================
if [[ "$MODE" == "setup" ]]; then
    echo "[*] Installing tracing toolchain..."
    apt-get update -y
    apt-get install -y \
        strace ltrace \
        auditd \
        tcpdump iproute2 \
        linux-tools-common linux-tools-generic linux-tools-"$(uname -r)" \
        blktrace fatrace \
        yara \
        binutils file \
        python3 python3-pip python3-venv \
        bpfcc-tools linux-headers-"$(uname -r)" \
        jq bc \
        xvfb xdotool x11-utils \
        qemu-user qemu-user-binfmt \
        libc6-amd64-cross libstdc++6-amd64-cross

    pip3 install --break-system-packages --quiet scapy 2>/dev/null || true

    sysctl -w kernel.perf_event_paranoid=-1 2>/dev/null || true
    echo "[*] Setup complete."
    exit 0
fi

# ============================================================================
# RUN PHASE
# ============================================================================
if [[ "$MODE" != "run" ]]; then
    echo "Usage:"
    echo "  sudo $0 setup"
    echo "  sudo $0 run <binary> [outdir] [watch_dir] [--timeout N] [--tracer strace|ltrace] [--no-gui] [--no-dummy] [--num-files N] -- [args...]"
    exit 1
fi

BINARY="${2:?Path to binary required}"
OUTDIR="${3:-logs_$(date +%Y%m%d_%H%M%S)}"
WATCHDIR="${4:-$(pwd)/test_corpus}"
shift $(( $# > 4 ? 4 : $# ))

# Parse optional flags
TRACER="strace"
NO_GUI=0
NO_DUMMY=0
NUM_FILES=85
TIMEOUT=120
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tracer)     TRACER="$2"; shift 2 ;;
        --no-gui)     NO_GUI=1; shift ;;
        --no-dummy)   NO_DUMMY=1; shift ;;
        --num-files)  NUM_FILES="$2"; shift 2 ;;
        --timeout)    TIMEOUT="$2"; shift 2 ;;
        --)           shift; break ;;
        *)            break ;;
    esac
done
BIN_ARGS=("$@")

# Validation
if [[ "$TRACER" != "strace" && "$TRACER" != "ltrace" ]]; then
    echo "[!] --tracer must be 'strace' or 'ltrace'"; exit 1
fi
if [[ ! -f "$BINARY" ]]; then
    echo "[!] $BINARY not found"; exit 1
fi
chmod +x "$BINARY" 2>/dev/null || true
if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root (strace -f / tcpdump need it)"; exit 1
fi

mkdir -p "$OUTDIR" "$WATCHDIR"
OUTDIR="$(realpath "$OUTDIR")"
WATCHDIR="$(realpath "$WATCHDIR")"

# ============================================================================
# ARCHITECTURE DETECTION
# ============================================================================
HOST_ARCH=$(uname -m)
BIN_INFO=$(file -b "$BINARY")
echo "[*] Host arch : $HOST_ARCH"
echo "[*] Binary    : $BINARY"
echo "[*] Binary info: $BIN_INFO"

USE_QEMU=0
QEMU_BIN=""
if echo "$BIN_INFO" | grep -q "x86-64"; then
    if [[ "$HOST_ARCH" != "x86_64" ]]; then
        USE_QEMU=1
        QEMU_BIN="qemu-x86_64"
        echo "[*] x86_64 binary on $HOST_ARCH → using QEMU user-mode emulation"
        if ! command -v qemu-x86_64 >/dev/null; then
            echo "[!] qemu-x86_64 not found. Run: sudo $0 setup"; exit 1
        fi
    fi
fi

if [[ $USE_QEMU -eq 1 && "$TRACER" == "ltrace" ]]; then
    echo "[!] ltrace incompatible with QEMU user-mode. Falling back to strace."
    TRACER="strace"
fi

echo "[*] Outdir    : $OUTDIR"
echo "[*] Watch     : $WATCHDIR"
echo "[*] Tracer    : $TRACER (QEMU=$USE_QEMU)"

# ============================================================================
# STATIC ANALYSIS (STR domain)
# ============================================================================
echo "[*] Static analysis..."
strings -a "$BINARY"   > "$OUTDIR/static_strings.txt" 2>&1
readelf -a "$BINARY"   > "$OUTDIR/static_readelf.txt" 2>&1
objdump -d "$BINARY"   > "$OUTDIR/static_objdump.txt" 2>&1
file -b "$BINARY"      > "$OUTDIR/file_info.txt" 2>&1

if [[ -d "./yara_rules" ]]; then
    yara -r ./yara_rules "$BINARY" > "$OUTDIR/yara_matches.txt" 2>&1 || true
fi

# ============================================================================
# DUMMY FILE SEEDING
# ============================================================================
if [[ $NO_DUMMY -eq 0 ]]; then
    echo "[*] Seeding $NUM_FILES dummy files into $WATCHDIR..."
    python3 - "$WATCHDIR" "$NUM_FILES" <<'PYEOF'
import os, sys, zipfile, io, random

watch = sys.argv[1]
num_files = int(sys.argv[2])

# Clean the directory first to ensure a fresh start
if os.path.exists(watch):
    for f in os.listdir(watch):
        fp = os.path.join(watch, f)
        if os.path.isfile(fp):
            os.remove(fp)

os.makedirs(watch, exist_ok=True)

# Calculate distribution based on total requested files
n_txt = max(1, int(num_files * 0.4))
n_pdf = max(1, int(num_files * 0.2))
n_pptx = max(1, int(num_files * 0.15))
n_docx = max(1, int(num_files * 0.15))
n_jpg = max(1, int(num_files * 0.05))
n_png = max(1, num_files - n_txt - n_pdf - n_pptx - n_docx - n_jpg)

# TXT files (low entropy)
for i in range(n_txt):
    with open(os.path.join(watch, f"document_{i:05d}.txt"), "w") as f:
        f.write(f"CONFIDENTIAL — Financial Report #{i}\n")
        f.write("Account: 1234-5678-9012-3456\nSSN: 123-45-6789\n")
        f.write("Balance: $50,000.00\n")
        f.write("This document contains sensitive information.\n" * 20)

# Minimal PDFs
for i in range(n_pdf):
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n0000000009 00000 n \n"
        b"0000000052 00000 n \n0000000101 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
    )
    pdf += b"% filler " * 500
    with open(os.path.join(watch, f"report_{i:05d}.pdf"), "wb") as f:
        f.write(pdf)

# Minimal PPTX (Office Open XML)
for i in range(n_pptx):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
            '</Types>')
        z.writestr("_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>'
            '</Relationships>')
        z.writestr("ppt/presentation.xml",
            f'<?xml version="1.0"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            f'<p:sldIdLst/><p:notesMasterIdLst/></p:presentation>')
    with open(os.path.join(watch, f"presentation_{i:05d}.pptx"), "wb") as f:
        f.write(buf.getvalue())

# Minimal DOCX
for i in range(n_docx):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>')
        z.writestr("_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>')
        z.writestr("word/document.xml",
            f'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f'<w:body><w:p><w:r><w:t>Confidential document content number {i}.</w:t></w:r></w:p>'
            f'<w:p><w:r><w:t>{"Lorem ipsum dolor sit amet. " * 50}</w:t></w:r></w:p>'
            f'</w:body></w:document>')
    with open(os.path.join(watch, f"spreadsheet_{i:05d}.docx"), "wb") as f:
        f.write(buf.getvalue())

# Minimal JPEG (fixed syntax)
for i in range(n_jpg):
    jpg = b''.join([
        b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00',
        b'\xff\xdb\x00C\x00', b'\x08' * 64,
        b'\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00',
        b'\xff\xc4\x00\x1f\x00', b'\x00' * 26,
        b'\xff\xda\x00\x08\x01\x01\x00\x00?\x00',
        b'\x55' * 2000, b'\xff\xd9',
    ])
    with open(os.path.join(watch, f"photo_{i:05d}.jpg"), "wb") as f:
        f.write(jpg)

# Minimal PNG (fixed syntax)
for i in range(n_png):
    png = b''.join([
        b'\x89PNG\r\n\x1a\n',
        b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde',
        b'\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N',
        b'\x00\x00\x00\x00IEND\xaeB`\x82',
    ])
    with open(os.path.join(watch, f"image_{i:05d}.png"), "wb") as f:
        f.write(png)

total = sum(1 for x in os.listdir(watch) if os.path.isfile(os.path.join(watch, x)))
print(f"  -> Seeded {total} dummy files")
PYEOF
fi

# ============================================================================
# GUI SIMULATION (Xvfb)
# ============================================================================
XVFB_PID=""
if [[ $NO_GUI -eq 0 ]]; then
    echo "[*] Starting Xvfb on :99..."
    pkill -f "Xvfb :99" 2>/dev/null || true
    sleep 0.3
    Xvfb :99 -screen 0 1024x768x24 >"$OUTDIR/xvfb.log" 2>&1 &
    XVFB_PID=$!
    export DISPLAY=:99
    sleep 1
    if ! kill -0 "$XVFB_PID" 2>/dev/null; then
        echo "[!] Xvfb failed to start. Continuing without GUI."
        XVFB_PID=""
        unset DISPLAY
    else
        echo "[*] Xvfb running (pid=$XVFB_PID)"
    fi
fi

# ============================================================================
# ENTROPY SAMPLER (CRYPTO/TEMPORAL)
# ============================================================================
cat > "$OUTDIR/_entropy_sampler.py" <<'PYEOF'
import sys, os, time, math, glob

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

watch_dir, out_csv, interval = sys.argv[1], sys.argv[2], float(sys.argv[3])
with open(out_csv, "w") as f:
    f.write("epoch,mean_entropy,file_count,total_bytes\n")
    while True:
        try:
            files = [x for x in glob.glob(os.path.join(watch_dir, "**", "*"), recursive=True)
                     if os.path.isfile(x)]
            ents, total_bytes = [], 0
            for fp in files:
                try:
                    with open(fp, "rb") as fh:
                        data = fh.read(65536)
                    ents.append(shannon_entropy(data))
                    total_bytes += os.path.getsize(fp)
                except OSError:
                    continue
            mean_e = sum(ents) / len(ents) if ents else 0.0
            f.write(f"{time.time():.3f},{mean_e:.4f},{len(files)},{total_bytes}\n")
            f.flush()
        except KeyboardInterrupt:
            break
        time.sleep(interval)
PYEOF

python3 "$OUTDIR/_entropy_sampler.py" "$WATCHDIR" "$OUTDIR/entropy_timeline.csv" 0.25 &
ENTROPY_PID=$!

# ============================================================================
# PACKET CAPTURE (NET)
# ============================================================================
tcpdump -i any -w "$OUTDIR/net.pcap" -U >"$OUTDIR/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 0.3

# ============================================================================
# LAUNCH TARGET
# ============================================================================
START_EPOCH=$(date +%s.%N)

if [[ $USE_QEMU -eq 1 ]]; then
    LAUNCH_CMD=(qemu-x86_64 -L /usr/x86_64-linux-gnu/ "$BINARY" "${BIN_ARGS[@]}")
else
    LAUNCH_CMD=("$BINARY" "${BIN_ARGS[@]}")
fi
echo "[*] Launching: ${LAUNCH_CMD[*]}"

if [[ "$TRACER" == "strace" ]]; then
    strace -f -tt -T -s 256 -o "$OUTDIR/strace.log" -- "${LAUNCH_CMD[@]}" &
else
    ltrace -f -tt -T -S -o "$OUTDIR/ltrace.log" -- "${LAUNCH_CMD[@]}" &
fi
TRACER_WRAPPER_PID=$!

# Resolve target PID
sleep 0.3
if [[ $USE_QEMU -eq 1 ]]; then
    TARGET_PID=$(pgrep -P "$TRACER_WRAPPER_PID" -f "qemu-x86_64" | head -n1)
    [[ -z "$TARGET_PID" ]] && TARGET_PID=$(pgrep -f "qemu-x86_64.*$(basename "$BINARY")" | head -n1)
else
    TARGET_PID=$(pgrep -P "$TRACER_WRAPPER_PID" -f "$(basename "$BINARY")" | head -n1)
    [[ -z "$TARGET_PID" ]] && TARGET_PID=$(pgrep -f "$(basename "$BINARY")" | head -n1)
fi
echo "[*] Tracer wrapper pid=$TRACER_WRAPPER_PID  target pid=${TARGET_PID:-unknown}"

# GUI interaction (dismiss Tkinter dialogs)
if [[ -n "$XVFB_PID" ]] && command -v xdotool >/dev/null; then
    (
        sleep 3
        export DISPLAY=:99
        xdotool key Return 2>/dev/null || true
        sleep 1
        xdotool key space 2>/dev/null || true
        sleep 1
        xdotool key Return 2>/dev/null || true
    ) &
    XDOTOOL_PID=$!
else
    XDOTOOL_PID=""
fi

# ============================================================================
# PERF HARDWARE COUNTERS (SYS/MEM)
# ============================================================================
PERF_PID=""
if [[ -n "${TARGET_PID:-}" ]]; then
    perf stat -e cycles,cache-misses,page-faults,minor-faults,major-faults \
        -p "$TARGET_PID" -o "$OUTDIR/perf.log" 2>/dev/null &
    PERF_PID=$!
fi

# ============================================================================
# /proc POLLER (MEM + FILE cross-check)
# ============================================================================
{
    echo "epoch,vmrss_kb,read_bytes,write_bytes" > "$OUTDIR/proc_timeline.csv"
    while [[ -n "${TARGET_PID:-}" ]] && kill -0 "$TARGET_PID" 2>/dev/null; do
        VMRSS=$(awk '/VmRSS/{print $2}' "/proc/$TARGET_PID/status" 2>/dev/null)
        RB=$(awk '/^read_bytes/{print $2}' "/proc/$TARGET_PID/io" 2>/dev/null)
        WB=$(awk '/^write_bytes/{print $2}' "/proc/$TARGET_PID/io" 2>/dev/null)
        echo "$(date +%s.%N),${VMRSS:-0},${RB:-0},${WB:-0}" >> "$OUTDIR/proc_timeline.csv"
        sleep 0.1
    done
} &
PROC_POLL_PID=$!

# ============================================================================
# WAIT WITH TIMEOUT
# ============================================================================
ELAPSED=0
while kill -0 "$TRACER_WRAPPER_PID" 2>/dev/null && [[ $ELAPSED -lt $TIMEOUT ]]; do
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
if [[ $ELAPSED -ge $TIMEOUT ]]; then
    echo "[!] Timeout ($TIMEOUT s). Killing target."
    kill -9 "$TRACER_WRAPPER_PID" 2>/dev/null
fi
END_EPOCH=$(date +%s.%N)

# ============================================================================
# TEARDOWN
# ============================================================================
kill "$ENTROPY_PID" "$TCPDUMP_PID" "$PROC_POLL_PID" "$PERF_PID" "$XDOTOOL_PID" 2>/dev/null
[[ -n "$XVFB_PID" ]] && kill "$XVFB_PID" 2>/dev/null
wait 2>/dev/null

# ============================================================================
# METADATA (using jq to avoid heredoc escaping issues)
# ============================================================================
BIN_HASH=$(sha256sum "$BINARY" | awk '{print $1}')
BIN_ARCH=$(file -b "$BINARY" | head -c 200)
DURATION=$(echo "$END_EPOCH - $START_EPOCH" | bc 2>/dev/null || echo 0)
GUI_FLAG=$([ -n "${XVFB_PID:-}" ] && echo true || echo false)

ARGS_JSON="[]"
if [[ ${#BIN_ARGS[@]} -gt 0 ]]; then
    ARGS_JSON=$(printf '%s\n' "${BIN_ARGS[@]}" | jq -R . | jq -s .)
fi

jq -n \
  --arg binary "$BINARY" \
  --arg sha256 "$BIN_HASH" \
  --arg binary_arch "$BIN_ARCH" \
  --arg host_arch "$HOST_ARCH" \
  --argjson used_qemu "$USE_QEMU" \
  --arg qemu_bin "$QEMU_BIN" \
  --arg tracer "$TRACER" \
  --argjson gui_simulated "$GUI_FLAG" \
  --arg start_epoch "$START_EPOCH" \
  --arg end_epoch "$END_EPOCH" \
  --arg duration_sec "$DURATION" \
  --arg target_pid "${TARGET_PID:-}" \
  --arg watch_dir "$WATCHDIR" \
  --argjson bin_args "$ARGS_JSON" \
  --arg timeout "$TIMEOUT" \
  '{
    binary: $binary,
    sha256: $sha256,
    binary_arch: $binary_arch,
    host_arch: $host_arch,
    used_qemu: $used_qemu,
    qemu_bin: $qemu_bin,
    tracer: $tracer,
    gui_simulated: $gui_simulated,
    start_epoch: ($start_epoch|tonumber),
    end_epoch: ($end_epoch|tonumber),
    duration_sec: ($duration_sec|tonumber),
    target_pid: (if $target_pid == "" then null else $target_pid end),
    watch_dir: $watch_dir,
    bin_args: $bin_args,
    timeout: ($timeout|tonumber)
  }' > "$OUTDIR/meta.json"

echo "[*] Done. Logs in $OUTDIR"
echo "[*] Next: python3 parse_logs.py --logdir $OUTDIR --out $OUTDIR/features.csv"
