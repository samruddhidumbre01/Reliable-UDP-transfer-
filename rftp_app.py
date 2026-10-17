# rftp_app.py -- RFTP in ONE file: UDP engine + web backend + dashboard page
#   python3 rftp_app.py                      -> dashboard at http://127.0.0.1:8000
#   python3 rftp_app.py receive|send|bench   -> original command line

# rftp.py  --  RFTP: Reliable File Transfer Protocol over UDP  (all modules in ONE file)
#
#   Module 1: send a file over UDP in small packets
#   Module 2: packet numbers + CRC + ACK/NACK + timeout + resend + SHA-256 check
#   Module 3: network monitor (counts what happens on the network)
#   Module 4: adaptive timeout (Smart mode) compared with a fixed timeout (Normal mode)
#
# The engine never uses print() for progress. It calls "on_event(dict)" instead,
# so the web backend can send the same information to the browser later.
#
# Run in two terminals:
#   python3 rftp.py receive
#   python3 rftp.py send myfile.pdf --mode smart --network average
#   python3 rftp.py bench          (compare Normal and Smart automatically)

import argparse
import hashlib
import os
import random
import shutil
import socket
import statistics
import struct
import tempfile
import threading
import time
import zlib

# ---------------- settings ----------------
HEADER = "!III"                       # packet header = seq, total, crc  (3 numbers)
HEADER_SIZE = struct.calcsize(HEADER) # = 12 bytes
REPLY = "!4sI"                        # reply = b"ACK " or b"NACK" + packet number
CHUNK_SIZE = 1024                     # bytes of file data per packet
MAX_RETRIES = 30                      # give up on a packet after this many resends
LINGER = 5.0                          # after a finished file, keep answering this long
                                      # (must be longer than the biggest sender timeout = 2 s)
GIVE_UP = 90.0                        # forget an UNFINISHED file after this much silence
                                      # (a very bad network can pause the sender for a long time)

# Network presets: loss, corruption, min delay, max delay (seconds)
NETWORKS = {
    "none":    (0.00, 0.00, 0.000, 0.00),
    "good":    (0.02, 0.02, 0.005, 0.03),
    "average": (0.10, 0.10, 0.020, 0.12),
    "bad":     (0.25, 0.20, 0.050, 0.30),
}


def say(on_event, **info):
    """Send one event (a small dictionary) to whoever is listening."""
    if on_event:
        info["t"] = time.time()
        on_event(info)


# =====================================================================
#  MODULE 4 : ADAPTIVE TIMEOUT
# =====================================================================
class AdaptiveTimeout:
    # Normal mode = timeout never changes.
    # Smart mode  = learn the reply time (RTT) and adjust (same idea as TCP, RFC 6298).

    def __init__(self, adaptive=True, initial=0.5, min_t=0.05, max_t=2.0):
        self.adaptive = adaptive
        self.timeout = initial        # seconds
        self.min_t = min_t            # never go below this
        self.max_t = max_t            # never go above this
        self.srtt = None              # smoothed (average) reply time
        self.rttvar = None            # how much the reply time jumps around

    def current(self):
        return self.timeout

    def new_timeout(self):
        # timeout = average reply time + 4 x variation, kept between min and max
        t = self.srtt + 4 * self.rttvar
        return min(max(t, self.min_t), self.max_t)

    def on_rtt(self, rtt):            # a good reply arrived: learn from it
        if not self.adaptive:
            return
        if self.srtt is None:         # first sample
            self.srtt = rtt
            self.rttvar = rtt / 2
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - rtt)
            self.srtt = 0.875 * self.srtt + 0.125 * rtt
        self.timeout = self.new_timeout()

    def on_resent_ack(self):          # ACK for a packet we had to resend
        # We cannot measure its RTT (we do not know which copy was answered),
        # but the network works, so we remove the "wait twice as long" backoff.
        if self.adaptive and self.srtt is not None:
            self.timeout = self.new_timeout()

    def on_timeout(self):             # no reply: wait twice as long next time
        if self.adaptive:
            self.timeout = min(self.timeout * 2, self.max_t)


# =====================================================================
#  MODULE 3 : NETWORK MONITOR
# =====================================================================
class NetworkMonitor:

    def __init__(self):
        self.start = time.time()
        self.sends = 0                # every packet we sent (including resends)
        self.retransmissions = 0      # how many of them were resends
        self.acks = 0
        self.timeouts = 0             # lost packets (no reply)
        self.corrupted = 0            # damaged packets (NACK)
        self.bytes_acked = 0
        self.rtts = []                # list of reply times in seconds

    def packet_sent(self, is_resend):
        self.sends += 1
        if is_resend:
            self.retransmissions += 1

    def ack_received(self, rtt, size):
        self.acks += 1
        self.bytes_acked += size
        if rtt is not None:
            self.rtts.append(rtt)

    def nack_received(self):
        self.corrupted += 1

    def timeout_happened(self):
        self.timeouts += 1

    def snapshot(self, timeout=None):
        """All numbers as a dictionary (used by the dashboard)."""
        elapsed = max(time.time() - self.start, 0.001)
        avg = statistics.mean(self.rtts) * 1000 if self.rtts else 0
        jitter = statistics.stdev(self.rtts) * 1000 if len(self.rtts) > 1 else 0
        return {
            "elapsed": round(elapsed, 2),
            "sends": self.sends,
            "acks": self.acks,
            "retransmissions": self.retransmissions,
            "timeouts": self.timeouts,
            "corrupted": self.corrupted,
            "avg_rtt_ms": round(avg, 1),
            "jitter_ms": round(jitter, 1),
            "throughput_kbps": round(self.bytes_acked / elapsed / 1024, 1),
            "efficiency_pct": round(100 * self.acks / self.sends, 1) if self.sends else 0,
            "timeout_s": round(timeout, 3) if timeout else None,
        }

    def show(self, timeout=None):
        s = self.snapshot(timeout)
        print("+--------------------------------------------+")
        print("|              NETWORK MONITOR               |")
        print("+--------------------------------------------+")
        print(f"| Packets sent    : {s['sends']:<24} |")
        print(f"| ACKs received   : {s['acks']:<24} |")
        print(f"| Retransmissions : {s['retransmissions']:<24} |")
        print(f"| Lost (timeout)  : {s['timeouts']:<24} |")
        print(f"| Damaged (NACK)  : {s['corrupted']:<24} |")
        print(f"| Average RTT     : {str(s['avg_rtt_ms']) + ' ms':<24} |")
        print(f"| Jitter          : {str(s['jitter_ms']) + ' ms':<24} |")
        print(f"| Throughput      : {str(s['throughput_kbps']) + ' KB/s':<24} |")
        print(f"| Efficiency      : {str(s['efficiency_pct']) + ' %':<24} |")
        if s["timeout_s"]:
            print(f"| Current timeout : {str(s['timeout_s']) + ' s':<24} |")
        print("+--------------------------------------------+")


# =====================================================================
#  MODULE 2 : THE RECEIVER
# =====================================================================
def new_transfer():
    """Empty notebook for one incoming file."""
    return {"pieces": {}, "total": None, "name": "", "size": 0, "hash": "",
            "crc_errors": 0, "duplicates": 0, "start": None, "done": False}


def run_receiver(host="0.0.0.0", port=5000, out_dir="received", on_event=None, stop_event=None):
    os.makedirs(out_dir, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)                          # wake up often so we can check stop_event
    say(on_event, type="recv_ready", port=port)

    tr = new_transfer()
    last_packet = time.time()

    while stop_event is None or not stop_event.is_set():
        try:
            packet, addr = sock.recvfrom(65535)   # WAIT for a packet
        except socket.timeout:
            # nothing arrived: forget an old transfer so the next file can start
            idle = time.time() - last_packet
            if tr["pieces"] and idle > (LINGER if tr["done"] else GIVE_UP):
                tr = new_transfer()
            continue

        if len(packet) < HEADER_SIZE:             # too short -> not ours
            continue
        seq, total, crc = struct.unpack(HEADER, packet[:HEADER_SIZE])
        data = packet[HEADER_SIZE:]
        if total < 1 or seq > total or len(data) == 0:   # impossible header -> ignore
            continue
        last_packet = time.time()

        # ---- STEP 1: VERIFY (recalculate CRC and compare) ----
        if zlib.crc32(data) != crc:
            tr["crc_errors"] += 1
            sock.sendto(struct.pack(REPLY, b"NACK", seq), addr)
            say(on_event, type="recv_packet", seq=seq, status="crc_error")
            continue

        # A different info packet (packet 0) means the sender started a NEW file
        if seq == 0 and 0 in tr["pieces"] and tr["pieces"][0] != data:
            tr = new_transfer()
        if tr["total"] is None:                   # first packet of this file
            tr["total"] = total
            tr["start"] = time.time()
        elif total != tr["total"]:                # does not belong to this file
            continue

        # packet 0 = file info "name|size|sha256|id"
        if seq == 0:
            try:
                name, size, file_hash, _ = data.decode().rsplit("|", 3)
                size = int(size)
            except ValueError:
                continue

        # ---- STEP 2: CONFIRM (send ACK) ----
        sock.sendto(struct.pack(REPLY, b"ACK ", seq), addr)
        if seq in tr["pieces"]:                   # we already have it (sender resent it)
            tr["duplicates"] += 1
            say(on_event, type="recv_packet", seq=seq, status="duplicate")
            continue
        tr["pieces"][seq] = data
        if seq == 0:
            tr["name"], tr["size"], tr["hash"] = os.path.basename(name), size, file_hash
        have = len(tr["pieces"]) - (1 if 0 in tr["pieces"] else 0)
        say(on_event, type="recv_packet", seq=seq, status="ok", progress=round(100 * have / total))

        # ---- STEP 3: REBUILD (info packet + every data packet are here) ----
        if not tr["done"] and len(tr["pieces"]) == total + 1:
            tr["done"] = True
            all_data = b"".join(tr["pieces"][i] for i in range(1, total + 1))
            path = os.path.join(out_dir, "received_" + tr["name"])
            with open(path, "wb") as f:
                f.write(all_data)
            my_hash = hashlib.sha256(all_data).hexdigest()
            say(on_event, type="recv_done", path=path, name=tr["name"], size=len(all_data),
                packets=total, crc_errors=tr["crc_errors"], duplicates=tr["duplicates"],
                elapsed=round(time.time() - tr["start"], 2),
                sha_sender=tr["hash"], sha_mine=my_hash,
                verified=(my_hash == tr["hash"] and len(all_data) == tr["size"]))
    sock.close()


# =====================================================================
#  MODULE 2 + 3 + 4 : THE SENDER
# =====================================================================
class TransferFailed(Exception):
    pass


def wait_for_answer(sock, seq, t0, timeout_now, loss, delay):
    """Wait for the reply to packet 'seq'.  Returns (answer, rtt).
       answer is "ACK", "NACK" or "TIMEOUT".
       'delay' = the fake network delay chosen for this attempt (seconds)."""
    while True:
        remaining = timeout_now - (time.time() - t0)
        if remaining <= 0:
            return "TIMEOUT", None
        sock.settimeout(remaining)
        try:
            reply, _ = sock.recvfrom(100)
        except socket.timeout:
            return "TIMEOUT", None
        if len(reply) != struct.calcsize(REPLY):
            continue
        kind, reply_seq = struct.unpack(REPLY, reply)
        if reply_seq != seq:                      # old reply for another packet -> ignore
            continue
        if random.random() < loss:                # fake network: the reply got LOST too
            continue
        # fake network: the reply is delayed. If it would arrive after our
        # timeout, we wait the full timeout and give up (like a real slow network).
        arrive = t0 + delay
        if arrive > t0 + timeout_now:
            time.sleep(max(t0 + timeout_now - time.time(), 0))
            return "TIMEOUT", None
        time.sleep(max(arrive - time.time(), 0))
        rtt = time.time() - t0
        return ("ACK" if kind == b"ACK " else "NACK"), rtt


def send_file(path, host="127.0.0.1", port=5000, smart=True, loss=0.0, corrupt=0.0,
              delay_lo=0.0, delay_hi=0.0, network_name="custom", on_event=None, stop_event=None):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) == 0:
        raise ValueError("File is empty")

    chunks = [data[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
    total = len(chunks)
    file_hash = hashlib.sha256(data).hexdigest()
    # packet 0 = file info.  The random number makes every transfer unique.
    info = f"{os.path.basename(path)}|{len(data)}|{file_hash}|{random.randint(0, 10**9)}".encode()
    packets = [info] + chunks

    server = (host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mon = NetworkMonitor()
    tmo = AdaptiveTimeout(adaptive=smart, initial=0.5)
    mode_name = "smart" if smart else "normal"
    say(on_event, type="start", file=os.path.basename(path), size=len(data), total=total,
        mode=mode_name, network=network_name, loss=loss, corrupt=corrupt, delay_max=delay_hi)
    start = time.time()

    try:
        for seq, payload in enumerate(packets):
            crc = zlib.crc32(payload)             # CRC of the CORRECT data
            attempt = 0                           # 0 = first try of this packet

            while True:                           # repeat until this packet is ACKed
                if stop_event is not None and stop_event.is_set():
                    raise TransferFailed("Stopped by user")
                if attempt > MAX_RETRIES:
                    raise TransferFailed(f"Packet {seq} failed after {MAX_RETRIES} resends")

                timeout_now = tmo.current()
                mon.packet_sent(is_resend=attempt > 0)
                t0 = time.time()

                # ---- FAKE NETWORK: lose or damage the packet ----
                if random.random() >= loss:       # (if lost: we simply do not send it)
                    to_send = payload
                    if random.random() < corrupt:
                        to_send = bytes([payload[0] ^ 0xFF]) + payload[1:]   # flip 1st byte
                    sock.sendto(struct.pack(HEADER, seq, total, crc) + to_send, server)

                # ---- WAIT FOR THE ANSWER ----
                delay = random.uniform(delay_lo, delay_hi)
                answer, rtt = wait_for_answer(sock, seq, t0, timeout_now, loss, delay)

                if answer == "ACK":
                    if attempt == 0:              # only a first-try packet gives a clean RTT
                        tmo.on_rtt(rtt)
                        mon.ack_received(rtt, len(payload))
                    else:
                        tmo.on_resent_ack()
                        mon.ack_received(None, len(payload))
                    say(on_event, type="packet", seq=seq, status="ack", attempt=attempt,
                        rtt=round(rtt * 1000, 1) if attempt == 0 else None,
                        timeout=round(tmo.current(), 3))
                    break                         # next packet
                elif answer == "NACK":
                    mon.nack_received()
                    say(on_event, type="packet", seq=seq, status="nack", attempt=attempt,
                        timeout=round(tmo.current(), 3))
                else:                             # TIMEOUT
                    mon.timeout_happened()
                    tmo.on_timeout()
                    say(on_event, type="packet", seq=seq, status="timeout", attempt=attempt,
                        timeout=round(tmo.current(), 3))
                attempt += 1

            say(on_event, type="stats", done=seq + 1, total=total + 1, **mon.snapshot(tmo.current()))
    except TransferFailed as e:
        say(on_event, type="error", message=str(e))
        raise
    finally:
        sock.close()

    elapsed = time.time() - start
    result = {"mode": mode_name, "network": network_name, "file": os.path.basename(path),
              "size": len(data), "total": total, "time_s": round(elapsed, 2)}
    result.update(mon.snapshot(tmo.current()))
    result["time_s"] = round(elapsed, 2)
    say(on_event, type="done", **result)
    return result


# =====================================================================
#  BENCHMARK : Normal vs Smart, repeated, so the numbers are fair
# =====================================================================
def benchmark(networks=("good", "average", "bad"), runs=5, size_kb=16, port=5600, on_progress=None):
    folder = tempfile.mkdtemp()
    src = os.path.join(folder, "test.bin")
    with open(src, "wb") as f:
        f.write(os.urandom(size_kb * 1024))       # random test file

    stop = threading.Event()
    rx = threading.Thread(target=run_receiver, args=("127.0.0.1", port, folder, None, stop))
    rx.start()
    time.sleep(0.3)

    rows = []                                     # one dictionary per run
    for net in networks:
        loss, corrupt, d_lo, d_hi = NETWORKS[net]
        for mode in ("normal", "smart"):
            for run in range(1, runs + 1):
                r = send_file(src, "127.0.0.1", port, mode == "smart", loss, corrupt,
                              d_lo, d_hi, network_name=net)
                r["run"] = run
                rows.append(r)
                if on_progress:
                    on_progress(net, mode, run, r["time_s"])
    stop.set()
    rx.join()
    shutil.rmtree(folder, ignore_errors=True)

    summary = []                                  # average over the runs
    for net in networks:
        for mode in ("normal", "smart"):
            group = [r for r in rows if r["network"] == net and r["mode"] == mode]
            times = [r["time_s"] for r in group]
            summary.append({
                "network": net, "mode": mode, "runs": len(group),
                "time_mean": round(statistics.mean(times), 2),
                "time_std": round(statistics.stdev(times), 2) if len(times) > 1 else 0,
                "retrans_mean": round(statistics.mean(r["retransmissions"] for r in group), 1),
                "timeouts_mean": round(statistics.mean(r["timeouts"] for r in group), 1),
            })
    return rows, summary


# =====================================================================
#  COMMAND LINE  (console printing lives here, not in the engine)
# =====================================================================
def print_sender_event(e):
    if e["type"] == "start":
        print(f"File: {e['file']}  ({e['total']} packets)")
        print(f"Mode: {e['mode']}   Network: {e['network']}  (loss {e['loss']:.0%}, "
              f"corruption {e['corrupt']:.0%}, delay up to {e['delay_max'] * 1000:.0f} ms)\n")
    elif e["type"] == "packet":
        name = "Info   " if e["seq"] == 0 else f"Packet {e['seq']:<4}"
        text = {"ack": "ACK", "nack": "CRC ERROR -> RETRANSMITTED",
                "timeout": "TIMEOUT   -> RETRANSMITTED"}[e["status"]]
        print(f"{name} {text}   [timeout {e['timeout']:.2f}s]")
    elif e["type"] == "error":
        print("ERROR:", e["message"])


def print_receiver_event(e):
    if e["type"] == "recv_ready":
        print(f"Receiver ready on port {e['port']}. Waiting for packets...\n")
    elif e["type"] == "recv_packet":
        print(f"Packet {e['seq']:<4} {e['status']}")
    elif e["type"] == "recv_done":
        print("\n----------- TRANSFER SUMMARY -----------")
        print(f"Saved as         : {e['path']}")
        print(f"CRC errors caught: {e['crc_errors']}")
        print(f"Duplicates       : {e['duplicates']}")
        print(f"SHA-256 (sender) : {e['sha_sender'][:16]}...")
        print(f"SHA-256 (mine)   : {e['sha_mine'][:16]}...")
        print("RESULT           : " + ("VERIFIED - file is identical" if e["verified"]
                                       else "MISMATCH - file is damaged"))
        print()


def main():
    parser = argparse.ArgumentParser(description="RFTP - reliable file transfer over UDP")
    sub = parser.add_subparsers(dest="command", required=True)

    r = sub.add_parser("receive")
    r.add_argument("--port", type=int, default=5000)
    r.add_argument("--out", default="received")

    s = sub.add_parser("send")
    s.add_argument("file")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--mode", choices=["normal", "smart"], default="smart")
    s.add_argument("--network", choices=list(NETWORKS), default="average")

    b = sub.add_parser("bench")
    b.add_argument("--runs", type=int, default=5)
    b.add_argument("--size-kb", type=int, default=16)

    a = parser.parse_args()

    if a.command == "receive":
        try:
            run_receiver("0.0.0.0", a.port, a.out, print_receiver_event)
        except KeyboardInterrupt:
            print("\nReceiver closed.")

    elif a.command == "send":
        loss, corrupt, d_lo, d_hi = NETWORKS[a.network]
        try:
            res = send_file(a.file, a.host, a.port, a.mode == "smart", loss, corrupt,
                            d_lo, d_hi, a.network, print_sender_event)
        except (TransferFailed, OSError, ValueError) as err:
            raise SystemExit(f"Failed: {err}")
        print(f"\nTransfer complete in {res['time_s']} s   (mode: {res['mode']}, network: {a.network})")
        print(f"Retransmissions: {res['retransmissions']}   Timeouts: {res['timeouts']}   "
              f"NACKs: {res['corrupted']}   Throughput: {res['throughput_kbps']} KB/s")

    elif a.command == "bench":
        _, summary = benchmark(runs=a.runs, size_kb=a.size_kb,
                               on_progress=lambda n, m, i, t: print(f"{n:<8} {m:<7} run {i}: {t} s"))
        print(f"\n{'network':<9}{'mode':<8}{'time (s)':<16}{'retrans':<10}{'timeouts'}")
        for x in summary:
            print(f"{x['network']:<9}{x['mode']:<8}{x['time_mean']} +- {x['time_std']:<8}"
                  f"{x['retrans_mean']:<10}{x['timeouts_mean']}")




# =====================================================================
#  WEB BACKEND
# =====================================================================
# server.py -- RFTP web backend (Python standard library only, no pip install needed)
#   python3 server.py            ->  open http://127.0.0.1:8000
import json, queue, re, urllib.parse, mimetypes, sys
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
rftp = sys.modules[__name__]

ROOT = os.path.dirname(os.path.abspath(__file__))
UP, RX = (os.path.join(ROOT, d) for d in ("uploads", "received"))
MAX_UPLOAD = 20 * 1024 * 1024
for d in (UP, RX):
    os.makedirs(d, exist_ok=True)

subs, lock = set(), threading.Lock()
S = {"rx_stop": None, "rx_port": None, "send_stop": None, "bench": False}


def publish(e):
    """Push one event to every connected browser (Server-Sent Events)."""
    data = json.dumps(e)
    with lock:
        for q in list(subs):
            q.put(data)


def busy_sending():
    return S["send_stop"] is not None


def start_receiver(port):
    if S["rx_stop"]:
        return False, "Receiver already running"
    stop = threading.Event()

    def run():
        try:
            rftp.run_receiver("0.0.0.0", port, RX, publish, stop)
        except OSError as err:
            publish({"type": "recv_error", "message": str(err)})
        finally:
            S["rx_stop"] = S["rx_port"] = None
            publish({"type": "recv_stopped"})

    S["rx_stop"], S["rx_port"] = stop, port
    threading.Thread(target=run, daemon=True).start()
    return True, "ok"


def start_send(path, p):
    stop = threading.Event()
    S["send_stop"] = stop

    def run():
        try:
            rftp.send_file(path, p["host"], p["port"], p["mode"] == "smart", p["loss"], p["corrupt"],
                           p["dlo"], p["dhi"], p["network"], lambda e: publish({**e, "src": "send"}), stop)
        except (rftp.TransferFailed, OSError, ValueError) as err:
            if not isinstance(err, rftp.TransferFailed):   # TransferFailed already emitted an event
                publish({"type": "error", "message": str(err)})
        finally:
            S["send_stop"] = None
            publish({"type": "send_idle"})

    threading.Thread(target=run, daemon=True).start()


def start_bench(runs, size_kb):
    S["bench"] = True

    def run():
        try:
            rows, summary = rftp.benchmark(
                runs=runs, size_kb=size_kb,
                on_progress=lambda n, m, i, t: publish({"type": "bench_progress", "network": n, "mode": m, "run": i, "time": t}))
            publish({"type": "bench_done", "summary": summary, "runs": runs, "size_kb": size_kb})
        except Exception as err:
            publish({"type": "bench_error", "message": str(err)})
        finally:
            S["bench"] = False

    threading.Thread(target=run, daemon=True).start()


def num(v, lo, hi, default):
    try:
        return min(max(float(v), lo), hi)
    except (TypeError, ValueError):
        return default


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ---- helpers ----
    def reply(self, code, obj=None, ctype="application/json", raw=None, extra=None):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_body(self, limit=MAX_UPLOAD):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            return None
        return self.rfile.read(n)

    # ---- GET ----
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path
        if path == "/events":
            return self.sse()
        if path == "/api/state":
            return self.reply(200, {"receiver": S["rx_port"], "sending": busy_sending(), "bench": S["bench"],
                                    "networks": rftp.NETWORKS, "files": self.files()})
        if path.startswith("/download/"):
            name = os.path.basename(urllib.parse.unquote(path[10:]))
            full = os.path.join(RX, name)
            if not os.path.isfile(full):
                return self.reply(404, {"error": "not found"})
            with open(full, "rb") as f:
                return self.reply(200, ctype="application/octet-stream", raw=f.read(),
                                  extra={"Content-Disposition": f'attachment; filename="{name}"'})
        if path in ("/", "/index.html"):
            return self.reply(200, ctype="text/html; charset=utf-8", raw=INDEX_HTML.encode())
        return self.reply(404, {"error": "not found"})

    def files(self):
        out = []
        for n in sorted(os.listdir(RX)):
            st = os.stat(os.path.join(RX, n))
            out.append({"name": n, "size": st.st_size, "mtime": st.st_mtime})
        return out

    def sse(self):
        q = queue.Queue()
        with lock:
            subs.add(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                try:
                    self.wfile.write(f"data: {q.get(timeout=15)}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with lock:
                subs.discard(q)

    # ---- POST ----
    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        p = url.path
        if p == "/api/receiver/start":
            ok, msg = start_receiver(int(num(qs.get("port"), 1024, 65535, 5000)))
            return self.reply(200 if ok else 409, {"ok": ok, "message": msg})
        if p == "/api/receiver/stop":
            if S["rx_stop"]:
                S["rx_stop"].set()
            return self.reply(200, {"ok": True})
        if p == "/api/stop":
            if S["send_stop"]:
                S["send_stop"].set()
            return self.reply(200, {"ok": True})
        if p == "/api/bench":
            if S["bench"] or busy_sending():
                return self.reply(409, {"ok": False, "message": "Something is already running"})
            start_bench(int(num(qs.get("runs"), 1, 10, 3)), int(num(qs.get("size_kb"), 1, 64, 16)))
            return self.reply(200, {"ok": True})
        if p == "/api/send":
            if busy_sending() or S["bench"]:
                self.read_body()
                return self.reply(409, {"ok": False, "message": "A transfer is already running"})
            body = self.read_body()
            if body is None:
                return self.reply(413, {"ok": False, "message": "File too large (max 20 MB)"})
            if not body:
                return self.reply(400, {"ok": False, "message": "File is empty"})
            name = re.sub(r"[^\w.\- ]", "_", os.path.basename(urllib.parse.unquote(self.headers.get("X-Filename", "upload.bin")))) or "upload.bin"
            path = os.path.join(UP, name)
            with open(path, "wb") as f:
                f.write(body)
            net = qs.get("network", "average")
            if net == "custom":
                params = dict(loss=num(qs.get("loss"), 0, 0.9, 0) / 1, corrupt=num(qs.get("corrupt"), 0, 0.9, 0),
                              dlo=0.0, dhi=num(qs.get("delay"), 0, 1, 0))
            elif net in rftp.NETWORKS:
                l, c, lo, hi = rftp.NETWORKS[net]
                params = dict(loss=l, corrupt=c, dlo=lo, dhi=hi)
            else:
                return self.reply(400, {"ok": False, "message": "Unknown network"})
            params.update(host=qs.get("host", "127.0.0.1"), port=int(num(qs.get("port"), 1, 65535, 5000)),
                          mode="normal" if qs.get("mode") == "normal" else "smart", network=net)
            start_send(path, params)
            return self.reply(200, {"ok": True})
        self.reply(404, {"error": "not found"})


# =====================================================================
#  FRONTEND (HTML page served at /)
# =====================================================================
INDEX_HTML = r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RFTP Dashboard</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--tx:#1c2230;--mut:#6b7385;--bd:#e1e4ea;--ac:#2f6fed;--ok:#1f9d55;--bad:#d64545;--warn:#e0a21b;--rt:#8b5cf6}
@media(prefers-color-scheme:dark){:root{--bg:#0f1219;--card:#181d28;--tx:#e8ebf2;--mut:#8b93a7;--bd:#272e3d;--ac:#5b8cff;--ok:#3ecf7a;--bad:#ff6b6b;--warn:#f0b840;--rt:#a78bfa}}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,sans-serif;background:var(--bg);color:var(--tx)}
header{padding:16px 24px;border-bottom:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
h1{font-size:18px;margin:0}h2{font-size:13px;margin:0 0 10px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
main{max-width:1200px;margin:auto;padding:16px;display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;grid-column:span 12;min-width:0}
@media(min-width:900px){.s4{grid-column:span 4}.s5{grid-column:span 5}.s6{grid-column:span 6}.s7{grid-column:span 7}.s8{grid-column:span 8}}
label{display:block;font-size:12px;color:var(--mut);margin:8px 0 3px}
select,input[type=number],input[type=text]{width:100%;padding:7px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--tx)}
button{padding:8px 14px;border:0;border-radius:6px;background:var(--ac);color:#fff;font-weight:600;cursor:pointer}
button.sec{background:transparent;color:var(--tx);border:1px solid var(--bd)}button:disabled{opacity:.45;cursor:not-allowed}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.row>*{flex:1}
.drop{border:2px dashed var(--bd);border-radius:8px;padding:18px;text-align:center;color:var(--mut);cursor:pointer}.drop.on{border-color:var(--ac)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px}
.stat{background:var(--bg);border-radius:8px;padding:8px 10px}.stat b{display:block;font-size:18px}.stat span{font-size:11px;color:var(--mut)}
.bar{height:10px;background:var(--bg);border-radius:6px;overflow:hidden;margin:6px 0}.bar i{display:block;height:100%;width:0;background:var(--ac);transition:width .15s}
canvas{width:100%;display:block}#log{height:190px;overflow:auto;font:12px ui-monospace,monospace;background:var(--bg);border-radius:6px;padding:8px}
.lg{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--mut);margin-top:6px}.lg i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}
.pill{padding:2px 9px;border-radius:99px;font-size:12px;background:var(--bg);border:1px solid var(--bd)}
.good{color:var(--ok)}.err{color:var(--bad)}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:5px 6px;border-bottom:1px solid var(--bd);text-align:left}
.hash{font:11px ui-monospace,monospace;word-break:break-all;color:var(--mut)}a{color:var(--ac)}
</style></head><body>
<header><h1>RFTP &middot; Reliable File Transfer over UDP</h1><span id="conn" class="pill">connecting...</span></header>
<main>
<section class="card s4"><h2>Sender</h2>
 <div class="drop" id="drop">Drop a file here or click to choose<br><small id="fname">(max 20 MB)</small></div><input type="file" id="file" hidden>
 <label>Timeout mode</label><select id="mode"><option value="smart">Smart (adaptive timeout)</option><option value="normal">Normal (fixed timeout)</option></select>
 <label>Simulated network</label><select id="net"></select>
 <div id="custom" hidden><label>Loss % / Corruption % / Max delay ms</label><div class="row" style="margin:0"><input type="number" id="cl" value="10" min="0" max="90"><input type="number" id="cc" value="10" min="0" max="90"><input type="number" id="cd" value="100" min="0" max="1000"></div></div>
 <label>Receiver host : port</label><div class="row" style="margin:0"><input type="text" id="host" value="127.0.0.1" style="flex:2"><input type="number" id="sport" value="5000"></div>
 <div class="row"><button id="send" disabled>Send file</button><button class="sec" id="stop" disabled>Stop</button></div>
</section>
<section class="card s8"><h2>Live transfer <span id="status" class="pill">idle</span></h2>
 <div class="bar"><i id="prog"></i></div><div id="ptxt" style="color:var(--mut);font-size:12px">No transfer yet</div>
 <div class="stats" id="stats" style="margin-top:10px"></div>
</section>
<section class="card s7"><h2>Packet map</h2><canvas id="map" height="110"></canvas>
 <div class="lg"><span><i style="background:var(--bd)"></i>waiting</span><span><i style="background:var(--ok)"></i>ACK</span><span><i style="background:var(--rt)"></i>ACK after resend</span><span><i style="background:var(--warn)"></i>CRC error (NACK)</span><span><i style="background:var(--bad)"></i>timeout</span></div>
</section>
<section class="card s5"><h2>RTT vs timeout (ms)</h2><canvas id="chart" height="150"></canvas>
 <div class="lg"><span><i style="background:var(--ac)"></i>measured RTT</span><span><i style="background:var(--bad)"></i>current timeout</span></div></section>
<section class="card s5"><h2>Receiver <span id="rstat" class="pill">stopped</span></h2>
 <div class="row" style="margin-top:0"><input type="number" id="rport" value="5000"><button id="rtoggle">Start receiver</button></div>
 <div id="verify" style="margin-top:12px;color:var(--mut)">Waiting for a file...</div>
 <h2 style="margin-top:14px">Received files</h2><table id="files"></table></section>
<section class="card s7"><h2>Event log</h2><div id="log"></div></section>
<section class="card"><h2>Benchmark: Normal vs Smart</h2>
 <div class="row" style="margin-top:0;align-items:end"><div><label>Runs per case</label><input type="number" id="bruns" value="3" min="1" max="10"></div><div><label>Test file (KB)</label><input type="number" id="bsize" value="16" min="1" max="64"></div><button id="bench">Run benchmark</button></div>
 <div id="bstat" style="margin:8px 0;color:var(--mut)">Runs both modes on good / average / bad networks with a private receiver.</div>
 <canvas id="bchart" height="200"></canvas><table id="btable"></table></section>
</main>
<script>
const $=s=>document.querySelector(s),css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
let file=null,cells=[],rtts=[],tmos=[],busy=false,rxOn=false,benchBusy=false,dirty=false;
const post=(u,b,h)=>fetch(u,{method:'POST',body:b,headers:h}).then(r=>r.json());
function log(t,c){const d=document.createElement('div');d.textContent=new Date().toLocaleTimeString()+'  '+t;if(c)d.className=c;const l=$('#log');l.appendChild(d);if(l.children.length>400)l.firstChild.remove();l.scrollTop=1e9}
function sync(){$('#send').disabled=!file||busy||benchBusy;$('#stop').disabled=!busy;$('#bench').disabled=busy||benchBusy;$('#rtoggle').textContent=rxOn?'Stop receiver':'Start receiver';$('#rstat').textContent=rxOn?'listening':'stopped';$('#rstat').className='pill '+(rxOn?'good':'')}
// ---- controls ----
const drop=$('#drop');drop.onclick=()=>$('#file').click();
drop.ondragover=e=>{e.preventDefault();drop.classList.add('on')};drop.ondragleave=()=>drop.classList.remove('on');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('on');pick(e.dataTransfer.files[0])};$('#file').onchange=e=>pick(e.target.files[0]);
function pick(f){if(!f)return;if(f.size>20*1024*1024){alert('Max 20 MB');return}file=f;$('#fname').textContent=f.name+' ('+(f.size/1024).toFixed(1)+' KB)';sync()}
$('#net').onchange=()=>$('#custom').hidden=$('#net').value!=='custom';
$('#send').onclick=async()=>{const q=new URLSearchParams({mode:$('#mode').value,network:$('#net').value,host:$('#host').value,port:$('#sport').value,loss:$('#cl').value/100,corrupt:$('#cc').value/100,delay:$('#cd').value/1000});
 const r=await post('/api/send?'+q,file,{'X-Filename':encodeURIComponent(file.name)});if(!r.ok)return alert(r.message);busy=true;sync()};
$('#stop').onclick=()=>post('/api/stop');
$('#rtoggle').onclick=async()=>{if(rxOn){await post('/api/receiver/stop')}else{const r=await post('/api/receiver/start?port='+$('#rport').value);if(!r.ok)alert(r.message)}};
$('#bench').onclick=async()=>{const r=await post(`/api/bench?runs=${$('#bruns').value}&size_kb=${$('#bsize').value}`);if(!r.ok)return alert(r.message);benchBusy=true;$('#bstat').textContent='Running...';sync()};
// ---- stats cards ----
const CARDS=[['sends','Packets sent'],['acks','ACKs'],['retransmissions','Retransmits'],['timeouts','Lost (timeout)'],['corrupted','Damaged (NACK)'],['avg_rtt_ms','Avg RTT ms'],['jitter_ms','Jitter ms'],['throughput_kbps','KB/s'],['efficiency_pct','Efficiency %'],['timeout_s','Timeout s']];
$('#stats').innerHTML=CARDS.map(([k,l])=>`<div class="stat"><b id="st_${k}">-</b><span>${l}</span></div>`).join('');
const setStats=s=>CARDS.forEach(([k])=>{const v=s[k];$('#st_'+k).textContent=v==null?'-':v});
// ---- drawing ----
function fit(c){const r=devicePixelRatio||1,w=c.clientWidth,h=+c.getAttribute('height');c.width=w*r;c.height=h*r;const x=c.getContext('2d');x.scale(r,r);return[x,w,h]}
function drawMap(){const[x,w,h]=fit($('#map'));x.clearRect(0,0,w,h);const n=cells.length;if(!n)return;
 const cols=['',css('--ok'),css('--warn'),css('--bad'),css('--rt')],bg=css('--bd');let cs=Math.max(3,Math.min(18,Math.sqrt(w*h/n)));const per=Math.floor(w/cs);
 for(let i=0;i<n;i++){x.fillStyle=cells[i]?cols[cells[i]]:bg;x.fillRect((i%per)*cs,Math.floor(i/per)*cs,cs-1,cs-1)}}
function drawChart(){const[x,w,h]=fit($('#chart'));x.clearRect(0,0,w,h);const N=Math.max(rtts.length,tmos.length);if(N<2)return;
 const R=rtts.slice(-150),T=tmos.slice(-150),mx=Math.max(...T,...R.filter(v=>v!=null),50)*1.1;
 const line=(a,col)=>{x.strokeStyle=col;x.lineWidth=1.5;x.beginPath();a.forEach((v,i)=>{const px=i/(a.length-1)*(w-34)+32,py=h-14-(v/mx)*(h-24);i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke()};
 x.fillStyle=css('--mut');x.font='10px system-ui';x.fillText(Math.round(mx),0,10);x.fillText('0',0,h-14);line(R,css('--ac'));line(T,css('--bad'))}
function redraw(){if(dirty)return;dirty=true;requestAnimationFrame(()=>{dirty=false;drawMap();drawChart()})}
function drawBench(sum){const[x,w,h]=fit($('#bchart'));x.clearRect(0,0,w,h);const nets=[...new Set(sum.map(s=>s.network))],mx=Math.max(...sum.map(s=>s.time_mean))*1.15||1,gw=(w-40)/nets.length;
 x.font='11px system-ui';nets.forEach((n,i)=>['normal','smart'].forEach((m,j)=>{const s=sum.find(a=>a.network===n&&a.mode===m),bh=s.time_mean/mx*(h-40),bx=40+i*gw+gw*.2+j*gw*.3;
  x.fillStyle=m==='smart'?css('--ac'):css('--mut');x.fillRect(bx,h-22-bh,gw*.26,bh);x.fillStyle=css('--tx');x.fillText(s.time_mean+'s',bx,h-26-bh);x.fillText(m,bx,h-8)}));
 nets.forEach((n,i)=>{x.fillStyle=css('--mut');x.fillText(n,44+i*gw+gw*.2,12)})}
// ---- events ----
function onEvent(e){
 if(e.type==='start'){cells=new Array(e.total+1).fill(0);rtts=[];tmos=[];busy=true;$('#status').textContent='sending ('+e.mode+')';$('#prog').style.width='0';
  $('#ptxt').textContent=`${e.file} - ${e.total} data packets - ${e.network} network`;log(`START ${e.file} mode=${e.mode} net=${e.network}`);sync();redraw()}
 else if(e.type==='packet'){cells[e.seq]=e.status==='ack'?(e.attempt?4:1):e.status==='nack'?2:3;tmos.push(e.timeout*1000);if(e.rtt!=null)rtts.push(e.rtt);
  if(e.status!=='ack')log(`packet ${e.seq}: ${e.status==='nack'?'CRC error -> resend':'timeout -> resend'} (attempt ${e.attempt+1})`,e.status==='nack'?'':'err');redraw()}
 else if(e.type==='stats'){setStats(e);const p=100*e.done/e.total;$('#prog').style.width=p+'%';$('#ptxt').textContent=`${e.done}/${e.total} packets acknowledged (${p.toFixed(0)}%)`}
 else if(e.type==='done'){setStats(e);$('#status').textContent='done in '+e.time_s+'s';log(`DONE in ${e.time_s}s, ${e.retransmissions} retransmissions`,'good')}
 else if(e.type==='error'){$('#status').textContent='failed';log('ERROR '+e.message,'err')}
 else if(e.type==='send_idle'){busy=false;sync()}
 else if(e.type==='recv_ready'){rxOn=true;log('Receiver listening on port '+e.port);sync()}
 else if(e.type==='recv_stopped'){rxOn=false;sync()}
 else if(e.type==='recv_error'){log('Receiver error: '+e.message,'err');alert(e.message)}
 else if(e.type==='recv_packet'){if(e.status==='crc_error')log(`receiver: packet ${e.seq} failed CRC -> NACK`)}
 else if(e.type==='recv_done'){const ok=e.verified;$('#verify').innerHTML=`<b class="${ok?'good':'err'}">${ok?'VERIFIED - file is identical':'MISMATCH - file damaged'}</b><br>${e.name} - ${e.size} bytes - ${e.packets} packets in ${e.elapsed}s<br>CRC errors caught: ${e.crc_errors} - duplicates: ${e.duplicates}<div class="hash">sender SHA-256: ${e.sha_sender}<br>receiver SHA-256: ${e.sha_mine}</div>`;
  log('Receiver: '+(ok?'SHA-256 verified':'SHA-256 MISMATCH'),ok?'good':'err');loadFiles()}
 else if(e.type==='bench_progress'){$('#bstat').textContent=`Running: ${e.network} / ${e.mode} / run ${e.run} -> ${e.time}s`}
 else if(e.type==='bench_done'){benchBusy=false;sync();$('#bstat').textContent=`Done: ${e.runs} runs per case, ${e.size_kb} KB file`;drawBench(e.summary);
  $('#btable').innerHTML='<tr><th>Network</th><th>Mode</th><th>Time (s)</th><th>Retransmits</th><th>Timeouts</th></tr>'+e.summary.map(s=>`<tr><td>${s.network}</td><td>${s.mode}</td><td>${s.time_mean} &plusmn; ${s.time_std}</td><td>${s.retrans_mean}</td><td>${s.timeouts_mean}</td></tr>`).join('')}
 else if(e.type==='bench_error'){benchBusy=false;sync();$('#bstat').textContent='Benchmark failed: '+e.message}
}
async function loadFiles(){const s=await (await fetch('/api/state')).json();$('#files').innerHTML=s.files.length?s.files.map(f=>`<tr><td><a href="/download/${encodeURIComponent(f.name)}">${f.name}</a></td><td>${(f.size/1024).toFixed(1)} KB</td></tr>`).join(''):'<tr><td style="color:var(--mut)">none yet</td></tr>'}
async function init(){const s=await (await fetch('/api/state')).json();
 $('#net').innerHTML=Object.entries(s.networks).map(([k,v])=>`<option value="${k}" ${k==='average'?'selected':''}>${k} (loss ${v[0]*100}%, corrupt ${v[1]*100}%, delay <=${v[3]*1000}ms)</option>`).join('')+'<option value="custom">custom...</option>';
 rxOn=!!s.receiver;busy=s.sending;benchBusy=s.bench;sync();loadFiles();
 const es=new EventSource('/events');es.onopen=()=>{$('#conn').textContent='live';$('#conn').className='pill good'};es.onerror=()=>{$('#conn').textContent='reconnecting...';$('#conn').className='pill err'};
 es.onmessage=m=>onEvent(JSON.parse(m.data))}
addEventListener('resize',redraw);init();
</script></body></html>
'''


def serve():
    port = int(os.environ.get("PORT", 8000))
    print(f"RFTP dashboard: http://127.0.0.1:{port}   (Ctrl+C to quit)")
    try:
        ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    # no arguments (or "web") -> dashboard;  receive / send / bench -> command line
    if len(sys.argv) == 1 or sys.argv[1] == "web":
        serve()
    else:
        main()
