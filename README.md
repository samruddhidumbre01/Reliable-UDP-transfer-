# Reliable-UDP-transfer

Reliable File Transfer Protocol (RFTP) built on top of UDP, with a live web dashboard.

## Features
- Files split into numbered packets sent over UDP
- CRC32 check on every packet, ACK/NACK replies, timeout and retransmission
- SHA-256 check of the finished file
- Network monitor: loss, corruption, RTT, jitter, throughput, efficiency
- Adaptive timeout ("Smart" mode, RFC 6298 style) compared with a fixed timeout ("Normal" mode)
- Simulated networks: none, good, average, bad, or custom

## How to run
Requires Python 3 only (no installs).

    python3 rftp_app.py

Then open http://127.0.0.1:8000

1. Click **Start receiver**
2. Choose a file, pick Smart/Normal and a network, click **Send file**
3. Watch the packet map, RTT chart and SHA-256 verification
4. Click **Run benchmark** to compare Normal vs Smart

## Command line
    python3 rftp_app.py receive
    python3 rftp_app.py send myfile.pdf --mode smart --network average
    python3 rftp_app.py bench --runs 10

## Results
(Benchmark table goes here)

## Screenshots
(Dashboard screenshot goes here)
