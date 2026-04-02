import pyshark
import sqlite3
import socket
import asyncio
import logging
from datetime import datetime
import argparse

logging.getLogger("asyncio").setLevel(logging.CRITICAL)
# --- EXTRACT ---
def extract_packets_live(interface, target_host=None, batch_size=10):
    bpf_filter = None #Berkeley Packet Filter
    if target_host:
        ip = resolve_host(target_host) if not target_host[0].isdigit() else target_host
        bpf_filter = f"host {ip}"

    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
    batch = []


    try:
        for pkt in capture.sniff_continuously():
            try:
                record = {
                    "timestamp": str(pkt.sniff_time),
                    "protocol":  pkt.highest_layer,
                    "length":    int(pkt.length),
                    "src_ip":    pkt.ip.src if hasattr(pkt, "ip") else None,
                    "dst_ip":    pkt.ip.dst if hasattr(pkt, "ip") else None,
                }
                batch.append(record)
                print(record)
                if len(batch) >= batch_size:
                    yield batch
                    batch = []
            except AttributeError:
                continue

    except (KeyboardInterrupt,EOFError):
        pass  # graceful Ctrl+C stop

    finally:
        if batch:
            yield batch  # flush remaining packets
        try:
            capture.eventloop.stop()         # stop the loop before closing
            capture.close()
        except Exception:
            pass  # suppress any further cleanup errors

# --- HELPER ---
def resolve_host(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")

# --- TRANSFORM --- (same logic as original)
def transform(packets):
    cleaned = []
    flagged = []
    for pkt in packets:
        if pkt['src_ip'] and pkt['dst_ip']:
            if pkt['length'] > 1000:
                flagged.append(pkt)
            else:
                cleaned.append(pkt)
    return cleaned, flagged

# --- LOAD --- (same logic as original)
def load(packets, db_name, batch_size=10, is_flagged=False, batch_num = None):
    if not packets:
        return
    with sqlite3.connect(db_name) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS packets(
                  timestamp TEXT,
                  protocol TEXT,
                  length INT,
                  src_ip TEXT,
                  dst_ip TEXT,
                  ingested_at TEXT,
                  flagged INT DEFAULT 0)''')
        now = datetime.now().isoformat()
        flagged_value = 1 if is_flagged else 0
        label = f"batch {batch_num}" if batch_num else "batch"        
        c.executemany(
            'INSERT INTO packets VALUES (?,?,?,?,?,?,?)',
            [(p['timestamp'], p['protocol'], p['length'],
              p['src_ip'], p['dst_ip'], now, flagged_value) for p in packets]
        )
        conn.commit()
        print(f"Inserted {label} - {len(packets)} {'flagged' if is_flagged else 'clean'} records")

'''
CLI Interface
python live_capture.py --interface eth0 --host google.com --db traffic.db
'''
def main():
    parser = argparse.ArgumentParser(description="Live Network Capture ETL Pipeline")
    parser.add_argument('--interface', required=True, help="Network interface (e.g. eth0, Wi-Fi)")
    parser.add_argument('--host', default=None, help="Target hostname or IP to filter (e.g. google.com)")
    parser.add_argument('--db', default="traffic.db", help="SQLite database name")
    parser.add_argument('--batch-size', type=int, default=10, help="Batch size", dest="batch_size")
    args = parser.parse_args()

    total_cleaned = 0
    total_flagged = 0
    batch_num = 0

    print(f"Capturing on {args.interface}" + (f" filtered to {args.host}" if args.host else "") + " — press Ctrl+C to stop\n")

    for batch in extract_packets_live(args.interface, target_host=args.host, batch_size=args.batch_size):
        cleaned, flagged = transform(batch)
        batch_num +=1
        load(cleaned, args.db, args.batch_size, is_flagged=False,batch_num=batch_num)
        load(flagged, args.db, args.batch_size, is_flagged=True,batch_num=batch_num)
        total_cleaned+= len(cleaned)
        total_flagged+= len(flagged)

    print(f"\nDone - {total_cleaned} total packets loaded into {args.db}")
    print(f"Flagged - {(total_flagged)} packets exceeded 1000 bytes")

if __name__ == '__main__':
    main()