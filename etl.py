import pyshark
import sqlite3
from datetime import datetime
import argparse

# --- EXTRACT ---
def extract_packets(pcap_file, batch_size=10):
    capture = pyshark.FileCapture(pcap_file)
    batch = []
    for pkt in capture:
        try:
            record = {
                "timestamp": str(pkt.sniff_time),
                "protocol": pkt.highest_layer,
                "length": int(pkt.length),
                "src_ip": pkt.ip.src if hasattr(pkt, "ip") else None,
                "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else None,
            }
            batch.append(record)
            if len(batch) >= batch_size:
                yield batch  # pauses the function here and sends the batch to the caller
                batch = []   # reset the batch
        except AttributeError:
            continue
    if batch:
        yield batch  # extract the remaining packets
    capture.close()

# Takes the packets from Loading function as argument and Returns a list of cleaned data
def transform(packets):
    # Filter out records with None IPs
    cleaned = []
    flagged = []
    for pkt in packets:
        # checks if the packet has a source ip and a destination ip
        if pkt['src_ip'] and pkt['dst_ip']:
            if pkt['length'] > 1000:
                flagged.append(pkt)
            else:
                cleaned.append(pkt)
    return cleaned, flagged

# Takes the packets from transform function and db name from line argument and loads the data in a database
def load(packets, db_name, batch_size=10, is_flagged=False):
    if not packets:  # skip DB connection entirely if nothing to insert
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
        # First split packets into chunks
        for i in range(0, len(packets), batch_size):
            batch = packets[i : i + batch_size]
            c.executemany(
                'INSERT INTO packets VALUES (?,?,?,?,?,?,?)',
                [(p['timestamp'], p['protocol'], p['length'],
                  p['src_ip'], p['dst_ip'], now, flagged_value) for p in batch]
            )
            # Commit per batch
            conn.commit()
            print(f"Inserted batch {i // batch_size + 1} - {len(batch)} records")

'''
CLI Interface using argparse
python filename.py --pcap NetworkFileName.cap --db DatabaseName.db
'''
def main():
    parser = argparse.ArgumentParser(description="ETL Network Pipeline")
    parser.add_argument('--pcap', required=True, help="Path to pcap file")
    parser.add_argument('--db', default="traffic.db", help="SQL database name")
    parser.add_argument('--batch-size', type=int, default=10, help="batch-size", dest="batch_size")
    args = parser.parse_args()

    # Calling all the functions for ETL, Dont forget it next time
    all_cleaned = []
    all_flagged = []
    for batch in extract_packets(args.pcap, args.batch_size):
        cleaned, flagged = transform(batch)
        all_cleaned.extend(cleaned)
        all_flagged.extend(flagged)
    
    print(f"\n--- Loading Clean Packets ---")
    load(all_cleaned,args.db,args.batch_size, is_flagged= False)
    
    print(f"\n--- Loading Flagged Packets ---")
    load(all_flagged,args.db,args.batch_size, is_flagged= True)

    print(f"Done - {len(all_cleaned)} total packets loaded into {args.db}")
    print(f"Flagged - {len(all_flagged)} packets exceeded 1000 bytes")

if __name__ == '__main__':
    main()