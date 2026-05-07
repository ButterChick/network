Network Traffic ETL Pipeline
A Python-based ETL pipeline that extracts network packet data from PCAP files, processes it, and stores structured insights in a SQLite database.

How to Get Started
1. Install Dependencies
bashpip install pyshark

Requires Wireshark/tshark installed on your system.

2. Pull Request Using GitHub

Repository: https://github.com/ButterChick/network
Make a pull request for this repository.

3. Run the Pipeline
bashpython etl.py --pcap http.cap --db traffic.db
4. Expected Output
--- Loading Clean Packets ---
Inserted batch 1 - 10 records
Inserted batch 2 - 10 records
Inserted batch 3 - 8 records

--- Loading Flagged Packets ---
Inserted batch 1 - 10 records
Inserted batch 2 - 5 records
Done - 28 total packets loaded into traffic.db
Flagged - 15 packets exceeded 1000 bytes

Explanation
1. Extract Layer

Uses pyshark.FileCapture
Streams packets instead of loading all at once
Outputs structured dictionaries

2. Transform Layer
Two key operations:

Data Cleaning: Removes packets without IP info
Anomaly Detection: Flags packets with size > 1000 bytes

3. Load Layer

Uses SQLite (sqlite3)
Creates a table automatically
Adds:

ingestion timestamp
flagged indicator




Database Schema
sqlpackets (
    timestamp    TEXT,
    protocol     TEXT,
    length       INT,
    src_ip       TEXT,
    dst_ip       TEXT,
    ingested_at  TEXT,
    flagged      INT
)

For Displaying the Data
1. Install Dependencies
bashpip install streamlit pandas matplotlib seaborn
2. Run the Code
bashstreamlit run display.py -- --db traffic.db
3. Expected Output
The Streamlit dashboard renders a Network Traffic Analysis Dashboard with:

A packet data table (loaded from traffic.db)
Protocol Distribution — bar chart of packet counts by protocol (TCP, HTTP, DNS, DATA-TEXT-LINES, XML)
Flagged vs Clean Packets — pie chart showing 34.9% flagged, 65.1% clean
Packet Length Distribution — histogram with a dashed threshold line at 1000 bytes
Top 10 Source IPs (Packet Count) — horizontal bar chart
Top 10 Destination IPs (Packet Count) — horizontal bar chart


Live Network Traffic ETL Pipeline
A real-time ETL pipeline that captures live network traffic, processes packets, and stores structured data in a SQLite database.

How to Get Started
1. Install Dependencies
bashpip install pyshark

Requires Wireshark/tshark installed on your system.

2. Pull Request Using GitHub

Repository: https://github.com/ButterChick/network
Make a pull request for this repository.

3. Run the Pipeline
bashpython live_etl.py --interface Wi-Fi --host youtube.com --db NewTraffic.db
4. Expected Output
{'timestamp': '2026-04-20 13:18:23.366824', 'protocol': 'TCP',  'length': 54,   'src_ip': '192.168.1.217',   'dst_ip': '142.250.206.110'}
{'timestamp': '2026-04-20 13:18:23.366867', 'protocol': 'TCP',  'length': 58,   'src_ip': '142.250.206.110', 'dst_ip': '192.168.1.217'}
{'timestamp': '2026-04-20 13:18:23.366867', 'protocol': 'TCP',  'length': 58,   'src_ip': '142.250.206.110', 'dst_ip': '192.168.1.217'}
{'timestamp': '2026-04-20 13:18:23.366873', 'protocol': 'TCP',  'length': 54,   'src_ip': '192.168.1.217',   'dst_ip': '142.250.206.110'}
{'timestamp': '2026-04-20 13:18:23.366883', 'protocol': 'TCP',  'length': 54,   'src_ip': '192.168.1.217',   'dst_ip': '142.250.206.110'}
{'timestamp': '2026-04-20 13:18:23.369060', 'protocol': 'TLS',  'length': 128,  'src_ip': '192.168.1.217',   'dst_ip': '142.250.206.110'}
{'timestamp': '2026-04-20 13:18:23.369317', 'protocol': 'TLS',  'length': 146,  'src_ip': '192.168.1.217',   'dst_ip': '142.250.206.110'}
{'timestamp': '2026-04-20 13:18:23.369534', 'protocol': 'TLS',  'length': 847,  'src_ip': '192.168.1.217',   'dst_ip': '142.250.206.110'}
{'timestamp': '2026-04-20 13:18:23.408685', 'protocol': 'TLS',  'length': 1010, 'src_ip': '142.250.206.110', 'dst_ip': '192.168.1.217'}
{'timestamp': '2026-04-20 13:18:23.408773', 'protocol': 'TLS',  'length': 89,   'src_ip': '142.250.206.110', 'dst_ip': '192.168.1.217'}
Inserted batch 2 - 9 clean records
Inserted batch 2 - 1 flagged records

Explanation
1. Extract Layer (Live Capture)

Uses pyshark.LiveCapture
Continuously listens on network interface
Applies optional BPF filter

2. Host Resolution

Converts domain → IP
Enables filtering
Example: resolve_host("google.com") → 142.250.x.x

3. Transform Layer
Same logic as batch ETL:

Remove packets with missing IPs
Flag packets with size > 1000 bytes

4. Load Layer

Inserts into SQLite
Adds:

ingestion timestamp
flagged indicator


Logs per batch


Database Schema
sqlpackets (
    timestamp    TEXT,
    protocol     TEXT,
    length       INT,
    src_ip       TEXT,
    dst_ip       TEXT,
    ingested_at  TEXT,
    flagged      INT
)

For Displaying the Data
1. Install Dependencies
bashpip install streamlit pandas matplotlib seaborn
2. Run the Code
bashstreamlit run live_display.py -- --db NewTraffic.db
3. Expected Output
The Streamlit dashboard renders a Real-Time Data Ingestion view with:

Settings panel (sidebar):

Max rows shown per feed (slider, default 20, range 10–100)
Poll interval in seconds (slider)
Toggle: Run stream
Button: Reset feeds


Reading from: NewTraffic.db
Status: Waiting for new rows... last_rowid=445  Last checked: 13:31:33
Clean Data table — columns: #, Time, Src IP, Dst IP, Proto, Length
Flagged Data table — same columns, highlighting packets with length > 1000 bytes