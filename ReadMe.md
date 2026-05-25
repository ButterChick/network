# Network Traffic ETL Pipeline

A Python-based ETL pipeline that extracts network packet data from PCAP files, processes it, and stores structured insights in a SQLite database.

---

## How to Get Started

### Install Dependencies

```bash
pip install pyshark
```

Requires Wireshark/tshark installed on your system.

---

## Pull Request Using GitHub

Repository:  
:contentReference[oaicite:0]{index=0}

Make a pull request for this repository.

---

## Run the Pipeline

```bash
python etl.py --pcap http.cap --db traffic.db
```

---

## Expected Output

```text
--- Loading Clean Packets ---
Inserted batch 1 - 10 records
Inserted batch 2 - 10 records
Inserted batch 3 - 8 records

--- Loading Flagged Packets ---
Inserted batch 1 - 10 records
Inserted batch 2 - 5 records

Done - 28 total packets loaded into traffic.db
Flagged - 15 packets exceeded 1000 bytes
```

---

# Explanation

## Extract Layer

- Uses `pyshark.FileCapture`
- Streams packets instead of loading all at once
- Outputs structured dictionaries

---

## Transform Layer

Two key operations:

### Data Cleaning

- Removes packets without IP info

### Anomaly Detection

- Flags packets with size > 1000 bytes

---

## Load Layer

- Uses SQLite (`sqlite3`)
- Creates a table automatically
- Adds:
  - ingestion timestamp
  - flagged indicator

---

# Database Schema

```sql
packets (
    timestamp TEXT,
    protocol TEXT,
    length INT,
    src_ip TEXT,
    dst_ip TEXT,
    ingested_at TEXT,
    flagged INT
)
```

---

# For Displaying the Data

## Install Dependencies

```bash
pip install streamlit pandas matplotlib seaborn
```

---

## Run the Code

```bash
streamlit run display.py -- --db traffic.db
```

---

## Expected Output

The Streamlit dashboard renders a **Network Traffic Analysis Dashboard** with:

- A packet data table loaded from `traffic.db`
- Protocol Distribution bar chart of packet counts by protocol:
  - TCP
  - HTTP
  - DNS
  - DATA-TEXT-LINES
  - XML
- Flagged vs Clean Packets pie chart showing:
  - 34.9% flagged
  - 65.1% clean
- Packet Length Distribution histogram with a dashed threshold line at 1000 bytes
- Top 10 Source IPs by packet count
- Top 10 Destination IPs by packet count

---

# Live Network Traffic ETL Pipeline

A real-time ETL pipeline that captures live network traffic, processes packets, and stores structured data in a SQLite database.

---

## How to Get Started

### Install Dependencies

```bash
pip install pyshark
```

Requires Wireshark/tshark installed on your system.

---

## Pull Request Using GitHub

Repository:  
:contentReference[oaicite:1]{index=1}

Make a pull request for this repository.

---

## Run the Pipeline

```bash
python live_etl.py --interface Wi-Fi --host youtube.com --db NewTraffic.db
```

---

## Expected Output

```python
{
    'timestamp': '2026-04-20 13:18:23.366824',
    'protocol': 'TCP',
    'length': 54,
    'src_ip': '192.168.1.217',
    'dst_ip': '142.250.206.110'
}

{
    'timestamp': '2026-04-20 13:18:23.366867',
    'protocol': 'TCP',
    'length': 58,
    'src_ip': '142.250.206.110',
    'dst_ip': '192.168.1.217'
}

{
    'timestamp': '2026-04-20 13:18:23.369060',
    'protocol': 'TLS',
    'length': 128,
    'src_ip': '192.168.1.217',
    'dst_ip': '142.250.206.110'
}

{
    'timestamp': '2026-04-20 13:18:23.369534',
    'protocol': 'TLS',
    'length': 847,
    'src_ip': '192.168.1.217',
    'dst_ip': '142.250.206.110'
}

{
    'timestamp': '2026-04-20 13:18:23.408685',
    'protocol': 'TLS',
    'length': 1010,
    'src_ip': '142.250.206.110',
    'dst_ip': '192.168.1.217'
}

Inserted batch 2 - 9 clean records
Inserted batch 2 - 1 flagged records
```

---

# Explanation

## Extract Layer (Live Capture)

- Uses `pyshark.LiveCapture`
- Continuously listens on network interface
- Applies optional BPF filter

---

## Host Resolution

- Converts domain → IP
- Enables filtering

Example:

```python
resolve_host("google.com") → 142.250.x.x
```

---

## Transform Layer

Same logic as batch ETL:

- Remove packets with missing IPs
- Flag packets with size > 1000 bytes

---

## Load Layer

- Inserts into SQLite
- Adds:
  - ingestion timestamp
  - flagged indicator
- Logs per batch

---

# Database Schema

```sql
packets (
    timestamp TEXT,
    protocol TEXT,
    length INT,
    src_ip TEXT,
    dst_ip TEXT,
    ingested_at TEXT,
    flagged INT
)
```

---

# For Displaying the Data

## Install Dependencies

```bash
pip install streamlit pandas matplotlib seaborn
```

---

## Run the Code

```bash
streamlit run live_display.py -- --db NewTraffic.db
```

---

## Expected Output

The Streamlit dashboard renders a **Real-Time Data Ingestion** view with:

### Settings Panel (Sidebar)

- Max rows shown per feed
  - Slider default: 20
  - Range: 10–100
- Poll interval in seconds slider
- Toggle: Run stream
- Button: Reset feeds

### Status Information

```text
Reading from: NewTraffic.db
Status: Waiting for new rows...
last_rowid=445
Last checked: 13:31:33
```

### Dashboard Components

#### Clean Data Table

Columns:

- #
- Time
- Src IP
- Dst IP
- Proto
- Length

#### Flagged Data Table

- Same columns as clean data
- Highlights packets with length > 1000 bytes