import streamlit as st
import sqlite3
import pandas as pd
import time
import argparse
import sys
from datetime import datetime

st.set_page_config(page_title="Real-Time Data Ingestion", layout="wide")
st.title("Real-Time Data Ingestion")

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="traffic.db", help="SQLite database path")
    return parser.parse_args(sys.argv[1:])

args = get_args()
st.caption(f"Reading from: `{args.db}`")

def fetch_new(db_path, since_rowid):
    try:
        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query(
            "SELECT rowid, * FROM packets WHERE rowid > ? ORDER BY rowid ASC",
            conn, params=(since_rowid,)
        )
        conn.close()
        return df
    except Exception as e:
        st.error(f"DB error: {e}")
        return pd.DataFrame()

for key, default in {
    "last_rowid":    0,
    "clean_feed":    [],
    "flagged_feed":  [],
    "total_clean":   0,
    "total_flagged": 0,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

st.sidebar.header("Settings")
threshold    = st.sidebar.slider("Flag threshold (length ≥ X bytes)", 100, 1500, 1000)
max_rows     = st.sidebar.slider("Max rows shown per feed", 10, 100, 20)
poll_interval = st.sidebar.slider("Poll interval (seconds)", 1, 10, 3)
run          = st.sidebar.checkbox("Run stream", value=True)

if st.sidebar.button("Reset feeds"):
    st.session_state.clean_feed    = []
    st.session_state.flagged_feed  = []
    st.session_state.total_clean   = 0
    st.session_state.total_flagged = 0
    #last_rowid is intentionally NOT reset so we don't re-process old rows
    st.rerun()

counter_area = st.empty()

st.markdown("---")

col_clean, col_flagged = st.columns(2)

with col_clean:
    st.subheader("✅ Clean Data")
    clean_box = st.empty()

with col_flagged:
    st.subheader("🚨 Flagged Data")
    flagged_box = st.empty()

def render_feed(records, kind):
    if not records:
        return "*No new records yet.*"
    header = "| # | Time | Src IP | Dst IP | Proto | Length |\n"
    header += "|---|------|--------|--------|-------|--------|\n"
    rows = ""
    for r in reversed(records[-max_rows:]):
        length_str = f"**{r['length']}**" if kind == "flagged" else str(r['length'])
        rows += (
            f"| {r['rowid']} | {r['ts']} | {r['src_ip']} "
            f"| {r['dst_ip']} | {r['protocol']} | {length_str} |\n"
        )
    return header + rows

def render_counters():
    total = st.session_state.total_clean + st.session_state.total_flagged
    pct   = (st.session_state.total_flagged / total * 100) if total else 0
    counter_area.markdown(
        f"**New records ingested:** `{total}` &nbsp;|&nbsp; "
        f"Clean: `{st.session_state.total_clean}` &nbsp;|&nbsp; "
        f"Flagged: `{st.session_state.total_flagged}` &nbsp;|&nbsp; "
        f"Flag rate: `{pct:.1f}%` &nbsp;|&nbsp; "
        f"Last poll: `{datetime.now().strftime('%H:%M:%S')}`"
    )

render_counters()
clean_box.markdown(render_feed(st.session_state.clean_feed, "clean"))
flagged_box.markdown(render_feed(st.session_state.flagged_feed, "flagged"))

if run:
    new_df = fetch_new(args.db, st.session_state.last_rowid)

    if not new_df.empty and 'rowid' in new_df.columns:
        # Advance the cursor — next poll will skip these rows entirely
        st.session_state.last_rowid = int(new_df['rowid'].max())

        for _, row in new_df.iterrows():
            record = {
                "rowid":    int(row.get('rowid', 0)),
                "ts":       datetime.now().strftime("%H:%M:%S"),
                "src_ip":   row.get('src_ip',   '?'),
                "dst_ip":   row.get('dst_ip',   '?'),
                "protocol": row.get('protocol', '?'),
                "length":   row.get('length',   0),
            }

            # Flag condition: packet length at or above threshold
            if record["length"] >= threshold:
                st.session_state.flagged_feed.append(record)
                st.session_state.total_flagged += 1
            else:
                st.session_state.clean_feed.append(record)
                st.session_state.total_clean += 1

        # Trim feeds to avoid unbounded memory growth
        st.session_state.clean_feed   = st.session_state.clean_feed[-200:]
        st.session_state.flagged_feed = st.session_state.flagged_feed[-200:]

        # Update UI in place
        render_counters()
        clean_box.markdown(render_feed(st.session_state.clean_feed, "clean"))
        flagged_box.markdown(render_feed(st.session_state.flagged_feed, "flagged"))

    else:
        counter_area.markdown(
            f"Waiting for new rows… `last_rowid={st.session_state.last_rowid}` "
            f"Last checked: `{datetime.now().strftime('%H:%M:%S')}`"
        )

    # Wait then trigger next poll
    time.sleep(poll_interval)
    st.rerun()

else:
    st.info("Stream paused. Check **Run stream** in the sidebar to resume.")