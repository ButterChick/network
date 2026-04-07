import streamlit as st
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import subprocess
import sys
import time

st.set_page_config(page_title="Network Traffic Dashboard", layout="wide")
st.title("Network Traffic Analysis Dashboard")


# ── CLI args (safe parse — ignores Streamlit's own flags) ────────────────────
def get_default_db():
    """Read --db from argv without argparse so it doesn't clash with Streamlit."""
    argv = sys.argv[1:]
    if "--db" in argv:
        idx = argv.index("--db")
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return "traffic.db"

_default_db = get_default_db()


# ── Session state init ────────────────────────────────────────────────────────
if 'capture_process' not in st.session_state:
    st.session_state.capture_process = None


# ── Sidebar: Live Capture Controls ───────────────────────────────────────────
st.sidebar.header("🎛️ Live Capture Controls")

interface  = st.sidebar.text_input("Network Interface", value="eth0",
                                    help="e.g. eth0, Wi-Fi, en0")
target_host = st.sidebar.text_input("Target Host (optional)",
                                     placeholder="e.g. google.com or 8.8.8.8")
batch_size  = st.sidebar.number_input("Batch Size", min_value=1,
                                       max_value=100, value=10)
db_name     = st.sidebar.text_input("Database Name", value=_default_db)

st.sidebar.divider()

col_start, col_stop = st.sidebar.columns(2)

with col_start:
    if st.button("▶ Start", use_container_width=True):
        proc = st.session_state.capture_process
        if proc is None or proc.poll() is not None:
            cmd = [
                sys.executable, "live_capture.py",
                "--interface", interface,
                "--db",        db_name,
                "--batch-size", str(batch_size),
            ]
            if target_host.strip():
                cmd += ["--host", target_host.strip()]

            st.session_state.capture_process = subprocess.Popen(cmd)
            st.sidebar.success(
                f"Capturing on **{interface}**"
                + (f" → `{target_host}`" if target_host.strip() else "")
            )
        else:
            st.sidebar.warning("Capture already running.")

with col_stop:
    if st.button("⏹ Stop", use_container_width=True):
        proc = st.session_state.capture_process
        if proc and proc.poll() is None:
            proc.terminate()
            st.session_state.capture_process = None
            st.cache_data.clear()
            st.sidebar.info("Capture stopped.")
        else:
            st.sidebar.warning("No active capture.")

# Status indicator
proc = st.session_state.capture_process
if proc and proc.poll() is None:
    st.sidebar.success("🟢 Capture running…")
else:
    st.sidebar.info("🔴 Capture idle")

st.sidebar.divider()
st.caption(f"📂 Using database: `{db_name}`")

# Auto-refresh while capturing
if proc and proc.poll() is None:
    st.cache_data.clear()
    time.sleep(2)
    st.rerun()


# ── Data loading ──────────────────────────────────────────────────────────────
@st.cache_data
def load_data(db_path):
    try:
        conn = sqlite3.connect(db_path)
        df   = pd.read_sql_query("SELECT * FROM packets", conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Could not load database: {e}")
        return pd.DataFrame()

df = load_data(db_name)

if df.empty:
    st.info("⏳ No packets yet — use the sidebar to start a capture, then data will appear here automatically.")
else:
    st.success(f"✅ Loaded {len(df):,} packets from `{db_name}`")
    st.dataframe(df.head(10), use_container_width=True)
    st.divider()

    # ── Row 1: Protocol | Flagged/Clean | Packet Length ──────────────────────
    col1, col2, col3 = st.columns(3)

    with col1:
        st.subheader("Protocol Distribution")
        fig, ax = plt.subplots(figsize=(5, 4))
        df['protocol'].value_counts().plot(kind='bar', ax=ax,
                                            color='steelblue', edgecolor='black')
        ax.set_xlabel("Protocol")
        ax.set_ylabel("Count")
        ax.tick_params(axis='x', rotation=45)
        plt.tight_layout()
        st.pyplot(fig)
        plt.close()

    with col2:
        st.subheader("Flagged vs Clean Packets")
        fig, ax = plt.subplots(figsize=(5, 4))
        df['flagged'].value_counts().rename({0: 'Clean', 1: 'Flagged'}).plot(
            kind='pie', ax=ax, autopct='%1.1f%%',
            colors=['steelblue', 'tomato'], startangle=90
        )
        ax.set_ylabel("")
        plt.tight_layout()
        st.pyplot(fig)
        plt.close()

    with col3:
        st.subheader("Packet Length Distribution")
        fig, ax = plt.subplots(figsize=(5, 4))
        sns.histplot(df['length'], bins=30, kde=True, color='steelblue', ax=ax)
        ax.axvline(x=1000, color='red', linestyle='--', label='Threshold (1000)')
        ax.set_xlabel("Packet Length (bytes)")
        ax.set_ylabel("Count")
        ax.legend()
        plt.tight_layout()
        st.pyplot(fig)
        plt.close()

    st.divider()

    # ── Row 2: Top Source IPs | Top Destination IPs ──────────────────────────
    col4, col5 = st.columns(2)

    with col4:
        st.subheader("Top 10 Source IPs (Packet Count)")
        fig, ax = plt.subplots(figsize=(6, 5))
        df['src_ip'].value_counts().head(10).plot(kind='barh', ax=ax,
                                                   color='steelblue', edgecolor='black')
        ax.set_xlabel("Packet Count")
        ax.set_ylabel("Source IP")
        plt.tight_layout()
        st.pyplot(fig)
        plt.close()

    with col5:
        st.subheader("Top 10 Destination IPs (Packet Count)")
        fig, ax = plt.subplots(figsize=(6, 5))
        df['dst_ip'].value_counts().head(10).plot(kind='barh', ax=ax,
                                                   color='tomato', edgecolor='black')
        ax.set_xlabel("Packet Count")
        ax.set_ylabel("Destination IP")
        plt.tight_layout()
        st.pyplot(fig)
        plt.close()

    st.divider()

    # ── Row 3: Top Source IPs by Bytes ───────────────────────────────────────
    st.subheader("Top 10 Source IPs by Total Bytes Sent")
    fig, ax = plt.subplots(figsize=(12, 5))
    df.groupby('src_ip')['length'].sum() \
      .sort_values(ascending=False).head(10) \
      .plot(kind='barh', ax=ax, color='seagreen', edgecolor='black')
    ax.set_xlabel("Total Bytes")
    ax.set_ylabel("Source IP")
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()