import streamlit as st
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys

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

df = load_data(_default_db)

if df.empty:
    st.info("No packets yet — use the sidebar to start a capture, then data will appear here automatically.")
else:
    st.success(f"Loaded {len(df):,} packets from `{_default_db}`")
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