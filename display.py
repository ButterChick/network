import streamlit as st
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
import argparse
import sys

st.set_page_config(page_title="Network Traffic Dashboard", layout="wide")
st.title("Network Traffic Analysis Dashboard")

def get_args():
    parser = argparse.ArgumentParser(description="Network Traffic Dashboard")
    parser.add_argument('--db', default= "traffic.db", help="SQL Database Name")
    return parser.parse_args(sys.argv[1:])  # skip streamlit's own args

args = get_args()
st.caption(f"📂 Using database: `{args.db}`")

#Load Data
@st.cache_data
def load_data(db_path):
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM packets", conn)
    conn.close()
    return df

df = load_data(args.db)

st.success(f"✅ Loaded {len(df):,} packets from traffic.db")
st.dataframe(df.head(10), use_container_width=True)
st.divider()

col1, col2, col3 = st.columns(3)
# Protocol Distribution
with col1:
    st.subheader("Protocol Distribution")
    fig, ax = plt.subplots(figsize=(5, 4))
    df['protocol'].value_counts().plot(kind='bar', ax=ax, color='steelblue', edgecolor='black')
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Count")
    ax.tick_params(axis='x', rotation=45)
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()

#Flagged vs Clean Packets
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

#Packet Length Distribution
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

col4, col5 = st.columns(2)
#Top 10 Source IPs
with col4:
    st.subheader("Top 10 Source IPs (Packet Count)")
    fig, ax = plt.subplots(figsize=(6, 5))
    df['src_ip'].value_counts().head(10).plot(kind='barh', ax=ax, color='steelblue', edgecolor='black')
    ax.set_xlabel("Packet Count")
    ax.set_ylabel("Source IP")
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()

#Top 10 Destination IPs
with col5:
    st.subheader("Top 10 Destination IPs (Packet Count)")
    fig, ax = plt.subplots(figsize=(6, 5))
    df['dst_ip'].value_counts().head(10).plot(kind='barh', ax=ax, color='tomato', edgecolor='black')
    ax.set_xlabel("Packet Count")
    ax.set_ylabel("Destination IP")
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()

st.divider()

#Top 10 Source IPs by Total Bytes Sent
st.subheader("Top 10 Source IPs by Total Bytes Sent")
fig, ax = plt.subplots(figsize=(12, 5))
df.groupby('src_ip')['length'].sum().sort_values(ascending=False).head(10).plot(
    kind='barh', ax=ax, color='seagreen', edgecolor='black'
)
ax.set_xlabel("Total Bytes")
ax.set_ylabel("Source IP")
plt.tight_layout()
st.pyplot(fig)
plt.close()