"""
TASK: Admin Dashboard for HAK/GAL Firewall
FILE: tools/admin_dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import requests
import time

# Config
PROXY_URL = "http://localhost:8081"
st.set_page_config(page_title="HAK/GAL Guardian", page_icon="🛡️", layout="wide")

# Custom CSS for Cyberpunk Look
st.markdown("""
<style>
    .stApp { background-color: #0e1117; color: #c9d1d9; }
    .metric-card { background-color: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #30363d; }
    div[data-testid="stMetricValue"] { color: #58a6ff; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ HAK/GAL Firewall Monitor")

# Sidebar
with st.sidebar:
    st.header("System Status")
    try:
        health = requests.get(f"{PROXY_URL}/health", timeout=1).json()
        st.success(f"🟢 ONLINE (v{health.get('version', '1.0')})")
    except:
        st.error("🔴 OFFLINE")
        st.stop()
    
    auto_refresh = st.checkbox("Auto-Refresh (2s)", value=True)
    if st.button("Clear Logs"):
        # Optional: Endpoint zum Löschen implementieren oder ignorieren
        pass

# Main Data Fetch
try:
    stats = requests.get(f"{PROXY_URL}/admin/stats").json()
    logs = requests.get(f"{PROXY_URL}/admin/logs").json()
except Exception as e:
    st.error(f"Connection Error: {e}")
    st.stop()

# 1. Top KPIs
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Requests", stats.get("total_requests", 0))
col2.metric("Blocked Attacks", stats.get("blocked_requests", 0), delta_color="inverse")
col3.metric("Active Sessions", stats.get("active_sessions", 0))
uptime_seconds = stats.get("uptime", 0)
uptime_minutes = uptime_seconds / 60
col4.metric("Uptime", f"{uptime_minutes:.1f} min")

# 2. Analytics Charts
if logs:
    df = pd.DataFrame(logs)
    if not df.empty:
        # Pie Chart: Decisions
        # Normalize decision values for pie chart
        decision_counts = df['decision'].value_counts()
        fig_pie = px.pie(
            values=decision_counts.values,
            names=decision_counts.index,
            title='Traffic Analysis',
            color_discrete_map={'ALLOWED': '#238636', 'BLOCKED_CAMPAIGN': '#da3633', 'BLOCKED_OFF_TOPIC': '#da3633', 'BLOCKED_UNSAFE': '#da3633'}
        )
        fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
        
        # Timeline
        if 'timestamp' in df.columns:
            df['time'] = pd.to_datetime(df['timestamp'], unit='s')
            if 'latency_ms' in df.columns:
                fig_line = px.scatter(df, x='time', y='latency_ms', color='decision', title='Latency & Events')
                fig_line.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
            else:
                fig_line = px.scatter(df, x='time', y=df.index, color='decision', title='Events Timeline')
                fig_line.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')

            c1, c2 = st.columns(2)
            c1.plotly_chart(fig_pie, use_container_width=True)
            c2.plotly_chart(fig_line, use_container_width=True)

# 3. Live Log Feed
st.subheader("🔍 Live Traffic Inspector")
if logs:
    df = pd.DataFrame(logs)
    if not df.empty:
        # Färbe Block-Zeilen rot
        def highlight_block(s):
            return ['background-color: #3d1619' if 'BLOCKED' in str(s.get('decision', '')) else '' for _ in s]
        
        # Select columns that exist
        display_cols = []
        for col in ['timestamp', 'session_id', 'topic', 'decision', 'latency_ms']:
            if col in df.columns:
                display_cols.append(col)
        
        if display_cols:
            st.dataframe(
                df[display_cols]
                .sort_values('timestamp' if 'timestamp' in df.columns else display_cols[0], ascending=False)
                .style.apply(highlight_block, axis=1),
                use_container_width=True
            )
        else:
            st.dataframe(df, use_container_width=True)
else:
    st.info("No traffic yet.")

# Auto Refresh
if auto_refresh:
    time.sleep(2)
    st.rerun()
