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
st.markdown(
    """
<style>
    .stApp { background-color: #0e1117; color: #c9d1d9; }
    .metric-card { background-color: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #30363d; }
    div[data-testid="stMetricValue"] { color: #58a6ff; }
</style>
""",
    unsafe_allow_html=True,
)

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
        decision_counts = df["decision"].value_counts()
        fig_pie = px.pie(
            values=decision_counts.values,
            names=decision_counts.index,
            title="Traffic Analysis",
            color_discrete_map={
                "ALLOWED": "#238636",
                "BLOCKED_CAMPAIGN": "#da3633",
                "BLOCKED_OFF_TOPIC": "#da3633",
                "BLOCKED_UNSAFE": "#da3633",
            },
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="white",
        )

        # Timeline
        if "timestamp" in df.columns:
            df["time"] = pd.to_datetime(df["timestamp"], unit="s")
            if "latency_ms" in df.columns:
                fig_line = px.scatter(
                    df,
                    x="time",
                    y="latency_ms",
                    color="decision",
                    title="Latency & Events",
                )
                fig_line.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                )
            else:
                fig_line = px.scatter(
                    df, x="time", y=df.index, color="decision", title="Events Timeline"
                )
                fig_line.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                )

            c1, c2 = st.columns(2)
            c1.plotly_chart(fig_pie, use_container_width=True)
            c2.plotly_chart(fig_line, use_container_width=True)

# 3. Active Sessions (NEW: Persistence Layer Integration)
st.subheader("📊 Active Sessions (Risk Analysis)")

try:
    sessions_response = requests.get(f"{PROXY_URL}/admin/sessions", timeout=2).json()
    sessions_data = sessions_response.get("sessions", [])

    if sessions_data:
        # Process sessions data for display
        sessions_list = []
        for session in sessions_data:
            session_id = session.get("session_id", "unknown")
            data = session.get("data", {})

            # Extract risk metrics
            latent_risk_multiplier = data.get("latent_risk_multiplier", 1.0)
            max_phase_ever = data.get("max_phase_ever", 0)
            tactical_buffer_size = len(data.get("tactical_buffer", []))
            total_events = sum(data.get("tool_counts", {}).values())
            last_updated = session.get("last_updated", "N/A")

            # Calculate risk score (0.0 - 1.0)
            # Base risk from phase (0.0 - 0.8) + multiplier boost (0.0 - 0.2)
            phase_risk = min(0.8, max_phase_ever * 0.2)
            multiplier_boost = min(0.2, (latent_risk_multiplier - 1.0) * 0.1)
            risk_score = min(1.0, phase_risk + multiplier_boost)

            sessions_list.append(
                {
                    "Session ID": session_id[:16] + "..."
                    if len(session_id) > 16
                    else session_id,
                    "Risk Score": f"{risk_score:.3f}",
                    "Max Phase": max_phase_ever,
                    "Risk Multiplier": f"{latent_risk_multiplier:.2f}",
                    "Events": total_events,
                    "Buffer Size": tactical_buffer_size,
                    "Last Updated": last_updated[:19]
                    if isinstance(last_updated, str) and len(last_updated) > 19
                    else str(last_updated)[:19],
                }
            )

        if sessions_list:
            sessions_df = pd.DataFrame(sessions_list)

            # Display with color coding for risk
            def color_risk(val):
                try:
                    risk = float(val)
                    if risk >= 0.7:
                        return (
                            "background-color: #da3633; color: white"  # High risk - red
                        )
                    elif risk >= 0.4:
                        return "background-color: #bf8700; color: white"  # Medium risk - yellow
                    else:
                        return "background-color: #238636; color: white"  # Low risk - green
                except:
                    return ""

            styled_df = sessions_df.style.applymap(color_risk, subset=["Risk Score"])
            st.dataframe(styled_df, use_container_width=True, height=400)

            # Delete functionality
            st.markdown("---")
            st.subheader("🗑️ Session Management")
            selected_session_id = st.selectbox(
                "Select Session to Delete:",
                options=[s["Session ID"] for s in sessions_list],
                key="delete_session_select",
            )

            if st.button("Delete Selected Session", type="primary"):
                # Find full session_id from shortened display
                full_session_id = None
                for session in sessions_data:
                    display_id = (
                        session.get("session_id", "")[:16] + "..."
                        if len(session.get("session_id", "")) > 16
                        else session.get("session_id", "")
                    )
                    if display_id == selected_session_id:
                        full_session_id = session.get("session_id")
                        break

                if full_session_id:
                    try:
                        delete_response = requests.delete(
                            f"{PROXY_URL}/admin/sessions/{full_session_id}", timeout=2
                        )
                        if delete_response.status_code == 200:
                            result = delete_response.json()
                            if result.get("success"):
                                st.success(
                                    f"✅ Session {selected_session_id} deleted successfully!"
                                )
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error(
                                    f"❌ Failed to delete session: {result.get('error', 'Unknown error')}"
                                )
                        else:
                            st.error(
                                f"❌ HTTP {delete_response.status_code}: {delete_response.text}"
                            )
                    except Exception as e:
                        st.error(f"❌ Error deleting session: {e}")
                else:
                    st.warning("⚠️ Could not find full session ID")
        else:
            st.info("No sessions found in storage.")
    else:
        st.info("No active sessions.")

except requests.exceptions.RequestException as e:
    st.warning(f"⚠️ Could not fetch sessions: {e}")
except Exception as e:
    st.error(f"❌ Error processing sessions: {e}")

# 4. Live Log Feed
st.subheader("🔍 Live Traffic Inspector")
if logs:
    df = pd.DataFrame(logs)
    if not df.empty:
        # Färbe Block-Zeilen rot
        def highlight_block(s):
            return [
                "background-color: #3d1619"
                if "BLOCKED" in str(s.get("decision", ""))
                else ""
                for _ in s
            ]

        # Select columns that exist
        display_cols = []
        for col in ["timestamp", "session_id", "topic", "decision", "latency_ms"]:
            if col in df.columns:
                display_cols.append(col)

        if display_cols:
            st.dataframe(
                df[display_cols]
                .sort_values(
                    "timestamp" if "timestamp" in df.columns else display_cols[0],
                    ascending=False,
                )
                .style.apply(highlight_block, axis=1),
                use_container_width=True,
            )
        else:
            st.dataframe(df, use_container_width=True)
else:
    st.info("No traffic yet.")

# Auto Refresh
if auto_refresh:
    time.sleep(2)
    st.rerun()
