import streamlit as st
from azure.storage.blob import BlobServiceClient
import pandas as pd
from datetime import datetime, time, timedelta
import requests
import json
import re

# Streamlit configuration
st.set_page_config(page_title="Azure WAF Log Analyzer", layout="wide")
st.title("🔍 Azure FrontDoor WAF Log Analyzer")

# Initialize session state
if 'log_df' not in st.session_state:
    st.session_state.log_df = None
    st.session_state.raw_logs = None
    st.session_state.waf_insights = None

# ----------------------------
# 1. Azure Connection
# ----------------------------
with st.expander("🔐 Step 1: Connect to Azure Storage"):
    connection_string = st.text_input(
        "Azure Connection String", 
        type="password",
        help="Format: DefaultEndpointsProtocol=https;AccountName=xxx;AccountKey=xxx"
    )
    
    if st.button("Connect"):
        if not connection_string:
            st.error("Please enter a connection string")
        else:
            try:
                st.session_state.blob_client = BlobServiceClient.from_connection_string(connection_string)
                st.success("✅ Connected to Azure Blob Storage!")
            except Exception as e:
                st.error(f"Connection failed: {str(e)}")

# ----------------------------
# 2. WAF-Specific Processing Functions
# ----------------------------
def extract_waf_log_data(log_entry):
    """Specialized parser for FrontDoor WAF logs"""
    properties = log_entry.get('properties', {})
    details = properties.get('details', {})
    
    # Extract matches if they exist
    matches = details.get('matches', [])
    match_details = "\n".join([
        f"{m.get('matchVariableName')}: {m.get('matchVariableValue')}" 
        for m in matches
    ]) if matches else "None"
    
    return {
        'Timestamp': log_entry.get('time', datetime.now()),
        'Client IP': properties.get('clientIP', 'N/A'),
        'Socket IP': properties.get('socketIP', 'N/A'),
        'Host': properties.get('host', 'N/A'),
        'Request URI': properties.get('requestUri', 'N/A'),
        'Rule Name': properties.get('ruleName', 'N/A'),
        'Action': properties.get('action', 'N/A'),
        'Policy Mode': properties.get('policyMode', 'N/A'),
        'Message': details.get('msg', 'N/A'),
        'Matches': match_details,
        'Tracking Reference': properties.get('trackingReference', 'N/A')
    }

def analyze_waf_logs(df):
    """Generate security insights from WAF logs"""
    insights = {
        "top_blocked_rules": [],
        "common_attack_patterns": [],
        "suspicious_ips": []
    }
    
    if df is None or df.empty:
        return insights
    
    # Top blocked rules
    blocked = df[df['Action'] == 'Block']
    if not blocked.empty:
        insights['top_blocked_rules'] = blocked['Rule Name'].value_counts().head(5).to_dict()
    
    # Common attack patterns
    xss_attempts = df[df['Message'].str.contains('XSS', case=False, na=False)]
    sql_attempts = df[df['Message'].str.contains('SQL', case=False, na=False)]
    
    if not xss_attempts.empty:
        insights['common_attack_patterns'].append({
            "type": "XSS",
            "count": len(xss_attempts),
            "example_uri": xss_attempts.iloc[0]['Request URI']
        })
    
    if not sql_attempts.empty:
        insights['common_attack_patterns'].append({
            "type": "SQLi",
            "count": len(sql_attempts),
            "example_uri": sql_attempts.iloc[0]['Request URI']
        })
    
    # Suspicious IPs
    ip_stats = df['Client IP'].value_counts().head(5).to_dict()
    insights['suspicious_ips'] = [
        {"ip": ip, "count": count, "actions": df[df['Client IP'] == ip]['Action'].value_counts().to_dict()}
        for ip, count in ip_stats.items()
    ]
    
    return insights

# ----------------------------
# 3. Fetch and Parse WAF Logs
# ----------------------------
if hasattr(st.session_state, 'blob_client'):
    with st.expander("📂 Step 2: Fetch and Parse WAF Logs"):
        containers = [c.name for c in st.session_state.blob_client.list_containers()]
        selected_container = st.selectbox("Select Container", containers)
        
        # Date range selection
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start date", value=datetime.now() - timedelta(days=1))
            start_time = st.time_input("Start time", value=time(0, 0))
        with col2:
            end_date = st.date_input("End date", value=datetime.now())
            end_time = st.time_input("End time", value=time(23, 59))
        
        start_datetime = datetime.combine(start_date, start_time)
        end_datetime = datetime.combine(end_date, end_time)
        
        if st.button("Fetch WAF Logs"):
            with st.spinner("Processing WAF logs..."):
                try:
                    container_client = st.session_state.blob_client.get_container_client(selected_container)
                    blobs = list(container_client.list_blobs())
                    
                    all_logs = []
                    for blob in blobs:
                        if not blob.name.lower().endswith('.json'):
                            continue
                            
                        blob_time = blob.last_modified.replace(tzinfo=None)
                        if start_datetime <= blob_time <= end_datetime:
                            content = container_client.get_blob_client(blob.name).download_blob().readall()
                            
                            try:
                                if content.strip().startswith(b'['):
                                    logs = json.loads(content)
                                else:
                                    logs = [json.loads(line) for line in content.splitlines() if line.strip()]
                                
                                for log in logs:
                                    try:
                                        log_data = extract_waf_log_data(log)
                                        log_data['Source File'] = blob.name
                                        all_logs.append(log_data)
                                    except Exception as e:
                                        st.warning(f"Skipped malformed log entry in {blob.name}: {str(e)}")
                                        
                            except json.JSONDecodeError:
                                st.warning(f"Skipped non-JSON file: {blob.name}")
                    
                    if all_logs:
                        df = pd.DataFrame(all_logs)
                        
                        # Proper timezone handling
                        start_datetime_utc = pd.to_datetime(start_datetime).tz_localize('UTC')
                        end_datetime_utc = pd.to_datetime(end_datetime).tz_localize('UTC')
                        df['Timestamp'] = pd.to_datetime(df['Timestamp']).dt.tz_convert('UTC')
                        
                        # Apply time filter
                        time_filtered = df[
                            (df['Timestamp'] >= start_datetime_utc) & 
                            (df['Timestamp'] <= end_datetime_utc)
                        ]
                        
                        st.session_state.raw_logs = df
                        st.session_state.log_df = time_filtered
                        st.session_state.waf_insights = analyze_waf_logs(time_filtered)
                        st.success(f"✅ Processed {len(time_filtered)} WAF log entries!")
                    else:
                        st.warning("No valid WAF log entries found in selected time range")
                        
                except Exception as e:
                    st.error(f"Error processing logs: {str(e)}")

# ----------------------------
# 4. Display WAF-Specific Results
# ----------------------------
if st.session_state.log_df is not None:
    with st.expander("📊 WAF Log Results", expanded=True):
        st.caption(f"Showing WAF logs between {start_datetime} and {end_datetime}")
        
        # WAF-specific filters
        col1, col2, col3 = st.columns(3)
        with col1:
            action_filter = st.multiselect(
                "Filter by Action",
                options=sorted(st.session_state.log_df['Action'].unique()),
                default=['Block', 'Log']
            )
        with col2:
            rule_filter = st.multiselect(
                "Filter by Rule",
                options=sorted(st.session_state.log_df['Rule Name'].unique()),
                default=[]
            )
        with col3:
            host_filter = st.multiselect(
                "Filter by Host",
                options=sorted(st.session_state.log_df['Host'].unique()),
                default=[]
            )
        
        # Apply filters
        filtered_df = st.session_state.log_df.copy()
        if action_filter:
            filtered_df = filtered_df[filtered_df['Action'].isin(action_filter)]
        if rule_filter:
            filtered_df = filtered_df[filtered_df['Rule Name'].isin(rule_filter)]
        if host_filter:
            filtered_df = filtered_df[filtered_df['Host'].isin(host_filter)]
        
        # Show data with WAF-specific columns
        st.dataframe(
            filtered_df,
            column_config={
                "Timestamp": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
                "Matches": st.column_config.TextColumn(width="large")
            },
            hide_index=True,
            use_container_width=True,
            height=500
        )
        
        st.download_button(
            "💾 Download WAF Logs (CSV)",
            data=filtered_df.to_csv(index=False).encode('utf-8'),
            file_name="waf_logs.csv"
        )

# ----------------------------
# 5. WAF Security Dashboard
# ----------------------------
if st.session_state.get('waf_insights'):
    with st.expander("🛡️ WAF Security Dashboard"):
        st.subheader("Security Insights")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Total Log Entries", len(st.session_state.log_df))
            st.metric("Blocked Requests", 
                     len(st.session_state.log_df[st.session_state.log_df['Action'] == 'Block']))
            
            st.write("### Top Blocked Rules")
            for rule, count in st.session_state.waf_insights['top_blocked_rules'].items():
                st.write(f"- **{rule}**: {count} blocks")
        
        with col2:
            st.metric("Logged Requests", 
                     len(st.session_state.log_df[st.session_state.log_df['Action'] == 'Log']))
            st.metric("Allowed Requests", 
                     len(st.session_state.log_df[st.session_state.log_df['Action'] == 'Allow']))
            
            st.write("### Common Attack Patterns")
            if st.session_state.waf_insights['common_attack_patterns']:
                for pattern in st.session_state.waf_insights['common_attack_patterns']:
                    st.write(f"- **{pattern['type']}**: {pattern['count']} attempts")
                    st.caption(f"Example: {pattern['example_uri']}")
            else:
                st.write("No common attack patterns detected")
        
        st.write("### Suspicious IP Activity")
        suspicious_df = pd.DataFrame(st.session_state.waf_insights['suspicious_ips'])
        if not suspicious_df.empty:
            st.dataframe(
                suspicious_df,
                column_config={
                    "ip": "IP Address",
                    "count": "Request Count",
                    "actions": st.column_config.BarChartColumn(
                        "Actions", 
                        y_min=0,
                        width="medium"
                    )
                },
                hide_index=True
            )
        else:
            st.write("No suspicious IPs detected")

# Reset button
if st.session_state.log_df is not None:
    if st.button("Clear Results"):
        st.session_state.log_df = None
        st.session_state.raw_logs = None
        st.session_state.waf_insights = None
        st.rerun()