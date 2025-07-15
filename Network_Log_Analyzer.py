import streamlit as st
import re
import pandas as pd
from datetime import datetime, timedelta

# --- Log Parsing and Analysis Functions ---

def parse_log_line(log_line):
    """
    Parses a single log line to extract timestamp, IP address, username, and event type (failed/successful).
    This regex is designed to be flexible for common SSH/router log formats.
    """
    # Updated regex to be more robust for various timestamp and message formats
    # It captures a general timestamp, then searches for keywords for failed or successful attempts,
    # optionally captures a username, and finally captures an IP address.
    pattern = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?|\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})' # Flexible timestamp
        r'.*?' # Non-greedy match for anything in between
        r'(?:'
            r'(?P<failed_event>failed|failure|invalid password|authentication failure|refused connect)' # Keywords for failed attempts
            r'|'
            r'(?P<success_event>accepted password|logged in|authentication success|connected)' # Keywords for successful attempts
        r')'
        r'(?: for (?P<username>\S+))?' # Optional username capture (e.g., "for user root")
        r'.*?' # Non-greedy match for anything in between
        r'(?:from|on)\s+(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # IP address
        , re.IGNORECASE # Ignore case for keywords
    )
    
    match = pattern.search(log_line)
    if match:
        timestamp_str = match.group('timestamp').strip()
        ip_address = match.group('ip_address')
        username = match.group('username') if match.group('username') else 'N/A' # Default to N/A if no username found
        
        event_type = 'unknown'
        if match.group('failed_event'):
            event_type = 'failed_login'
        elif match.group('success_event'):
            event_type = 'successful_login'
        
        dt_obj = None
        for fmt in ["%b %d %H:%M:%S %Y", "%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
            try:
                # If year is missing (e.g., "Jul 15 15:00:00"), assume current year for parsing
                if "%Y" not in fmt and len(timestamp_str.split()) == 3:
                    current_year = datetime.now().year
                    dt_obj = datetime.strptime(f"{timestamp_str} {current_year}", fmt + " %Y")
                else:
                    dt_obj = datetime.strptime(timestamp_str, fmt)
                break
            except ValueError:
                continue
        
        if dt_obj:
            return {
                'timestamp': dt_obj,
                'ip_address': ip_address,
                'username': username,
                'event_type': event_type,
                'log_line': log_line.strip()
            }
    return None

def analyze_brute_force(parsed_logs, time_window_minutes=1, max_attempts=5):
    """
    Analyzes parsed logs for brute-force attempts.
    Args:
        parsed_logs (list of dict): List of dictionaries, each from parse_log_line.
        time_window_minutes (int): Time window in minutes to consider repeated attempts.
        max_attempts (int): Maximum allowed failed attempts within the time window.
    Returns:
        list of dict: Detected brute-force attempts.
    """
    if not parsed_logs:
        return []

    # Filter for only failed login attempts for brute-force analysis
    failed_logs = [log for log in parsed_logs if log['event_type'] == 'failed_login']
    failed_logs.sort(key=lambda x: x['timestamp'])

    brute_force_attempts = []
    ip_failed_attempts = {} # Stores {ip: [(timestamp, log_line), ...]}

    for log in failed_logs: # Iterate only through failed logs
        ip = log['ip_address']
        timestamp = log['timestamp']

        if ip not in ip_failed_attempts:
            ip_failed_attempts[ip] = []
        
        # Add current attempt
        ip_failed_attempts[ip].append((timestamp, log['log_line']))

        # Filter out old attempts outside the time window
        threshold_time = timestamp - timedelta(minutes=time_window_minutes)
        ip_failed_attempts[ip] = [
            (ts, line) for ts, line in ip_failed_attempts[ip] if ts >= threshold_time
        ]

        # Check for brute-force
        if len(ip_failed_attempts[ip]) >= max_attempts:
            # Only add if this specific IP hasn't been flagged recently
            # This prevents duplicate flags for the same ongoing attack
            
            already_flagged_recently = False
            for flagged_item in brute_force_attempts:
                # Compare datetime objects directly for recency check
                if flagged_item['IP Address'] == ip and \
                   (timestamp - flagged_item['Last Attempt Time_DT']).total_seconds() < (time_window_minutes * 60 / 2): 
                    already_flagged_recently = True
                    break
            
            if not already_flagged_recently:
                brute_force_attempts.append({
                    "IP Address": ip,
                    "Failed Attempts": len(ip_failed_attempts[ip]),
                    # Store datetime objects here, format to string only for display
                    "First Attempt Time_DT": ip_failed_attempts[ip][0][0],
                    "Last Attempt Time_DT": ip_failed_attempts[ip][-1][0],
                    "Sample Log Lines": [item[1] for item in ip_failed_attempts[ip]][:3] # Show first 3 relevant lines
                })
    return brute_force_attempts

def analyze_successful_connections(parsed_logs):
    """
    Analyzes parsed logs for successful connection attempts.
    Returns:
        list of dict: Detected successful connections.
    """
    successful_connections = []
    for log in parsed_logs:
        if log['event_type'] == 'successful_login':
            successful_connections.append({
                "Timestamp": log['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
                "IP Address": log['ip_address'],
                "Username": log['username'],
                "Log Line": log['log_line']
            })
    return successful_connections

# --- Streamlit User Interface ---

st.set_page_config(page_title="Network Log Analyzer", layout="centered")
st.title("Network Log Analyzer")
st.markdown("---")

st.markdown("""
This tool helps you analyze your network logs (e.g., router logs, SSH logs) to detect potential brute-force attacks and suspicious login attempts.
**Upload your log file below, and the app will analyze it for you.**
""")

st.info("""
**How to get your logs:**
1.  **Access your router's admin panel:** Open a web browser and go to your router's IP (e.g., `192.168.1.1` or `192.168.0.1`). Log in with your router's username and password.
2.  **Find the Logs section:** Look for tabs like "Logs", "System Log", "Security Log", or "Event Log".
3.  **Copy/Download Logs:** Copy the text content or download the log file if your router offers that option. Save it as a `.txt` file.
""")

st.markdown("---")

uploaded_log_file = st.file_uploader("Upload Network Log File (.txt)", type=["txt", "log"], key="log_file_uploader")

# --- Analysis Parameters ---
st.sidebar.header("Analysis Settings")
time_window = st.sidebar.slider(
    "Time Window for Brute-Force (minutes)",
    min_value=1, max_value=60, value=5, step=1,
    help="Number of minutes within which repeated failed attempts are considered a brute-force."
)
max_failed_attempts = st.sidebar.slider(
    "Max Failed Attempts in Window",
    min_value=2, max_value=20, value=10, step=1,
    help="Minimum number of failed attempts from an IP within the time window to be flagged."
)

if st.button("Analyze Logs", type="primary"):
    if uploaded_log_file is not None:
        with st.spinner("Analyzing logs... This might take a moment for large files."):
            # Read file content
            log_content = uploaded_log_file.getvalue().decode("utf-8", errors='ignore')
            log_lines = log_content.splitlines()

            parsed_logs = []
            for line in log_lines:
                parsed = parse_log_line(line)
                if parsed:
                    parsed_logs.append(parsed)
            
            if not parsed_logs:
                st.warning("No relevant log entries (login attempts) found in the uploaded file with the current parsing rules. Please ensure your log format is compatible or try a different log file.")
            else:
                st.subheader("Analysis Results:")
                
                # Create tabs for different analysis types
                tab1, tab2 = st.tabs(["Brute-Force Attempts", "Successful Connections"])

                with tab1:
                    brute_force_results = analyze_brute_force(parsed_logs, time_window, max_failed_attempts)
                    if brute_force_results:
                        st.error(f"🚨 **Brute-Force Attempts Detected!** 🚨")
                        st.write(f"Found {len(brute_force_results)} potential brute-force attack patterns.")
                        
                        # Convert results to DataFrame for better display
                        formatted_brute_force_results = []
                        for item in brute_force_results:
                            formatted_brute_force_results.append({
                                "IP Address": item["IP Address"],
                                "Failed Attempts": item["Failed Attempts"],
                                "First Attempt Time": item["First Attempt Time_DT"].strftime("%Y-%m-%d %H:%M:%S"),
                                "Last Attempt Time": item["Last Attempt Time_DT"].strftime("%Y-%m-%d %H:%M:%S"),
                                "Sample Log Lines": "\n".join(item["Sample Log Lines"]) # Join sample lines for display
                            })

                        df_brute_force = pd.DataFrame(formatted_brute_force_results)
                        # Reorder columns for better readability
                        df_brute_force = df_brute_force[["IP Address", "Failed Attempts", "First Attempt Time", "Last Attempt Time", "Sample Log Lines"]]
                        st.dataframe(df_brute_force, use_container_width=True)
                        
                        st.markdown("""
                        ---
                        **What to do?**
                        * **Change Passwords:** Immediately change passwords for any accounts being targeted.
                        * **Block IP:** Consider blocking the detected IP addresses in your router's firewall settings.
                        * **Enable 2FA:** Activate Two-Factor Authentication (2FA) on all your accounts.
                        * **Update Firmware:** Ensure your router's firmware is up to date.
                        """)
                    else:
                        st.success("🎉 **No significant brute-force attempts detected** with the current settings. Your network seems secure from this type of attack based on the provided logs.")
                        st.info("You can adjust the 'Analysis Settings' in the sidebar to change sensitivity.")

                with tab2:
                    st.subheader("Successful Connections")
                    successful_conn_results = analyze_successful_connections(parsed_logs)
                    
                    if successful_conn_results:
                        st.success(f"✅ **{len(successful_conn_results)} Successful Connections Found.**")
                        df_successful_conn = pd.DataFrame(successful_conn_results)
                        st.dataframe(df_successful_conn, use_container_width=True)
                        st.markdown("""
                        ---
                        **Review these connections:**
                        * Ensure all successful logins are from expected users and devices.
                        * Investigate any unfamiliar IP addresses or usernames.
                        """)
                    else:
                        st.info("No successful connections found in the provided logs with the current parsing rules.")

    else:
        st.warning("Please upload a log file to start the analysis.")

st.markdown("---")
st.info("This tool performs basic log analysis. For advanced security, consider dedicated SIEM solutions and professional network monitoring.")
