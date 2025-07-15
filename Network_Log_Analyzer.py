import streamlit as st
import re
import pandas as pd
from datetime import datetime, timedelta

# --- Log Parsing and Analysis Functions ---

def parse_log_line(log_line):
    """
    Parses a single log line to extract timestamp, IP address, and event type.
    This regex is designed to be somewhat flexible for common log formats.
    It looks for:
    - A timestamp (e.g., "Jul 15 15:00:00", "2025-07-15 15:00:00")
    - An IP address (IPv4)
    - Keywords like "failed", "failure", "invalid password", "authentication failure"
    """
    # Regex to capture common log patterns for failed login attempts
    # It tries to capture a date/time, then looks for keywords and an IP address.
    # This regex is a starting point and might need adjustment based on actual log formats.
    
    # Example patterns it tries to match:
    # "Jul 15 15:00:00 router auth: Failed login from 192.168.1.1"
    # "2025-07-15 15:00:00 [SSH] Authentication failure for user root from 192.168.1.1"
    
    # Updated regex to be more robust for various timestamp and message formats
    # It captures a general timestamp, then searches for keywords and an IP.
    pattern = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?|\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})' # Flexible timestamp
        r'.*?' # Non-greedy match for anything in between
        r'(?:failed|failure|invalid password|authentication failure|refused connect)' # Keywords for failed attempts
        r'.*?' # Non-greedy match for anything in between
        r'(?:from|for|on)\s+(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # IP address
        , re.IGNORECASE # Ignore case for keywords
    )
    
    match = pattern.search(log_line)
    if match:
        timestamp_str = match.group('timestamp').strip()
        ip_address = match.group('ip_address')
        
        # Attempt to parse various timestamp formats
        dt_obj = None
        for fmt in ["%b %d %H:%M:%S %Y", "%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
            try:
                # If year is missing, assume current year for parsing
                if "%Y" not in fmt and len(timestamp_str.split()) == 3:
                    current_year = datetime.now().year
                    dt_obj = datetime.strptime(f"{timestamp_str} {current_year}", fmt + " %Y")
                else:
                    dt_obj = datetime.strptime(timestamp_str, fmt)
                break
            except ValueError:
                continue
        
        if dt_obj:
            return {'timestamp': dt_obj, 'ip_address': ip_address, 'log_line': log_line.strip()}
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

    # Sort logs by timestamp to process chronologically
    parsed_logs.sort(key=lambda x: x['timestamp'])

    brute_force_attempts = []
    ip_failed_attempts = {} # Stores {ip: [(timestamp, log_line), ...]}

    for log in parsed_logs:
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
            last_flag_time = ip_failed_attempts[ip][0][0] # Timestamp of the first attempt in current window
            
            # Check if this IP was already flagged very recently to avoid spamming
            already_flagged_recently = False
            for flagged_item in brute_force_attempts:
                if flagged_item['IP Address'] == ip and (timestamp - flagged_item['Last Attempt Time']).total_seconds() < (time_window_minutes * 60 / 2): # Half the window to avoid re-flagging too fast
                    already_flagged_recently = True
                    break
            
            if not already_flagged_recently:
                brute_force_attempts.append({
                    "IP Address": ip,
                    "Failed Attempts": len(ip_failed_attempts[ip]),
                    "First Attempt Time": ip_failed_attempts[ip][0][0].strftime("%Y-%m-%d %H:%M:%S"),
                    "Last Attempt Time": ip_failed_attempts[ip][-1][0].strftime("%Y-%m-%d %H:%M:%S"),
                    "Sample Log Lines": [item[1] for item in ip_failed_attempts[ip]][:3] # Show first 3 relevant lines
                })
    return brute_force_attempts

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
        st.spinner("Analyzing logs... This might take a moment for large files.")
        
        # Read file content
        log_content = uploaded_log_file.getvalue().decode("utf-8", errors='ignore')
        log_lines = log_content.splitlines()

        parsed_logs = []
        for line in log_lines:
            parsed = parse_log_line(line)
            if parsed:
                parsed_logs.append(parsed)
        
        if not parsed_logs:
            st.warning("No relevant log entries (failed login attempts) found in the uploaded file with the current parsing rules. Please ensure your log format is compatible or try a different log file.")
        else:
            st.subheader("Analysis Results:")
            brute_force_results = analyze_brute_force(parsed_logs, time_window, max_failed_attempts)

            if brute_force_results:
                st.error(f"🚨 **Brute-Force Attempts Detected!** 🚨")
                st.write(f"Found {len(brute_force_results)} potential brute-force attack patterns.")
                
                # Convert results to DataFrame for better display
                df_results = pd.DataFrame(brute_force_results)
                # Reorder columns for better readability
                df_results = df_results[["IP Address", "Failed Attempts", "First Attempt Time", "Last Attempt Time", "Sample Log Lines"]]
                st.dataframe(df_results, use_container_width=True)
                
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

    else:
        st.warning("Please upload a log file to start the analysis.")

st.markdown("---")
st.info("This tool performs basic log analysis. For advanced security, consider dedicated SIEM solutions and professional network monitoring.")
