import os
import sqlite3
import shutil
import pandas as pd

def get_chrome_downloads():
    # Path to Chrome's History file (which also stores downloads)
    user_home = os.path.expanduser('~')
    history_db = os.path.join(user_home, r'AppData\Local\Google\Chrome\User Data\Default\History')
    
    # Forensic Copy (to avoid locking issues)
    temp_db = "temp_chrome_history"
    if os.path.exists(history_db):
        shutil.copy2(history_db, temp_db)
    else:
        print("[-] Chrome History not found. Is Chrome installed in the default path?")
        return

    # Connect to the copy
    conn = sqlite3.connect(temp_db)
    
    # This SQL query pulls the filename, the source URL, and the Referrer (where you were before clicking download)
    query = """
    SELECT target_path, tab_url, referrer, total_bytes, 
    datetime(start_time / 1000000 + (strftime('%s', '1601-01-01')), 'unixepoch') as download_time
    FROM downloads
    ORDER BY start_time DESC
    """
    
    print("[!] Analyzing Chrome Downloads for Patient Zero...")
    df = pd.read_sql_query(query, conn)
    conn.close()
    os.remove(temp_db) # Clean up
    
    # Show the most recent 5 downloads
    print(df.head(5))
    
    # Save to a CSV for your report
    df.to_csv("Download_Analysis_Report.csv", index=False)
    print("\n[+] Success! Report saved as Download_Analysis_Report.csv")

if __name__ == "__main__":
    get_chrome_downloads()