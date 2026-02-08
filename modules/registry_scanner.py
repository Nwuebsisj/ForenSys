import winreg
import pandas as pd

def scan_registry_location(hive, path, location_name):
    """Scans a specific registry path for auto-start entries."""
    results = []
    try:
        # Open the key with Read-only access
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        
        # Count how many values are inside
        num_values = winreg.QueryInfoKey(key)[1]
        
        for i in range(num_values):
            name, value, _ = winreg.EnumValue(key, i)
            results.append({
                "Location": location_name,
                "Program Name": name,
                "File Path": value
            })
        winreg.CloseKey(key)
    except FileNotFoundError:
        # Some keys might not exist (like RunOnce if it's empty)
        pass
    except Exception as e:
        print(f"[-] Error scanning {location_name}: {e}")
        
    return results

def run_forensys_registry():
    print("[!] ForenSys: Starting Registry Persistence Scan...")
    
    # Define the 'Hot Zones' for malware
    targets = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "User Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "User RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "System Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "System RunOnce"),
    ]
    
    all_findings = []
    for hive, path, name in targets:
        all_findings.extend(scan_registry_location(hive, path, name))
    
    # Display results
    if all_findings:
        df = pd.DataFrame(all_findings)
        print("\n--- Found Auto-Start Entries ---")
        print(df.to_string(index=False))
        
        # Save to CSV for the final report
        df.to_csv("Registry_Persistence_Report.csv", index=False)
        print("\n[+] Report saved to Registry_Persistence_Report.csv")
    else:
        print("[+] No suspicious auto-start entries found in common keys.")

if __name__ == "__main__":
    run_forensys_registry()