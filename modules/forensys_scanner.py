import winreg
import os
import subprocess
import pandas as pd

def check_signature(file_path):
    """Uses PowerShell to check if a file has a valid digital signature."""
    if not os.path.exists(file_path):
        return "File Not Found"
    
    # PowerShell command to check Authenticode Signature
    cmd = f'Get-AuthenticodeSignature "{file_path}" | Select-Object -ExpandProperty Status'
    try:
        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
        status = result.stdout.strip()
        return status if status else "Unsigned/Unknown"
    except Exception:
        return "Error Checking"

def get_risk_level(name, path, signature):
    """Logic to automatically flag entries as High, Medium, or Low risk."""
    path_lower = path.lower()
    
    # 1. High Risk: Running from Temp or AppData + Unsigned
    if ("temp" in path_lower or "appdata" in path_lower) and signature != "Valid":
        return "HIGH (Suspicious Path + Unsigned)"
    
    # 2. High Risk: Using System Tools for persistence (LOLBins)
    if "powershell.exe" in path_lower or "cmd.exe" in path_lower or "wscript.exe" in path_lower:
        return "HIGH (Scripting Tool used for Persistence)"
    
    # 3. Medium Risk: Unsigned but in a normal location
    if signature != "Valid" and "program files" not in path_lower:
        return "MEDIUM (Unsigned & Outside Program Files)"
    
    return "LOW (Likely Legitimate)"

def run_scanner():
    print("[!] ForenSys: Running Advanced Risk Scanner...")
    
    targets = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "User Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "System Run")
    ]
    
    findings = []
    
    for hive, reg_path, loc_name in targets:
        try:
            key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, val, _ = winreg.EnumValue(key, i)
                
                # Clean the path (remove arguments like /silent or -auto)
                clean_path = val.split(' -')[0].split(' /')[0].replace('"', '').strip()
                
                sig = check_signature(clean_path)
                risk = get_risk_level(name, clean_path, sig)
                
                findings.append({
                    "Registry": loc_name,
                    "Entry Name": name,
                    "File Path": clean_path,
                    "Signature": sig,
                    "Risk Level": risk
                })
            winreg.CloseKey(key)
        except Exception as e:
            print(f"[-] Error accessing {loc_name}: {e}")

    # Output to Terminal and CSV
    df = pd.DataFrame(findings)
    print("\n", df[["Entry Name", "Signature", "Risk Level"]])
    df.to_csv("ForenSys_Risk_Report.csv", index=False)
    print("\n[+] Full report saved to: ForenSys_Risk_Report.csv")

if __name__ == "__main__":
    run_scanner()