# process_dump.py
# Simple DFIR Process Dumping Tool
# Requires: psutil (pip install psutil)

import psutil
import csv
from datetime import datetime

def collect_processes():
    process_list = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'create_time']):
        try:
            process_info = proc.info
            process_list.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return process_list

def save_report(process_list):
    report_name = f"process_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(report_name, 'w', newline='') as csvfile:
        fieldnames = ['pid', 'name', 'username', 'memory_rss', 'create_time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for proc in process_list:
            writer.writerow({
                'pid': proc['pid'],
                'name': proc['name'],
                'username': proc['username'],
                'memory_rss': proc['memory_info'].rss,
                'create_time': datetime.fromtimestamp(proc['create_time']).strftime('%Y-%m-%d %H:%M:%S')
            })
    print(f"[+] Report saved as {report_name}")
    return report_name

def check_anomalies(process_list):
    print("\n[!] Checking for suspicious processes...\n")
    for proc in process_list:
        if proc['username'] == 'SYSTEM' and proc['name'] not in ['svchost.exe', 'explorer.exe']:
            print(f"[!] Suspicious process: {proc['name']} (PID: {proc['pid']})")

def main():
    print("[*] Collecting process information...")
    processes = collect_processes()
    save_report(processes)
    check_anomalies(processes)
    print("\n[*] Process dump completed.")

if __name__ == "__main__":
    main()
