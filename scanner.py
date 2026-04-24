import nmap
import csv
import datetime

# =====================================================
# Automated Network Vulnerability Assessment Tool
# Final Year Cybersecurity Project
# =====================================================

print("="*60)
print(" Automated Network Vulnerability Assessment Tool ")
print("="*60)

# Nmap Path
nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"

# Initialize Scanner
scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))

# Target Input
target = input("Enter target IP: ")

# Advanced Scan
# -sV = service version detection
# -O  = OS detection
scanner.scan(target, '1-1000', arguments='-sV -O')

print("\nScan Results\n")

results = []

# -----------------------------------------------------
# SCAN LOGIC
# -----------------------------------------------------

for host in scanner.all_hosts():

    # OS Detection
    if 'osmatch' in scanner[host] and len(scanner[host]['osmatch']) > 0:
        print("Possible OS:", scanner[host]['osmatch'][0]['name'])

    for proto in scanner[host].all_protocols():

        for port in scanner[host][proto]:

            service = scanner[host][proto][port]['name']

            # -----------------------------------------
            # Risk Classification + Severity Scoring
            # -----------------------------------------

            if port in [21,23]:
                risk="High"
                score=8.5

            elif port in [22,80,445,3389]:
                risk="Medium"
                score=5.5

            else:
                risk="Low"
                score=2.0


            # -----------------------------------------
            # Vulnerability Alerts + Recommendations
            # -----------------------------------------

            if port == 445:
                print("Potential SMB Exposure Detected")
                print("Recommendation: Disable SMBv1 and restrict port 445")

            if port == 21:
                print("FTP may allow insecure access")
                print("Recommendation: Replace FTP with SFTP")

            if port == 23:
                print("Telnet is insecure")
                print("Recommendation: Disable Telnet, use SSH")

            if port == 3389:
                print("RDP Exposure Detected")
                print("Recommendation: Restrict RDP or use VPN")

            if port == 22:
                print("SSH Open - Check weak credentials")
                print("Recommendation: Enforce key authentication")


            # -----------------------------------------
            # Output Findings
            # -----------------------------------------

            print(
                "Port:", port,
                "Service:", service,
                "Risk:", risk,
                "Score:", score
            )

            results.append(
                [port,service,risk,score]
            )


# -----------------------------------------------------
# CSV REPORT EXPORT
# -----------------------------------------------------

with open("scan_report.csv","w",newline="") as file:

    writer=csv.writer(file)

    writer.writerow(
        ["Scan Time",datetime.datetime.now()]
    )

    writer.writerow([])

    writer.writerow(
        ["Port","Service","Risk","Severity Score"]
    )

    writer.writerows(results)


# -----------------------------------------------------
# SUMMARY
# -----------------------------------------------------

print("\nScan Summary")
print("Open Ports Found:",len(results))
print("Scan Time:",datetime.datetime.now())

print("\nReport saved as scan_report.csv")