import nmap
import ping3

def generate_report(scan_results):
    report = "Scan Report:\n\n"
    
    for host_info in scan_results:
        report += f"IP: {host_info['ip']}\n"
        report += f"Hostname: {host_info['hostname']}\n"
        report += f"MAC Address: {host_info['mac_address']}\n"
        report += f"Vendor: {host_info['vendor_name']}\n"
        report += f"Gateway: {'Oui' if host_info['is_gateway'] else 'Non'}\n"
        report += f"Pingable: {'Oui' if host_info['is_pingable'] else 'Non'}\n"

        report += "\n"

    return report

def is_pingable(ip):
    response_time = ping3.ping(ip)
    return response_time is not None

def scanReseau(target, gateway_ip):
    print('===============BEGIN OF SCAN ==================')
    scanMe = nmap.PortScanner()
    
    scanMe.scan(hosts=target, arguments="-sS -O -F")

    liste_hotes = []
    
    for hotes in scanMe.all_hosts():
        print("scanning host", hotes)

        if scanMe[hotes]['status']['state'] == 'up':
            hostname = scanMe[hotes]['hostnames'][0]['name'] if 'hostnames' in scanMe[hotes] else 'N/A'

            mac_address = ''
            vendor_name = 'N/A'
            if 'addresses' in scanMe[hotes] and 'mac' in scanMe[hotes]['addresses']:
                mac_address = scanMe[hotes]['addresses']['mac']
                if 'vendor' in scanMe[hotes] and mac_address in scanMe[hotes]['vendor']:
                    vendor_name = scanMe[hotes]['vendor'][mac_address]
            is_gateway = hotes == gateway_ip
            is_pingable_host = is_pingable(hotes)
            infos = {
                'ip': hotes,
                'hostname': hostname,
                'mac_address': mac_address,
                'vendor_name': vendor_name,
                'is_gateway': is_gateway,
                'is_pingable': is_pingable_host
            }
            liste_hotes.append(infos)

    return liste_hotes

target = '192.168.0.0/24'
gateway_ip = '192.168.0.1'
hote_interne = scanReseau(target, gateway_ip)

report = generate_report(hote_interne)

# Write the report to a file
with open('scan_report.csv', 'w') as report_file:
    report_file.write(report)

print("Scan report generated.")
