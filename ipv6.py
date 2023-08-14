import nmap
import ping3
import socket

def generate_report(scan_results):
    report = "Scan Report:\n\n"
    
    for host_info in scan_results:
        report += f"IP: {host_info['ip']}\n"
        report += f"Hostname: {host_info['hostname']}\n"
        report += f"MAC Address: {host_info['mac_address']}\n"
        report += f"Vendor: {host_info['vendor_name']}\n"
        report += f"Gateway: {'Oui' if host_info['is_gateway'] else 'Non'}\n"
        report += f"Pingable: {'Oui' if host_info['is_pingable'] else 'Non'}\n"
        report += f"IPv6: {'Oui' if host_info['has_ipv6'] else 'Non'}\n"  # Added this line

        report += "\n"

    return report

def is_pingable(ip):
    response_time = ping3.ping(ip)
    return response_time is not None

def has_ipv6(ip):
    try:
        addr_info = socket.getaddrinfo(ip, None)
        for _, _, _, _, address in addr_info:
            if ':' in address[0]:  # IPv6 address
                return True
        return False
    except socket.gaierror:
        return False

def scanReseau(target, gateway_ip):
    print('===============BEGIN OF SCAN ==================')
    scanMe = nmap.PortScanner()
    
    scanMe.scan(hosts=target, arguments="-sS -O -F")

    liste_hotes = []
    
    for hotes in scanMe.all_hosts():
        print("scanning host", hotes)

        if scanMe[hotes]['status']['state'] == 'up':
            hostname = scanMe[hotes]['hostnames'][0] if 'hostnames' in scanMe[hotes] else 'N/A'

            mac_address = ''
            vendor_name = 'N/A'
            if 'addresses' in scanMe[hotes] and 'mac' in scanMe[hotes]['addresses']:
                mac_address = scanMe[hotes]['addresses']['mac']
                if 'vendor' in scanMe[hotes] and mac_address in scanMe[hotes]['vendor']:
                    vendor_name = scanMe[hotes]['vendor'][mac_address]
            is_gateway = hotes == gateway_ip
            is_pingable_host = is_pingable(hotes)
            has_ipv6_address = has_ipv6(hotes)  # Check if host has an IPv6 address
            infos = {
                'ip': hotes,
                'hostname': hostname,
                'mac_address': mac_address,
                'vendor_name': vendor_name,
                'is_gateway': is_gateway,
                'is_pingable': is_pingable_host,
                'has_ipv6': has_ipv6_address
            }
            liste_hotes.append(infos)

    return liste_hotes

target = '192.168.0.0/24'
gateway_ip = '192.168.0.1'
hotes_internes = scanReseau(target, gateway_ip)

report = generate_report(hotes_internes)

# Write the report to a file
with open('scan_report.csv', 'w') as report_file:
    report_file.write(report)

print("Scan report generated.")
