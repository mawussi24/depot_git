import nmap
import csv

def scanReseau(target):
    print('===============BEGIN OF SCAN ==================')
    scanMe = nmap.PortScanner()
    scanMe.scan(hosts=target, arguments="-sn")

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

            infos = {
                'ip': hotes,
                'hostname': hostname,
                'mac_address': mac_address,
                'vendor_name': vendor_name
            }
            liste_hotes.append(infos)

    return liste_hotes

target = '192.168.0.0/24'
hotes_internes = scanReseau(target)

csv_filename = 'scan_report.csv'

# Write the data to CSV
with open(csv_filename, 'w', newline='') as csvfile:
    fieldnames = ['IP', 'Hostname', 'MAC Address', 'Vendor']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for device in hotes_internes:
        writer.writerow({
            'IP': device["ip"],
            'Hostname': device["hostname"],
            'MAC Address': device["mac_address"],
            'Vendor': device["vendor_name"]
        })

print(f'Results saved to {csv_filename}')
