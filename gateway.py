import nmap

def scanReseau(target, gateway_ip):
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

            is_gateway = hotes == gateway_ip  # Check if the host's IP matches the gateway IP

            infos = {
                'ip': hotes,
                'hostname': hostname,
                'mac_address': mac_address,
                'vendor_name': vendor_name,
                'is_gateway': is_gateway
            }
            liste_hotes.append(infos)

    return liste_hotes

target = '192.168.0.0/24'
gateway_ip = '192.168.0.1'  # Replace with the actual gateway IP
hotes_internes = scanReseau(target, gateway_ip)

print('Liste des hotes :')
for device in hotes_internes:
    gateway_status = "Passerelle" if device['is_gateway'] else "Non passerelle"
    print(f'IP: {device["ip"]}, Hostname: {device["hostname"]}, MAC Address: {device["mac_address"]}, Vendor: {device["vendor_name"]}, Statut: {gateway_status}')
