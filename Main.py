from scapy.all import ARP, Ether, srp

def scan_network(target_ip, target_mac):
    arp_request = ARP(pdst=target_ip)
    ether = Ether(dst=target_mac)
    packet = ether / arp_request

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

if __name__ == "__main__":
    target_ip = "192.168.1.1/24" 
    target_mac = "ff:ff:ff:ff:ff:ff" 

    devices = scan_network(target_ip, target_mac)

    print("Appareils trouvés sur le réseau :")
    for device in devices:
        print(f"IP : {device['ip']}, MAC : {device['mac']}")
