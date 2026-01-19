"""
Network Scanner Module
Uses ARP table for efficient device discovery across multiple networks
"""

import socket
import subprocess
import concurrent.futures
import re
import platform
from typing import Dict, List, Tuple
import ipaddress


def get_all_network_interfaces() -> List[Dict]:
    """Get all network interfaces with their IP addresses and subnets"""
    interfaces = []

    if platform.system().lower() == 'windows':
        # Use ipconfig to get all interfaces
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=10)
        output = result.stdout

        current_adapter = None
        current_ip = None
        current_mask = None

        for line in output.split('\n'):
            line = line.strip()

            # Detect adapter name
            if 'adapter' in line.lower() and ':' in line:
                # Save previous adapter if valid
                if current_adapter and current_ip and current_mask:
                    try:
                        network = ipaddress.IPv4Network(f"{current_ip}/{current_mask}", strict=False)
                        interfaces.append({
                            'name': current_adapter,
                            'ip': current_ip,
                            'netmask': current_mask,
                            'network': str(network)
                        })
                    except:
                        pass
                current_adapter = line.split(':')[0].replace('Ethernet adapter', '').replace('Wireless LAN adapter', '').strip()
                current_ip = None
                current_mask = None

            # Get IPv4 address
            if 'IPv4 Address' in line or 'IP Address' in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    if not ip.startswith('127.'):
                        current_ip = ip

            # Get subnet mask
            if 'Subnet Mask' in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    current_mask = match.group(1)

        # Don't forget last adapter
        if current_adapter and current_ip and current_mask:
            try:
                network = ipaddress.IPv4Network(f"{current_ip}/{current_mask}", strict=False)
                interfaces.append({
                    'name': current_adapter,
                    'ip': current_ip,
                    'netmask': current_mask,
                    'network': str(network)
                })
            except:
                pass
    else:
        # Linux: use ip addr
        result = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=10)
        output = result.stdout

        current_iface = None
        for line in output.split('\n'):
            # Interface line
            iface_match = re.match(r'\d+:\s+(\S+):', line)
            if iface_match:
                current_iface = iface_match.group(1)

            # IP line
            ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if ip_match and current_iface and current_iface != 'lo':
                ip = ip_match.group(1)
                prefix = ip_match.group(2)
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                    interfaces.append({
                        'name': current_iface,
                        'ip': ip,
                        'prefix': prefix,
                        'network': str(network)
                    })
                except:
                    pass

    return interfaces


def get_arp_table() -> List[Dict]:
    """Get all entries from the ARP table - these are known, reachable devices"""
    devices = []

    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=30)
            output = result.stdout

            current_interface = None
            for line in output.split('\n'):
                line = line.strip()

                # Interface header line
                if 'Interface:' in line:
                    match = re.search(r'Interface:\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        current_interface = match.group(1)

                # ARP entry line
                match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':').upper()
                    entry_type = match.group(3)

                    # Skip broadcast and multicast
                    if mac == 'FF:FF:FF:FF:FF:FF' or ip.endswith('.255'):
                        continue

                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'type': entry_type,
                        'interface_ip': current_interface
                    })
        else:
            # Linux
            result = subprocess.run(['arp', '-an'], capture_output=True, text=True, timeout=30)
            output = result.stdout

            for line in output.split('\n'):
                # Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
                match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper()

                    if mac != 'FF:FF:FF:FF:FF:FF' and mac != '<INCOMPLETE>':
                        iface_match = re.search(r'on\s+(\S+)', line)
                        iface = iface_match.group(1) if iface_match else 'unknown'

                        devices.append({
                            'ip': ip,
                            'mac': mac,
                            'type': 'dynamic',
                            'interface': iface
                        })
    except Exception as e:
        print(f"Error reading ARP table: {e}")

    return devices


def populate_arp_table(networks: List[str] = None):
    """
    Ping sweep to populate ARP table before reading it.
    This ensures we discover devices that haven't communicated recently.
    """
    if networks is None:
        interfaces = get_all_network_interfaces()
        networks = [iface['network'] for iface in interfaces]

    all_ips = []
    for network in networks:
        try:
            net = ipaddress.ip_network(network, strict=False)
            # Only do this for reasonably sized networks
            if net.num_addresses <= 1024:
                all_ips.extend([str(ip) for ip in net.hosts()])
        except:
            pass

    if not all_ips:
        return

    print(f"Populating ARP table with ping sweep ({len(all_ips)} addresses)...")

    # Fast parallel ping - we don't care about results, just populating ARP
    def quick_ping(ip):
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            timeout_val = '200' if platform.system().lower() == 'windows' else '1'
            subprocess.run(
                ['ping', param, '1', timeout_param, timeout_val, ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1
            )
        except:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(quick_ping, all_ips)


def check_ssh_port(ip: str, ports: List[int] = [22, 2222]) -> Tuple[int, str]:
    """Check if SSH is running and get banner"""
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    sock.close()
                    return port, banner
                except:
                    sock.close()
                    return port, ""
            sock.close()
        except:
            pass
    return None, None


def get_hostname(ip: str) -> str:
    """Get hostname for an IP address via reverse DNS"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return ""


def scan_device(device: Dict) -> Dict:
    """Enrich a device from ARP table with SSH info and hostname"""
    ip = device['ip']

    # Get hostname
    hostname = get_hostname(ip)

    # Check SSH
    ssh_port, ssh_banner = check_ssh_port(ip)

    return {
        'ip': ip,
        'mac': device.get('mac', 'Unknown'),
        'hostname': hostname if hostname else 'Unknown',
        'interface_ip': device.get('interface_ip', device.get('interface', '')),
        'ssh_available': ssh_port is not None,
        'ssh_port': ssh_port,
        'ssh_banner': ssh_banner,
        'status': 'online'
    }


def scan_network(do_ping_sweep: bool = True, progress_callback=None) -> Tuple[List[Dict], List[Dict]]:
    """
    Scan network using ARP table.
    Returns (devices, interfaces)
    """
    # Get network interfaces first
    interfaces = get_all_network_interfaces()
    print(f"Found {len(interfaces)} network interfaces:")
    for iface in interfaces:
        print(f"  - {iface['name']}: {iface['ip']} ({iface['network']})")

    # Optionally populate ARP table with ping sweep
    if do_ping_sweep:
        populate_arp_table()

    # Get ARP table
    arp_entries = get_arp_table()
    print(f"Found {len(arp_entries)} entries in ARP table")

    if not arp_entries:
        return [], interfaces

    devices = []
    total = len(arp_entries)

    # Sequential SSH checks and hostname lookups (one at a time to avoid connection exhaustion)
    for completed, entry in enumerate(arp_entries, 1):
        if progress_callback:
            progress_callback(completed, total)

        try:
            result = scan_device(entry)
            devices.append(result)
            ssh_status = f"SSH:{result['ssh_port']}" if result['ssh_available'] else "No SSH"
            print(f"  [{completed}/{total}] {result['ip']} - {result['hostname']} - {ssh_status}")
        except Exception as e:
            print(f"  Error scanning device: {e}")

    # Sort by IP address
    devices.sort(key=lambda x: [int(p) for p in x['ip'].split('.')])

    return devices, interfaces


if __name__ == "__main__":
    print("=" * 60)
    print("Network Scanner - ARP-based Discovery")
    print("=" * 60)

    devices, interfaces = scan_network()

    print(f"\n{'=' * 60}")
    print(f"Found {len(devices)} devices across {len(interfaces)} networks")
    print("=" * 60)

    ssh_devices = [d for d in devices if d['ssh_available']]
    print(f"\nDevices with SSH ({len(ssh_devices)}):")
    for d in ssh_devices:
        print(f"  {d['ip']:15} {d['hostname']:30} SSH:{d['ssh_port']} {d['mac']}")
