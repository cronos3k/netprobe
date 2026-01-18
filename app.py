"""
NetProbe - Multi-Network Discovery Hub
Flask server providing REST API and web interface for network discovery and GPU detection
"""

from flask import Flask, render_template, jsonify, request
from scanner import scan_network, get_all_network_interfaces, get_arp_table
from ssh_client import (
    get_device_info, install_ssh_key, generate_ssh_key,
    get_public_key, has_ssh_key, SSHClient
)
import threading
import time
import json
import os

app = Flask(__name__, template_folder='templates', static_folder='static')


@app.errorhandler(Exception)
def handle_exception(e):
    """Ensure all errors return JSON instead of HTML"""
    if hasattr(e, 'code'):
        return jsonify({'error': str(e)}), e.code
    return jsonify({'error': str(e)}), 500

# File to persist credentials and device info
DATA_FILE = os.path.join(os.path.dirname(__file__), 'data.json')

# Global state
scan_state = {
    'is_scanning': False,
    'progress': 0,
    'total': 0,
    'devices': [],
    'interfaces': [],
    'last_scan': None
}

# Stored credentials (in memory, optionally persisted)
credentials = {
    'username': '',
    'password': ''
}

# Cached system info for devices
device_system_info = {}

# Per-device credentials: {ip: {username, password, use_key}}
device_credentials = {}

scan_lock = threading.Lock()


def load_data():
    """Load persisted data from file"""
    global credentials, device_system_info, device_credentials
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as f:
                data = json.load(f)
                credentials['username'] = data.get('username', '')
                credentials['password'] = data.get('password', '')
                device_system_info.update(data.get('device_info', {}))
                device_credentials.update(data.get('device_credentials', {}))
    except Exception as e:
        print(f"Error loading data: {e}")


def save_data():
    """Save credentials and device info to file"""
    try:
        data = {
            'username': credentials['username'],
            'password': credentials['password'],
            'device_info': device_system_info,
            'device_credentials': device_credentials
        }
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving data: {e}")


def get_device_creds(ip: str) -> tuple:
    """Get credentials for a device - per-device if set, else global.
    Returns (username, password, use_key)"""
    if ip in device_credentials:
        creds = device_credentials[ip]
        return (
            creds.get('username') or credentials['username'],
            creds.get('password') or credentials['password'],
            creds.get('use_key', False)
        )
    return credentials['username'], credentials['password'], False


def progress_callback(completed: int, total: int):
    """Callback for scan progress updates"""
    with scan_lock:
        scan_state['progress'] = completed
        scan_state['total'] = total


# Load persisted data on startup
load_data()


@app.route('/')
def index():
    """Serve the main web interface"""
    return render_template('index.html')


@app.route('/api/interfaces')
def get_interfaces():
    """Get all network interfaces on this server"""
    interfaces = get_all_network_interfaces()
    return jsonify({'interfaces': interfaces})


@app.route('/api/credentials', methods=['GET', 'POST'])
def handle_credentials():
    """Get or set SSH credentials"""
    if request.method == 'POST':
        data = request.get_json()
        credentials['username'] = data.get('username', '')
        credentials['password'] = data.get('password', '')
        save_data()
        return jsonify({'status': 'saved'})
    else:
        return jsonify({
            'username': credentials['username'],
            'has_password': bool(credentials['password'])
        })


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a network scan"""
    with scan_lock:
        if scan_state['is_scanning']:
            return jsonify({'error': 'Scan already in progress'}), 400
        scan_state['is_scanning'] = True
        scan_state['progress'] = 0
        scan_state['total'] = 0

    data = request.get_json() or {}
    do_ping_sweep = data.get('ping_sweep', True)

    def do_scan():
        try:
            devices, interfaces = scan_network(do_ping_sweep, progress_callback)
            with scan_lock:
                scan_state['devices'] = devices
                scan_state['interfaces'] = interfaces
                scan_state['last_scan'] = time.strftime('%Y-%m-%d %H:%M:%S')
        finally:
            with scan_lock:
                scan_state['is_scanning'] = False

    thread = threading.Thread(target=do_scan)
    thread.start()

    return jsonify({'status': 'started'})


@app.route('/api/scan/quick', methods=['POST'])
def quick_scan():
    """Quick scan - just read ARP table without ping sweep"""
    with scan_lock:
        if scan_state['is_scanning']:
            return jsonify({'error': 'Scan already in progress'}), 400
        scan_state['is_scanning'] = True

    def do_scan():
        try:
            devices, interfaces = scan_network(do_ping_sweep=False, progress_callback=progress_callback)
            with scan_lock:
                scan_state['devices'] = devices
                scan_state['interfaces'] = interfaces
                scan_state['last_scan'] = time.strftime('%Y-%m-%d %H:%M:%S')
        finally:
            with scan_lock:
                scan_state['is_scanning'] = False

    thread = threading.Thread(target=do_scan)
    thread.start()

    return jsonify({'status': 'started'})


@app.route('/api/scan/status')
def scan_status():
    """Get current scan status"""
    with scan_lock:
        return jsonify({
            'is_scanning': scan_state['is_scanning'],
            'progress': scan_state['progress'],
            'total': scan_state['total'],
            'devices': scan_state['devices'],
            'interfaces': scan_state['interfaces'],
            'last_scan': scan_state['last_scan']
        })


@app.route('/api/devices')
def get_devices():
    """Get list of discovered devices"""
    with scan_lock:
        return jsonify({
            'devices': scan_state['devices'],
            'interfaces': scan_state['interfaces'],
            'last_scan': scan_state['last_scan']
        })


@app.route('/api/devices/ssh')
def get_ssh_devices():
    """Get only devices with SSH available - for AI clients"""
    with scan_lock:
        ssh_devices = [d for d in scan_state['devices'] if d.get('ssh_available')]

        # Include cached system info if available
        for device in ssh_devices:
            ip = device['ip']
            if ip in device_system_info:
                device['system_info'] = device_system_info[ip]

        return jsonify({
            'devices': ssh_devices,
            'interfaces': scan_state['interfaces'],
            'last_scan': scan_state['last_scan'],
            'credentials_configured': bool(credentials['username'] and credentials['password'])
        })


@app.route('/api/device/<ip>/info', methods=['GET', 'POST'])
def get_device_details(ip):
    """Get detailed system info via SSH"""
    # Get per-device credentials or fall back to global
    dev_user, dev_pass, use_key = get_device_creds(ip)

    # Override with provided credentials if any
    if request.method == 'POST':
        try:
            data = request.get_json(silent=True) or {}
        except Exception:
            data = {}
        username = data.get('username') or dev_user
        password = data.get('password') or dev_pass
        port = data.get('port')
        use_key = data.get('use_key', use_key)
    else:
        username = dev_user
        password = dev_pass
        port = None

    if not username or (not password and not use_key):
        return jsonify({'error': 'No credentials provided. Set credentials first.'}), 400

    # Find the device to get SSH port
    device = None
    with scan_lock:
        for d in scan_state['devices']:
            if d['ip'] == ip:
                device = d
                break

    if not device:
        # Device not in scan results, try anyway
        device = {'ip': ip, 'ssh_port': port or 22}

    ssh_port = port or device.get('ssh_port', 22)

    try:
        info = get_device_info(ip, ssh_port, username, password, use_key)
        if info:
            # Cache the system info
            device_system_info[ip] = info
            save_data()
            return jsonify({'success': True, 'info': info})
        else:
            return jsonify({'error': 'Failed to connect via SSH. Check credentials.'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/device/<ip>/credentials', methods=['GET', 'POST', 'DELETE'])
def device_credentials_endpoint(ip):
    """Manage per-device SSH credentials"""
    if request.method == 'GET':
        if ip in device_credentials:
            creds = device_credentials[ip]
            return jsonify({
                'has_custom': True,
                'username': creds.get('username', ''),
                'has_password': bool(creds.get('password')),
                'use_key': creds.get('use_key', False)
            })
        return jsonify({
            'has_custom': False,
            'username': credentials['username'],
            'has_password': bool(credentials['password']),
            'use_key': False
        })

    elif request.method == 'POST':
        data = request.get_json() or {}
        device_credentials[ip] = {
            'username': data.get('username', ''),
            'password': data.get('password', ''),
            'use_key': data.get('use_key', False)
        }
        save_data()
        return jsonify({'status': 'saved'})

    elif request.method == 'DELETE':
        if ip in device_credentials:
            del device_credentials[ip]
            save_data()
        return jsonify({'status': 'deleted'})


@app.route('/api/ssh/key', methods=['GET', 'POST'])
def ssh_key_endpoint():
    """Manage SSH key - generate or get public key"""
    if request.method == 'GET':
        if has_ssh_key():
            return jsonify({
                'has_key': True,
                'public_key': get_public_key()
            })
        return jsonify({'has_key': False})

    elif request.method == 'POST':
        # Generate new key
        private_path, public_key = generate_ssh_key()
        return jsonify({
            'success': True,
            'public_key': public_key
        })


@app.route('/api/device/<ip>/install-key', methods=['POST'])
def install_key_on_device(ip):
    """Install SSH public key on a device for passwordless auth"""
    # Need password to install key initially
    dev_user, dev_pass, _ = get_device_creds(ip)

    data = request.get_json(silent=True) or {}
    username = data.get('username') or dev_user
    password = data.get('password') or dev_pass

    if not username or not password:
        return jsonify({'error': 'Password required to install SSH key'}), 400

    # Find SSH port
    ssh_port = 22
    with scan_lock:
        for d in scan_state['devices']:
            if d['ip'] == ip and d.get('ssh_port'):
                ssh_port = d['ssh_port']
                break

    # Generate key if not exists
    if not has_ssh_key():
        generate_ssh_key()

    # Install key on remote host
    success, message = install_ssh_key(ip, ssh_port, username, password)

    if success:
        # Mark device as using key auth
        if ip not in device_credentials:
            device_credentials[ip] = {}
        device_credentials[ip]['use_key'] = True
        device_credentials[ip]['username'] = username
        save_data()

        return jsonify({
            'success': True,
            'message': message,
            'public_key': get_public_key()
        })
    else:
        return jsonify({'error': message}), 500


@app.route('/api/device/<ip>/refresh', methods=['POST'])
def refresh_device_info(ip):
    """Refresh system info for a device using stored credentials"""
    if not credentials['username'] or not credentials['password']:
        return jsonify({'error': 'No credentials configured'}), 400

    # Find SSH port
    ssh_port = 22
    with scan_lock:
        for d in scan_state['devices']:
            if d['ip'] == ip and d.get('ssh_port'):
                ssh_port = d['ssh_port']
                break

    try:
        info = get_device_info(ip, ssh_port, credentials['username'], credentials['password'])
        if info:
            device_system_info[ip] = info
            save_data()
            return jsonify({'success': True, 'info': info})
        else:
            return jsonify({'error': 'Failed to connect'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# API for AI/CLI Clients
# ============================================================

@app.route('/api/v1/resources', methods=['GET'])
def api_get_resources():
    """
    API endpoint for AI/CLI clients to discover SSH-accessible resources.
    Returns all devices with SSH that can be logged into with stored credentials.
    """
    with scan_lock:
        ssh_devices = [d for d in scan_state['devices'] if d.get('ssh_available')]

    resources = []
    for device in ssh_devices:
        ip = device['ip']
        resource = {
            'ip': ip,
            'hostname': device.get('hostname', 'Unknown'),
            'mac': device.get('mac', 'Unknown'),
            'ssh_port': device.get('ssh_port', 22),
            'ssh_banner': device.get('ssh_banner', ''),
            'network_interface': device.get('interface_ip', ''),
        }

        # Include cached system info
        if ip in device_system_info:
            info = device_system_info[ip]
            resource['system'] = {
                'os_type': info.get('os_type', ''),
                'os_version': info.get('os_version', ''),
                'hostname': info.get('hostname', ''),
                'cpu_info': info.get('cpu_info', ''),
                'cpu_cores': info.get('cpu_cores', ''),
                'memory_total': info.get('memory_total', ''),
                'gpu_available': info.get('gpu_available', False),
                'cuda_version': info.get('cuda_version', ''),
                'gpu_info': info.get('gpu_info', [])
            }

        resources.append(resource)

    return jsonify({
        'resources': resources,
        'count': len(resources),
        'server_interfaces': scan_state.get('interfaces', []),
        'last_scan': scan_state.get('last_scan'),
        'credentials_ready': bool(credentials['username'] and credentials['password'])
    })


@app.route('/api/v1/connect', methods=['POST'])
def api_connect():
    """
    API endpoint for AI clients to get connection info for a specific resource.
    Uses stored credentials.
    """
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address required'}), 400

    ip = data['ip']

    if not credentials['username'] or not credentials['password']:
        return jsonify({'error': 'Credentials not configured on server'}), 400

    # Find device
    device = None
    with scan_lock:
        for d in scan_state['devices']:
            if d['ip'] == ip:
                device = d
                break

    if not device:
        return jsonify({'error': 'Device not found in scan results'}), 404

    if not device.get('ssh_available'):
        return jsonify({'error': 'SSH not available on this device'}), 400

    return jsonify({
        'ip': ip,
        'port': device.get('ssh_port', 22),
        'username': credentials['username'],
        'password': credentials['password'],
        'hostname': device.get('hostname', 'Unknown')
    })


@app.route('/api/v1/execute', methods=['POST'])
def api_execute_command():
    """
    API endpoint for AI clients to execute a command on a remote host.
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400

    ip = data.get('ip')
    command = data.get('command')

    if not ip or not command:
        return jsonify({'error': 'IP and command required'}), 400

    if not credentials['username'] or not credentials['password']:
        return jsonify({'error': 'Credentials not configured'}), 400

    # Find SSH port
    ssh_port = data.get('port', 22)
    with scan_lock:
        for d in scan_state['devices']:
            if d['ip'] == ip and d.get('ssh_port'):
                ssh_port = d['ssh_port']
                break

    try:
        from ssh_client import SSHClient
        client = SSHClient(ip, ssh_port, credentials['username'], credentials['password'])
        if client.connect():
            output = client.execute(command)
            client.disconnect()
            return jsonify({
                'success': True,
                'output': output,
                'host': ip
            })
        else:
            return jsonify({'error': 'SSH connection failed'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("=" * 60)
    print("NetProbe - Multi-Network Discovery Hub")
    print("=" * 60)

    interfaces = get_all_network_interfaces()
    print(f"\nServer Network Interfaces ({len(interfaces)}):")
    for iface in interfaces:
        print(f"  - {iface['name']}: {iface['ip']} ({iface['network']})")

    print("\nStarting web server on http://0.0.0.0:5000")
    print("API endpoint for AI clients: http://<server-ip>:5000/api/v1/resources")
    print("=" * 60)

    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
