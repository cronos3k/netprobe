"""
SSH Client Module
Connects to devices via SSH and retrieves system information
"""

import paramiko
from typing import Dict, Optional
import re


class SSHClient:
    def __init__(self, host: str, port: int = 22, username: str = "", password: str = ""):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = None
        self.os_type = None

    def connect(self) -> bool:
        """Establish SSH connection"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            # Detect OS type
            self._detect_os()
            return True
        except Exception as e:
            print(f"SSH connection failed to {self.host}: {e}")
            return False

    def _detect_os(self):
        """Detect if the remote system is Linux or Windows"""
        try:
            _, stdout, _ = self.client.exec_command("uname -s", timeout=5)
            result = stdout.read().decode().strip()
            if result:
                self.os_type = "linux"
            else:
                self.os_type = "windows"
        except:
            self.os_type = "unknown"

    def execute(self, command: str) -> str:
        """Execute a command and return output"""
        if not self.client:
            return ""
        try:
            _, stdout, stderr = self.client.exec_command(command, timeout=30)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            return output if output else error
        except Exception as e:
            return f"Error: {e}"

    def get_system_info(self) -> Dict:
        """Gather comprehensive system information"""
        info = {
            'host': self.host,
            'os_type': self.os_type,
            'hostname': '',
            'os_version': '',
            'kernel': '',
            'uptime': '',
            'cpu_info': '',
            'cpu_cores': '',
            'cpu_usage': '',
            'memory_total': '',
            'memory_used': '',
            'memory_free': '',
            'memory_percent': '',
            'disk_info': [],
            'network_interfaces': [],
            'logged_users': '',
            'processes': '',
            'load_average': '',
            'services': [],
            'gpu_available': False,
            'gpu_info': [],
            'cuda_version': '',
            'nvidia_driver': ''
        }

        if self.os_type == "linux":
            info = self._get_linux_info(info)
        elif self.os_type == "windows":
            info = self._get_windows_info(info)

        return info

    def _get_linux_info(self, info: Dict) -> Dict:
        """Get system info from Linux host"""
        # Hostname
        info['hostname'] = self.execute("hostname").strip()

        # OS Version
        os_release = self.execute("cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null")
        for line in os_release.split('\n'):
            if line.startswith('PRETTY_NAME='):
                info['os_version'] = line.split('=')[1].strip('"')
                break
        if not info['os_version']:
            info['os_version'] = os_release.split('\n')[0] if os_release else "Unknown Linux"

        # Kernel
        info['kernel'] = self.execute("uname -r").strip()

        # Uptime
        uptime_raw = self.execute("uptime -p 2>/dev/null || uptime")
        info['uptime'] = uptime_raw.strip()

        # CPU Info
        cpu_model = self.execute("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2")
        info['cpu_info'] = cpu_model.strip()

        cpu_cores = self.execute("nproc")
        info['cpu_cores'] = cpu_cores.strip()

        # CPU Usage
        cpu_usage = self.execute("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1")
        if cpu_usage.strip():
            info['cpu_usage'] = f"{cpu_usage.strip()}%"

        # Load Average
        load = self.execute("cat /proc/loadavg | awk '{print $1, $2, $3}'")
        info['load_average'] = load.strip()

        # Memory Info
        mem_info = self.execute("free -h | grep Mem")
        mem_parts = mem_info.split()
        if len(mem_parts) >= 3:
            info['memory_total'] = mem_parts[1]
            info['memory_used'] = mem_parts[2]
            info['memory_free'] = mem_parts[3] if len(mem_parts) > 3 else "N/A"

        mem_percent = self.execute("free | grep Mem | awk '{printf(\"%.1f\", $3/$2 * 100.0)}'")
        info['memory_percent'] = f"{mem_percent.strip()}%"

        # Disk Info
        disk_output = self.execute("df -h | grep -E '^/dev'")
        for line in disk_output.strip().split('\n'):
            if line:
                parts = line.split()
                if len(parts) >= 6:
                    info['disk_info'].append({
                        'device': parts[0],
                        'size': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'percent': parts[4],
                        'mount': parts[5]
                    })

        # Network Interfaces
        net_output = self.execute("ip -4 addr show | grep -E 'inet |^[0-9]'")
        current_interface = None
        for line in net_output.strip().split('\n'):
            if line and not line.startswith(' '):
                match = re.search(r'\d+: (\S+):', line)
                if match:
                    current_interface = match.group(1)
            elif 'inet ' in line and current_interface:
                ip_match = re.search(r'inet (\S+)', line)
                if ip_match:
                    info['network_interfaces'].append({
                        'interface': current_interface,
                        'ip': ip_match.group(1)
                    })

        # Logged in users
        info['logged_users'] = self.execute("who | wc -l").strip()

        # Process count
        info['processes'] = self.execute("ps aux | wc -l").strip()

        # Running services (systemd)
        services = self.execute("systemctl list-units --type=service --state=running 2>/dev/null | head -20")
        if services:
            for line in services.strip().split('\n')[1:]:
                if '.service' in line:
                    parts = line.split()
                    if parts:
                        info['services'].append(parts[0].replace('.service', ''))

        # NVIDIA GPU Information
        info = self._get_nvidia_gpu_info_linux(info)

        return info

    def _get_nvidia_gpu_info_linux(self, info: Dict) -> Dict:
        """Get NVIDIA GPU info from Linux host using nvidia-smi"""
        # Check if nvidia-smi is available
        nvidia_check = self.execute("which nvidia-smi 2>/dev/null")
        if not nvidia_check.strip() or 'not found' in nvidia_check.lower():
            return info

        info['gpu_available'] = True

        # Get NVIDIA driver version
        driver = self.execute("nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1")
        info['nvidia_driver'] = driver.strip()

        # Get CUDA version
        cuda_version = self.execute("nvidia-smi | grep 'CUDA Version' | awk '{print $9}' 2>/dev/null")
        if cuda_version.strip():
            info['cuda_version'] = cuda_version.strip()
        else:
            # Try nvcc as fallback
            nvcc_version = self.execute("nvcc --version 2>/dev/null | grep 'release' | awk '{print $5}' | tr -d ','")
            if nvcc_version.strip():
                info['cuda_version'] = nvcc_version.strip()

        # Get detailed GPU information for each GPU
        gpu_query = self.execute(
            "nvidia-smi --query-gpu=index,name,uuid,memory.total,memory.used,memory.free,"
            "utilization.gpu,utilization.memory,temperature.gpu,power.draw,power.limit,"
            "clocks.current.graphics,clocks.current.memory,pstate "
            "--format=csv,noheader,nounits 2>/dev/null"
        )

        for line in gpu_query.strip().split('\n'):
            if line and not line.startswith('Error') and ',' in line:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 10:
                    gpu = {
                        'index': parts[0] if len(parts) > 0 else 'N/A',
                        'name': parts[1] if len(parts) > 1 else 'N/A',
                        'uuid': parts[2] if len(parts) > 2 else 'N/A',
                        'memory_total': f"{parts[3]} MiB" if len(parts) > 3 else 'N/A',
                        'memory_used': f"{parts[4]} MiB" if len(parts) > 4 else 'N/A',
                        'memory_free': f"{parts[5]} MiB" if len(parts) > 5 else 'N/A',
                        'gpu_utilization': f"{parts[6]}%" if len(parts) > 6 else 'N/A',
                        'memory_utilization': f"{parts[7]}%" if len(parts) > 7 else 'N/A',
                        'temperature': f"{parts[8]}C" if len(parts) > 8 else 'N/A',
                        'power_draw': f"{parts[9]} W" if len(parts) > 9 else 'N/A',
                        'power_limit': f"{parts[10]} W" if len(parts) > 10 else 'N/A',
                        'clock_graphics': f"{parts[11]} MHz" if len(parts) > 11 else 'N/A',
                        'clock_memory': f"{parts[12]} MHz" if len(parts) > 12 else 'N/A',
                        'pstate': parts[13] if len(parts) > 13 else 'N/A'
                    }
                    info['gpu_info'].append(gpu)

        # If detailed query failed, try simpler query
        if not info['gpu_info']:
            simple_query = self.execute(
                "nvidia-smi --query-gpu=index,name,memory.total,memory.used,temperature.gpu,utilization.gpu "
                "--format=csv,noheader,nounits 2>/dev/null"
            )
            for line in simple_query.strip().split('\n'):
                if line and ',' in line:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 4:
                        gpu = {
                            'index': parts[0] if len(parts) > 0 else 'N/A',
                            'name': parts[1] if len(parts) > 1 else 'N/A',
                            'memory_total': f"{parts[2]} MiB" if len(parts) > 2 else 'N/A',
                            'memory_used': f"{parts[3]} MiB" if len(parts) > 3 else 'N/A',
                            'temperature': f"{parts[4]}C" if len(parts) > 4 else 'N/A',
                            'gpu_utilization': f"{parts[5]}%" if len(parts) > 5 else 'N/A'
                        }
                        info['gpu_info'].append(gpu)

        # Get compute capability / CUDA ID for each GPU
        for gpu in info['gpu_info']:
            cuda_id = self.execute(
                f"nvidia-smi -i {gpu['index']} --query-gpu=compute_cap --format=csv,noheader 2>/dev/null"
            )
            if cuda_id.strip() and 'Error' not in cuda_id:
                gpu['cuda_compute_capability'] = cuda_id.strip()

        return info

    def _get_windows_info(self, info: Dict) -> Dict:
        """Get system info from Windows host"""
        # Hostname
        info['hostname'] = self.execute("hostname").strip()

        # OS Version
        os_info = self.execute('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"')
        for line in os_info.split('\n'):
            if 'OS Name' in line:
                info['os_version'] = line.split(':', 1)[1].strip() if ':' in line else ""

        # Uptime
        uptime = self.execute('net statistics workstation | findstr "since"')
        info['uptime'] = uptime.strip()

        # CPU Info
        cpu = self.execute('wmic cpu get name /value')
        for line in cpu.split('\n'):
            if 'Name=' in line:
                info['cpu_info'] = line.split('=')[1].strip()

        cores = self.execute('wmic cpu get NumberOfCores /value')
        for line in cores.split('\n'):
            if 'NumberOfCores=' in line:
                info['cpu_cores'] = line.split('=')[1].strip()

        # Memory
        mem = self.execute('wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /value')
        total_kb = 0
        free_kb = 0
        for line in mem.split('\n'):
            if 'TotalVisibleMemorySize=' in line:
                try:
                    total_kb = int(line.split('=')[1].strip())
                    info['memory_total'] = f"{total_kb // 1024} MB"
                except:
                    pass
            if 'FreePhysicalMemory=' in line:
                try:
                    free_kb = int(line.split('=')[1].strip())
                    info['memory_free'] = f"{free_kb // 1024} MB"
                except:
                    pass

        if total_kb > 0 and free_kb > 0:
            used_kb = total_kb - free_kb
            info['memory_used'] = f"{used_kb // 1024} MB"
            info['memory_percent'] = f"{(used_kb / total_kb * 100):.1f}%"

        # Disk Info
        disk = self.execute('wmic logicaldisk get caption,size,freespace /value')
        current_disk = {}
        for line in disk.split('\n'):
            line = line.strip()
            if 'Caption=' in line:
                if current_disk:
                    info['disk_info'].append(current_disk)
                current_disk = {'device': line.split('=')[1]}
            elif 'FreeSpace=' in line and current_disk:
                try:
                    free_bytes = int(line.split('=')[1])
                    current_disk['available'] = f"{free_bytes // (1024**3)} GB"
                except:
                    pass
            elif 'Size=' in line and current_disk:
                try:
                    size_bytes = int(line.split('=')[1])
                    current_disk['size'] = f"{size_bytes // (1024**3)} GB"
                except:
                    pass
        if current_disk and current_disk.get('size'):
            info['disk_info'].append(current_disk)

        # Network
        net = self.execute('ipconfig | findstr /i "IPv4 Adapter"')
        current_adapter = "Unknown"
        for line in net.split('\n'):
            if 'Adapter' in line:
                current_adapter = line.split('Adapter')[1].strip().rstrip(':')
            elif 'IPv4' in line:
                ip = line.split(':')[1].strip() if ':' in line else ""
                if ip:
                    info['network_interfaces'].append({
                        'interface': current_adapter,
                        'ip': ip
                    })

        # Process count
        proc_count = self.execute('tasklist | find /c /v ""')
        info['processes'] = proc_count.strip()

        # NVIDIA GPU Information for Windows
        info = self._get_nvidia_gpu_info_windows(info)

        return info

    def _get_nvidia_gpu_info_windows(self, info: Dict) -> Dict:
        """Get NVIDIA GPU info from Windows host using nvidia-smi"""
        # Check if nvidia-smi is available
        nvidia_check = self.execute('where nvidia-smi 2>nul')
        if not nvidia_check.strip() or 'Could not find' in nvidia_check:
            # Try default path
            nvidia_check = self.execute('dir "C:\\Program Files\\NVIDIA Corporation\\NVSMI\\nvidia-smi.exe" 2>nul')
            if 'File Not Found' in nvidia_check or not nvidia_check.strip():
                return info

        info['gpu_available'] = True
        nvidia_cmd = 'nvidia-smi'

        # Get NVIDIA driver version
        driver = self.execute(f'{nvidia_cmd} --query-gpu=driver_version --format=csv,noheader 2>nul')
        if driver.strip():
            info['nvidia_driver'] = driver.strip().split('\n')[0]

        # Get CUDA version from nvidia-smi output
        smi_output = self.execute(f'{nvidia_cmd} 2>nul')
        for line in smi_output.split('\n'):
            if 'CUDA Version' in line:
                parts = line.split('CUDA Version:')
                if len(parts) > 1:
                    info['cuda_version'] = parts[1].strip().split()[0]
                break

        # Get detailed GPU information
        gpu_query = self.execute(
            f'{nvidia_cmd} --query-gpu=index,name,uuid,memory.total,memory.used,memory.free,'
            'utilization.gpu,utilization.memory,temperature.gpu,power.draw,power.limit '
            '--format=csv,noheader,nounits 2>nul'
        )

        for line in gpu_query.strip().split('\n'):
            if line and ',' in line and 'Error' not in line:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 6:
                    gpu = {
                        'index': parts[0] if len(parts) > 0 else 'N/A',
                        'name': parts[1] if len(parts) > 1 else 'N/A',
                        'uuid': parts[2] if len(parts) > 2 else 'N/A',
                        'memory_total': f"{parts[3]} MiB" if len(parts) > 3 else 'N/A',
                        'memory_used': f"{parts[4]} MiB" if len(parts) > 4 else 'N/A',
                        'memory_free': f"{parts[5]} MiB" if len(parts) > 5 else 'N/A',
                        'gpu_utilization': f"{parts[6]}%" if len(parts) > 6 else 'N/A',
                        'memory_utilization': f"{parts[7]}%" if len(parts) > 7 else 'N/A',
                        'temperature': f"{parts[8]}C" if len(parts) > 8 else 'N/A',
                        'power_draw': f"{parts[9]} W" if len(parts) > 9 else 'N/A',
                        'power_limit': f"{parts[10]} W" if len(parts) > 10 else 'N/A'
                    }
                    info['gpu_info'].append(gpu)

        # Get compute capability for each GPU
        for gpu in info['gpu_info']:
            cuda_id = self.execute(
                f'{nvidia_cmd} -i {gpu["index"]} --query-gpu=compute_cap --format=csv,noheader 2>nul'
            )
            if cuda_id.strip() and 'Error' not in cuda_id:
                gpu['cuda_compute_capability'] = cuda_id.strip()

        return info

    def disconnect(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.client = None


def get_device_info(host: str, port: int, username: str, password: str) -> Optional[Dict]:
    """Helper function to get device info via SSH"""
    client = SSHClient(host, port, username, password)
    if client.connect():
        info = client.get_system_info()
        client.disconnect()
        return info
    return None


if __name__ == "__main__":
    # Test connection
    import sys
    if len(sys.argv) >= 4:
        host = sys.argv[1]
        user = sys.argv[2]
        passwd = sys.argv[3]
        port = int(sys.argv[4]) if len(sys.argv) > 4 else 22

        info = get_device_info(host, port, user, passwd)
        if info:
            print(f"\nSystem Information for {host}:")
            for key, value in info.items():
                print(f"  {key}: {value}")
        else:
            print(f"Failed to connect to {host}")
    else:
        print("Usage: python ssh_client.py <host> <username> <password> [port]")
