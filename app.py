import socket
import ipaddress
import os
from flask import Flask, render_template, request, flash
import concurrent.futures
from scapy.all import sr1, IP, TCP, ICMP, send

app = Flask(__name__)
app.secret_key = 'supersecretkey' # Needed for flashing messages

def scan_port(host, port, timeout=1):
    """
    Scans a single port to see if it is open.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        # connect_ex returns 0 if connection succeeds, otherwise an error code
        result = sock.connect_ex((host, port))
        if result == 0:
            return port
        return None
    except (socket.gaierror, socket.error):
        # This handles errors like "Name or service not known"
        return False
    finally:
        sock.close()

def parse_ports(port_string):
    """Parses a port string (e.g., "80, 100-110, 443") into a list of integers."""
    ports = set()
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 0 < start <= end < 65536:
                    ports.update(range(start, end + 1))
            except ValueError:
                # Ignore malformed ranges
                pass
        else:
            try:
                port = int(part)
                if 0 < port < 65536:
                    ports.add(port)
            except ValueError:
                # Ignore malformed port numbers
                pass
    return sorted(list(ports))

def parse_hosts(host_string):
    """Parses a host string into a list of IP addresses or hostnames."""
    hosts = set()
    parts = [part.strip() for part in host_string.replace(',', '\n').split('\n') if part.strip()]

    for part in parts:
        try:
            network = ipaddress.ip_network(part, strict=False)
            if network.num_addresses == 1:
                hosts.add(str(network.network_address))
            else:
                for ip in network:
                    hosts.add(str(ip))
        except ValueError:
            hosts.add(part)
    return sorted(list(hosts))

def syn_scan_port(host, port, timeout=1):
    """Performs a SYN scan on a single port."""
    try:
        ip_packet = IP(dst=host)
        tcp_packet = TCP(dport=port, sport=RandShort(), flags="S")
        response = sr1(ip_packet/tcp_packet, timeout=timeout, verbose=0)

        if response is None:
            return None

        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12: # SYN/ACK
                rst_packet = IP(dst=host)/TCP(dport=port, sport=response[TCP].dport, seq=response[TCP].ack, ack=response[TCP].seq + 1, flags="R")
                send(rst_packet, verbose=0)
                return port
            elif response.getlayer(TCP).flags == 0x14: # RST/ACK
                return None
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                return None # Filtered
    except Exception:
        return None
    return None

def sweep_scan(hosts, ports, scan_type='tcp', concurrency=100, timeout=1):
    """Performs a scan across multiple hosts and ports."""
    scan_func = syn_scan_port if scan_type == 'syn' else scan_port

    results = {host: [] for host in hosts}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_host_port = {
            executor.submit(scan_func, host, port, timeout): (host, port)
            for host in hosts for port in ports
        }

        for future in concurrent.futures.as_completed(future_to_host_port):
            host, port = future_to_host_port[future]
            try:
                if future.result() is not None:
                    results[host].append(port)
            except Exception:
                pass

    final_results = {host: sorted(open_ports) for host, open_ports in results.items() if open_ports}
    return final_results

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    hosts_string = ''
    ports_string = ''
    timeout = 1.0
    concurrency = 100
    scan_type = 'tcp'

    if request.method == 'POST':
        hosts_string = request.form.get('hosts', '')
        ports_string = request.form.get('ports', '')
        timeout = float(request.form.get('timeout', 1.0))
        concurrency = int(request.form.get('concurrency', 100))
        scan_type = request.form.get('scan_type', 'tcp')

        original_scan_type = scan_type
        if scan_type == 'syn' and os.geteuid() != 0:
            flash('SYN scan requires root privileges. Falling back to TCP Connect scan.')
            scan_type = 'tcp'

        hosts_to_scan = parse_hosts(hosts_string)
        ports_to_scan = parse_ports(ports_string)

        if hosts_to_scan and ports_to_scan:
             results = sweep_scan(hosts_to_scan, ports_to_scan, scan_type, concurrency, timeout)

        return render_template('index.html', results=results, hosts_string=hosts_string, ports_string=ports_string, timeout=timeout, concurrency=concurrency, scan_type=original_scan_type)

    return render_template('index.html', results=results, hosts_string=hosts_string, ports_string=ports_string, timeout=timeout, concurrency=concurrency, scan_type=scan_type)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
