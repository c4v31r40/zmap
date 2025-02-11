import argparse
from colorama import Fore, Style
import socket
import concurrent.futures

# Definição manual das portas e serviços
PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "Domain (DNS)",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "Microsoft-DS",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    # Adicione mais portas e serviços conforme necessário
}

# Função para escanear uma porta
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

# Função para escanear várias portas usando threads
def fast_scan(ip, ports):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)
    return open_ports

# Função para verificar vulnerabilidades com base na porta e serviço
def check_vulnerabilities(port, service):
    vulnerabilities = []
    if port == 21 and service == "FTP":
        vulnerabilities.append("FTP Worth Check for Anonymous Login.")
    if port == 22 and service == "SSH":
        vulnerabilities.append("SSH: Verificar versão e autenticação.")
    if port == 80 and service == "HTTP":
        vulnerabilities.append("HTTP: Verificar se há diretórios expostos.")
    if port == 443 and service == "HTTPS":
        vulnerabilities.append("HTTPS: Verificar certificado SSL/TLS.")
    if port == 3389 and service == "RDP":
        vulnerabilities.append("RDP: Verificar se a autenticação é segura.")
    # Adicione mais verificações de vulnerabilidades conforme necessário
    return vulnerabilities

# Função para imprimir os resultados
def print_results(ip, open_ports):
    for port in open_ports:
        service = PORT_SERVICES.get(port, "Unknown")
        vulnerabilities = check_vulnerabilities(port, service)
        print(f"{Fore.GREEN}[+] Port {port} open: {service}{Style.RESET_ALL}")
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(f"{Fore.RED}[!] {vuln}{Style.RESET_ALL}")

# Função principal
def main():
    parser = argparse.ArgumentParser(description="ZMap - Basic Scan Tool.")
    parser.add_argument("-t", "--target", help="Target IP", required=True)
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 'all' for all ports, or '21,53,80' for specific ports)", required=True)
    args = parser.parse_args()

    target_ip = args.target
    ports_input = args.ports

    # Definir as portas a serem escaneadas
    if ports_input.lower() == "all":
        ports_to_scan = range(1, 65536)  # Escaneia todas as portas (1-65535)
    else:
        ports_to_scan = [int(port) for port in ports_input.split(",")]  # Escaneia portas específicas

    print(f"{Fore.BLUE}[*] Scanning IP {target_ip}...{Style.RESET_ALL}")
    open_ports = fast_scan(target_ip, ports_to_scan)
    if open_ports:
        print_results(target_ip, open_ports)
    else:
        print(f"{Fore.YELLOW}[!] No open ports found.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()