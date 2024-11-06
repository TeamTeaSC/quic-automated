import os
import json
import time
import subprocess
from urllib.parse import urlparse

TMP_PCAP_DIR = './tmp'

def make_dirs():
    if not os.path.exists(TMP_PCAP_DIR):
        os.makedirs(TMP_PCAP_DIR)

def run_pcap(url_host: str, url_port: str | None, url_path: str):
    process = subprocess.Popen([
        'sudo',
        'tcpdump',
        f'tcp and host {url_host}',  # filter for TCP and host traffic
        '-i',                        # filter by interface
        'eth0',
        '-w',
        f'{TMP_PCAP_DIR}/out.pcap'
    ])
    return process

def read_pcap():
    filepath = f'{TMP_PCAP_DIR}/out.pcap'
    output = subprocess.run([

    ], capture_output=True)
    return

def run_benchmark(config_file: str):
    # Make directories
    make_dirs()

    # Read JSON file containing configs
    with open(config_file) as f:
        d = json.load(f)
    
    clients: list[str] = d.get('clients')
    if clients is None:
        print("Error: client field is empty, exiting.")
        return

    endpoint: str = d.get('endpoint')
    if endpoint is None:
        print("Error: endpoint field is empty, exiting.")
        return
    
    iters = 1  # number of iterations to run tests for
    for client in clients:
        run_client(client, endpoint, iters)


def run_client(client: str, endpoint: str, iters: int):
    # parse endpoint
    url_obj = urlparse(endpoint)
    url_host: str = url_obj.hostname
    url_port: str = url_obj.port
    url_path: str = url_obj.path
    print(url_host, url_port, url_path)

    # generate client commands
    cmds: list[str] = client_cmds(client, endpoint, url_host, url_port, url_path)

    for _ in range(iters):
        pcap_process = run_pcap(url_host, url_port, url_path)
        time.sleep(1)

        output = subprocess.run(cmds, capture_output=True)
        stdout, stderr = output.stdout, output.stderr

        time.sleep(1)
        pcap_process.kill()
        # print(output)

def client_cmds(client: str, endpoint: str, url_host: str, url_port: str | None, 
                url_path: str) -> list[str]:
    cmds = []
    match client:
        case 'curl_h2':
            cmds.append('curl')
            cmds.append('--http2')
            cmds.append(endpoint)

        case 'proxygen_h3':
            cmds.append()

    return cmds
            

run_benchmark('./network/param.json')