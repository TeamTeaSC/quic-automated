import os
import json
import time
import subprocess
from urllib.parse import urlparse

TMP_PCAP_DIR = './tmp'
PCAP_OUT_DIR = './pcap'
DIRS = [TMP_PCAP_DIR, 
        PCAP_OUT_DIR]

# Make all directories in DIRS (if they don't exist)
def make_dirs():
    for DIR in DIRS:
        if not os.path.exists(DIR):
            os.makedirs(DIR)
    

# Start tcpdump
def run_pcap(url_host: str, url_port: str | None, url_path: str):
    process = subprocess.Popen([
        'sudo',
        'tshark',
        '-f',
        f'tcp and host {url_host}',  # filter for TCP and host traffic
        '-i',                        # capture on interface
        'eth0',
        '-w',
        f'{TMP_PCAP_DIR}/out.pcap'
    ])
    return process

# Convert pcap files into JSON
def read_pcap():
    curr_time = time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())
    read_path = f'{TMP_PCAP_DIR}/out.pcap'
    write_path = f'{PCAP_OUT_DIR}/out-{curr_time}.json'

    cmd = ' '.join([
        'tshark',
        f'-r {read_path}',  # read pcap file
        '-T json',          # output format = JSON
        '-e ip.src',        # ip source address
        '-e ip.dst',        # ip destination address
        '-e tcp',           # tcp summary
        '-e tcp.srcport',   # tcp source port
        '-e tcp.dstport',   # tcp destination port
        '-e tcp.len',       # tcp len (bytes)
        '-e tcp.seq',       # tcp sequence number
        '-e tcp.ack',       # tcp ack
        '-e tcp.flags',     # tcp flags
        '-e frame.time',    # timestamp (of ethernet frame)
        f'> {write_path}'   # write JSON file
    ])

    output = subprocess.run([cmd],
                            capture_output=True, 
                            shell=True)
    return output

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
        # start recording pcap
        pcap_process = run_pcap(url_host, url_port, url_path)
        time.sleep(1)

        output = subprocess.run(cmds, capture_output=True)
        stdout, stderr = output.stdout, output.stderr

        time.sleep(1)
        pcap_process.kill()
        # print(output)

        pcap_output = read_pcap()
        print(pcap_output)

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