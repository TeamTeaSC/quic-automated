import os
import json
import time
import subprocess
from urllib.parse import urlparse

# Directories
TMP_PCAP_DIR = './tmp'
PCAP_OUT_DIR = './pcap'
DIRS = [TMP_PCAP_DIR, 
        PCAP_OUT_DIR]

# Make all directories in DIRS (if they don't exist)
def make_dirs():
    for DIR in DIRS:
        if not os.path.exists(DIR):
            os.makedirs(DIR)
    

# Use tshark capture packets
def run_pcap(url_host: str, url_port: str | None, url_path: str):
    process = subprocess.Popen([
        'tshark',
        '-f',
        f'host {url_host}',         # filter for only host traffic
        '-i'
        'eth0',                     # capture on eth0 interface
        '-w',
        f'{TMP_PCAP_DIR}/out.pcap', # write to temp file
    ])
    return process

# Convert pcap file into JSON
def read_pcap(is_h3: bool):
    curr_time = time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())
    read_path = f'{TMP_PCAP_DIR}/out.pcap'
    write_path = f'{PCAP_OUT_DIR}/out-{curr_time}.json'

    if is_h3:  # filter for QUIC packets
        cmd = ' '.join([
            'tshark',
            f'-r {read_path}',  # read pcap file
            '-T json',          # output format = JSON
            '-e ip.src',        # ip source address
            '-e ip.dst',        # ip destination address
            '-e udp',           # udp summary
            '-e udp.length',    # udp len (bytes)
            '-e quic',                   # quic summary
            '-e quic.packet_length',     # quic len (bytes)
            '-e quic.short',             # quic flags
            '-e quic.remaining_payload', # quic payload
            '-e frame.time',    # timestamp (of ethernet frame)
            f'> {write_path}'   # write JSON file
        ])
    else:  # filter for TCP packets
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

# Generate commands for client targeting endpoint.
# Returns [] if client string is invalid.
def client_cmds(client: str, endpoint: str, url_host: str, url_port: str | None, 
                url_path: str) -> list[str]:
    cmds = []
    match client:
        case 'curl_h2':
            cmds.append('curl')      
            cmds.append('--http2')   # use http2
            cmds.append(endpoint)    # target endpoint

        case 'proxygen_h3':
            cmds.append('/home/shchien/proxygen/proxygen/_build/proxygen/httpserver/hq')  
            cmds.append('--mode=client')              # cliet mode
            cmds.append('--protocol=h3')              # use http3
            cmds.append('--quic_version=1')           # use quic version 1
            cmds.append(f'--host={url_host}')         # host
            cmds.append(f'--port={url_port or 443}')  # port (default to 443)
            cmds.append(f'--path={url_path}')         # path

        case 'ngtcp2_h3':  
            cmds.append('/home/shchien/ngtcp2/examples/wsslclient')
            cmds.append('--exit-on-all-streams-close')  # close all streams upon exit
            cmds.append(f'{url_host}')         # host
            cmds.append(f'{url_port or 443}')  # port (default to 443)
            cmds.append(f'{endpoint}')         # complete url

        case _:  # invalid client provided, return []
            pass

    return cmds

# Run benchmark across all clients
def run_benchmark(config_file: str):
    print(f'--- START BENCHMARK ---\n')

    # Make directories
    make_dirs()

    # Read JSON file containing configs
    with open(config_file) as f:
        d = json.load(f)
    
    # Get clients
    clients: list[str] = d.get('clients')
    if clients is None:
        print("Error: client field is empty, exiting.")
        return

    # Get target endpoint
    endpoint: str = d.get('endpoint')
    if endpoint is None:
        print("Error: endpoint field is empty, exiting.")
        return
    
    iters = 1  # number of iterations to run tests for
    for client in clients:
        run_client(client, endpoint, iters)

    print(f'--- END BENCHMARK ---\n')

# Run client iters-many times
def run_client(client: str, endpoint: str, iters: int):
    print(f'--- START CLIENT: {client} ---\n')

    # determine if client is h2 or h3
    is_h3 = ('h3' in client)

    # parse endpoint
    url_obj = urlparse(endpoint)
    url_host: str = url_obj.hostname
    url_port: str = url_obj.port
    url_path: str = url_obj.path
    print(url_host, url_port, url_path)

    # generate client commands
    cmds: list[str] = client_cmds(client, endpoint, url_host, url_port, url_path)
    if cmds == []:
        print(f'Error: client field is invalid ({client}), exiting.')
        return

    for i in range(iters):
        print(f'--- CLIENT {client} : ITERATION {i} ---\n')
        # start recording pcap
        pcap_process = run_pcap(url_host, url_port, url_path)

        # hit endpoint
        time.sleep(1)
        output = subprocess.run(cmds, capture_output=True)
        # print(output)
        
        # stop recording pcap
        time.sleep(1)
        pcap_process.kill()
        
        # read pcap into JSON
        time.sleep(1)
        pcap_output = read_pcap(is_h3)
        print(pcap_output)
    
    print(f'--- STOP CLIENT: {client} ---\n')
            

run_benchmark('./network/param.json')
