import os
import json
import time
import pathlib
import subprocess
from urllib.parse import urlparse

# Directories
ROOT_DIR = pathlib.Path(__file__).parent.parent.absolute()
TMP_PCAP_DIR = ROOT_DIR.joinpath('tmp')
PCAP_OUT_DIR = ROOT_DIR.joinpath('pcap')
SSL_KEY_LOG_DIR = ROOT_DIR.joinpath('ssl')
DIRS = [TMP_PCAP_DIR, PCAP_OUT_DIR, SSL_KEY_LOG_DIR]   

PROXYGEN_EXEC_PATH = '/home/shchien/proxygen/proxygen/_build/proxygen/httpserver/hq'
NGTCP2_EXEC_PATH = '/home/shchien/ngtcp2/examples/wsslclient'

# Make all directories in DIRS (if they don't exist)
def make_dirs(DIRS: list[str]):
    for DIR in DIRS:
        if not os.path.exists(DIR):
            os.makedirs(DIR) 

# Use tshark capture packets
def run_pcap(pcap_file: str, url_host: str, url_port: str | None, url_path: str, 
            env):
    process = subprocess.Popen([
        'tshark',
        '-f',
        f'host {url_host}',         # filter for only host traffic
        '-i'
        'eth0',                     # capture on eth0 interface
        '-w',
        f'{pcap_file}', # write to temp file
    ], env=env)
    return process

# Convert pcap file into JSON, returns process exit
def read_pcap(is_h3: bool, pcap_file: str, json_file: str, ssl_key_log_file: str, 
              env) -> str:
    if is_h3:  # filter for QUIC packets
        cmd = ' '.join([
            'tshark',
            f'-r {pcap_file}',  # read pcap file
            '-T json',          # output format = JSON
            f'-o tls.keylog_file:{ssl_key_log_file}', # points to TLS secrets
            '--no-duplicate-keys', # combines all duplicate keys into one array
            f'> {json_file}'   # write JSON file
        ])
    else:  # filter for TCP packets
        cmd = ' '.join([
            'tshark',
            f'-r {pcap_file}',   # read pcap file
            '-T json',           # output format = JSON
            '-J tcp',            # combines all duplicate keys into one array
            '--no-duplicate-keys',
            f'> {json_file}'    # write JSON file
        ])

    output = subprocess.run([cmd],
                            capture_output=True, 
                            shell=True, env=env)
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
            cmds.append(PROXYGEN_EXEC_PATH)  
            cmds.append('--mode=client')              # cliet mode
            cmds.append('--protocol=h3')              # use http3
            cmds.append('--quic_version=1')           # use quic version 1
            cmds.append(f'--host={url_host}')         # host
            cmds.append(f'--port={url_port or 443}')  # port (default to 443)
            cmds.append(f'--path={url_path}')         # path

        case 'ngtcp2_h3':  
            cmds.append(NGTCP2_EXEC_PATH)
            cmds.append('--exit-on-all-streams-close')  # close all streams upon exit
            cmds.append(f'{url_host}')         # host
            cmds.append(f'{url_port or 443}')  # port (default to 443)
            cmds.append(f'{endpoint}')         # complete url

        case _:  # invalid client provided, return []
            pass

    return cmds

# Run client iters-many times.
# Returns a list of output file names (packet traces in JSON).
def run_client(client: str, endpoint: str, iters: int) -> list[str]:
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

    outputs = []
    for i in range(iters):
        print(f'--- CLIENT {client} : ITERATION {i} ---\n')
        
        # timestamp files
        curr_time = time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())

        # setup OS environment to log TLS keys
        ssl_key_log_file = SSL_KEY_LOG_DIR.joinpath(f'ssl-{curr_time}.txt')
        env = os.environ.copy()
        env['SSLKEYLOGFILE'] = ssl_key_log_file

        # start recording pcap
        pcap_file = f'{TMP_PCAP_DIR}/out-{curr_time}.pcap'
        pcap_process = run_pcap(pcap_file, url_host, url_port, url_path, env)

        # hit endpoint
        time.sleep(1)
        subprocess.run(cmds, capture_output=True, env=env)

        # stop recording pcap
        time.sleep(1)
        pcap_process.kill()
        
        # read pcap into JSON
        time.sleep(1)
        json_file = f'{PCAP_OUT_DIR}/out-{curr_time}.json'
        outputs.append(json_file)
        read_pcap(is_h3, pcap_file, json_file, ssl_key_log_file, env)
    
    print(f'--- STOP CLIENT: {client} ---\n')
    return outputs

# Run benchmark across all clients.
# For each client, returns a list containing all JSON output files.
def run_benchmark(config_file: str) -> dict[str, list[str]]:
    print(f'--- START BENCHMARK ---\n')

    # Make directories
    make_dirs(DIRS)

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
    
    # Get number of iterations for each client
    iters: int = d.get('iters')
    if iters is None:
        iters = 1  # default number of iterations

    outputs = {}
    for client in clients:
        client_out: list[str] = run_client(client, endpoint, iters)
        outputs[client] = client_out
    
    print(f'--- END BENCHMARK ---\n')    
    return outputs

# test
run_benchmark('./param.json')
