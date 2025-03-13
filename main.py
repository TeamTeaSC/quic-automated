import subprocess

from network.generate_cmds import generate_cmds
from clients.run_clients import run_benchmark
from clients.helper import is_client_tcp
from analysis.analyze_ack import *
from analysis.changepoint import Changepoint

CONFIG_FILE = './param.json'

def main():
    # Run network commands
    cmds = generate_cmds(CONFIG_FILE)
    subprocess.run(cmds, capture_output=True, shell=True)

    # Run benchmarks
    clients: dict[str, list[str]] = run_benchmark(CONFIG_FILE)

    # Generate plots
    print("clients:", clients)
    for client in clients:
        for json_file in clients[client]:
            print(f'{client}: {json_file}')
            if (is_client_tcp(client)):
                generate_plot_tcp(json_file, client=client, 
                                  algs=[Changepoint.PELT, Changepoint.BINSEG, Changepoint.WINDOW])
            else:
                generate_plot_quic(json_file, client=client,
                                   algs=[Changepoint.PELT, Changepoint.BINSEG, Changepoint.WINDOW])

main()
