import subprocess

import numpy as np
from network.generate_cmds import generate_cmds
from clients.run_clients import run_benchmark
from clients.helper import is_client_tcp
from analysis.analyze_ack import *
from analysis.changepoint import Changepoint
from analysis.eval_changepoint import *

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
                generate_plot_tcp(json_file, client=client)
            else:
                # generate_plot_quic(json_file, client=client)
                generate_csv_quic(json_file, client=client)

def test_changepoint_algorithm():
    csv_file = "./csv/meta-5MB-delay0-loss0.json"
    correct_bkps = np.array([22, 35, 46, 83, 107, 113, 143, 167, 231, 267, 310, 342])
    raw = read_csv_quic(csv_file)
    if raw is None:
        return
    
    rtts = raw['rtts']
    cum_acks = raw['cum_acks']

    min_size = None
    jump = None
    sigma = None
    width = None

    # (min_size, jump) = best_params_pelt(rtts, cum_acks, correct_bkps)
    # err, sigma = best_params_binseg(rtts, cum_acks, correct_bkps)
    # err, sigma = best_params_bottomup(rtts, cum_acks, correct_bkps)
    err, sigma, width = best_params_window(rtts, cum_acks, correct_bkps)
    
    print(f'err: {err}')
    print(f'min_size: {min_size}, jump: {jump}')
    print(f'sigma: {sigma}')
    print(f'width: {width}')

    generate_plot_quic_csv("./csv/meta-5MB-delay0-loss0.json", correct_bkps, 
                           alg = Changepoint.PELT, min_size=min_size, jump=jump,
                           sigma=sigma, width=width)

# main()
test_changepoint_algorithm()
# generate_plot_quic_csv("./csv/meta-5MB-delay0-loss0.json")
