import subprocess

from network.generate_cmds import generate_cmds
from clients.run_clients import run_benchmark
from analysis.analyze_ack import generate_plot

CONFIG_FILE = './param.json'

def main():
    # Run network commands
    cmds = generate_cmds(CONFIG_FILE)
    subprocess.run(cmds, capture_output=True, shell=True)

    # Run benchmarks
    clients: dict[str, list[str]] = run_benchmark(CONFIG_FILE)

    # Generate plots
    for client in clients:
        for json_file in client:
            generate_plot(json_file)

main()
