import os
import json
import numpy as np
from matplotlib import pylab, mlab, pyplot as plt
from matplotlib.pylab import scatter

# Directories
PLOTS_DIR = './plots'
DIRS = [PLOTS_DIR]

# Make all directories in DIRS (if they don't exist)
def make_dirs(DIRS: list[str]):
    for DIR in DIRS:
        if not os.path.exists(DIR):
            os.makedirs(DIR) 

def analyze_pcap_tcp(pcap_file: str):
    with open(pcap_file) as f:
        d = json.load(f)
    
    times = []
    seqs = []
    acks = []
    is_fin = False

    for packet in d:
        if is_fin:
            break 
    
        tcp = packet['_source']['layers']['tcp']
        time = float(tcp['Timestamps']['tcp.time_relative']) * 1000  # relative time (in ms)

        is_receive = (tcp['tcp.srcport'] == '443')
        is_fin = (tcp['tcp.flags_tree']['tcp.flags.fin'] == '1')
    
        seq = int(tcp['tcp.seq'])
        ack = int(tcp['tcp.ack'])

        if not (is_receive or is_fin):
            times.append(time)
            seqs.append(seq)
            acks.append(ack)

    times = np.array(times)
    seqs  = np.array(seqs)
    acks  = np.array(acks)
    return {
        'times': times,
        'seqs': seqs,
        'acks': acks
    }

def generate_plot(pcap_file: str):
    make_dirs(DIRS)

    res = analyze_pcap_tcp(pcap_file)
    times, seqs, acks = res['times'], res['seqs'], res['acks']

    plt.scatter(times, acks)
    plt.xlabel('time (ms)')
    plt.ylabel('bytes acked')

    plot_file = str.replace(pcap_file, 'json', 'pdf')
    plot_file = str.replace(plot_file, 'pcap', PLOTS_DIR)
    plt.savefig(plot_file, format='pdf', bbox_inches='tight')

# test
# file_name = './pcap/out-2024-11-08-02:10:10.json'
# generate_plot(file_name)
