# --- Import external libraries ---
import os
import csv
import json
import time
import numpy as np
from matplotlib import pyplot as plt, patches as ptch
from typing import Optional

# --- Import internal files ---
from analysis.changepoint import *

# --- Directories ---
PLOTS_DIR = './plots'
CSV_DIR = './csv'
DIRS = [PLOTS_DIR, CSV_DIR]

# --- Constants ---
ACK_TYPE = '0x0000000000000002'
CSV_DELIM = ','

# Make all directories in DIRS (if they don't exist)
def make_dirs(DIRS: list[str]):
    for DIR in DIRS:
        if not os.path.exists(DIR):
            os.makedirs(DIR) 

# Analyze TCP PCAP file and returns data points: ([RTT], [bytes acked])
def analyze_pcap_tcp_per_RTT(pcap_file: str):
    try:
        with open(pcap_file) as f:
            d = json.load(f)
    except OSError:
        print(f'[ERROR] could not open file:', pcap_file)
        return
    
    times = []
    seqs = []
    acks = []
    rtts = []
    is_fin = False

    initial_rtt = None   # RTT measured from initial handshake
    curr_rtt: int = 0    # current RTT
    cum_ack_prev = 0     # cumulative ack from previous RTT window
    cum_ack_curr = 0     # cumulative ack from current RTT window
    cum_acks = []        # cumulative ack within each RTT window

    for packet in d:
        if is_fin:
            break 

        tcp = packet['_source']['layers']['tcp']

        if ((initial_rtt is None) and 
            tcp.get('tcp.analysis') is not None and
            tcp.get('tcp.analysis').get('tcp.analysis.initial_rtt') is not None):
            initial_rtt = float(tcp['tcp.analysis']['tcp.analysis.initial_rtt']) * 1000 # (in ms)

        if initial_rtt is None:
            continue

        time = float(tcp['Timestamps']['tcp.time_relative']) * 1000  # relative time (in ms)

        is_receive = (tcp['tcp.srcport'] == '443') # packet coming from server port 443
        is_fin = (tcp['tcp.flags_tree']['tcp.flags.fin'] == '1')
    
        seq = int(tcp['tcp.seq'])
        ack = int(tcp['tcp.ack'])

        if not (is_receive or is_fin):
            times.append(time)
            seqs.append(seq)
            acks.append(ack)

            rtt = time / initial_rtt
            rtts.append(rtt)

            if int(rtt) > curr_rtt:
                curr_rtt = int(rtt)
                cum_ack_curr = cum_ack_prev
            cum_ack_prev = ack
            cum_acks.append(ack - cum_ack_curr)
            
    return {
        'times': np.array(times),
        'rtts': np.array(rtts),
        'seqs': np.array(seqs),
        'acks': np.array(acks),
        'cum_acks': np.array(cum_acks)
    }

# Analyze TCP PCAP file and returns data points: ([RTT], [bytes acked])
def analyze_pcap_tcp_cum(pcap_file: str):
    try:
        with open(pcap_file) as f:
            d = json.load(f)
    except OSError:
        print(f'[ERROR] could not open file:', pcap_file)
        return
    
    times = []
    seqs = []
    acks = []
    rtts = []
    is_fin = False

    initial_rtt = None   # RTT measured from initial handshake
    cum_acks = []        # cumulative ack within each RTT window

    for packet in d:
        if is_fin:
            break 

        tcp = packet['_source']['layers']['tcp']

        if ((initial_rtt is None) and 
            tcp.get('tcp.analysis') is not None and
            tcp.get('tcp.analysis').get('tcp.analysis.initial_rtt') is not None):
            initial_rtt = float(tcp['tcp.analysis']['tcp.analysis.initial_rtt']) * 1000 # (in ms)

        if initial_rtt is None:
            continue

        time = float(tcp['Timestamps']['tcp.time_relative']) * 1000  # relative time (in ms)

        is_receive = (tcp['tcp.srcport'] == '443') # packet coming from server port 443
        is_fin = (tcp['tcp.flags_tree']['tcp.flags.fin'] == '1')
    
        seq = int(tcp['tcp.seq'])
        ack = int(tcp['tcp.ack'])

        if not (is_receive or is_fin):
            times.append(time)
            seqs.append(seq)
            acks.append(ack)

            rtt = time / initial_rtt
            rtts.append(rtt)
            cum_acks.append(ack)
            
    return {
        'times': np.array(times),
        'rtts': np.array(rtts),
        'seqs': np.array(seqs),
        'acks': np.array(acks),
        'cum_acks': np.array(cum_acks)
    }

# Analyze QUIC PCAP file and returns data points: ([RTT], [bytes acked])
def analyze_pcap_quic(pcap_file: str):
    try:
        with open(pcap_file) as f:
            d = json.load(f)
    except OSError:
        print(f'[analyze_ack.py]: could not open file {pcap_file}')
        return

    times   : list[float] = []  # timestamps (in ms) of ACK packets
    acks    : list[int]   = []  # bytes ACKed
    cum_acks: list[int]   = []  # cumulative bytes ACKed

    # pkt_num -> (bytes outstanding, time)
    bytes_outstanding: dict[int, tuple[int, float]] = {}  
    rtt : Optional[float] = None

    for packet in d:
        layers = packet['_source']['layers']
        udp = layers.get('udp')
        quics = layers.get('quic')
        if (udp is None) or (quics is None):
            continue
        
        src = udp['udp.srcport']
        dst = udp['udp.dstport']
        is_receive = (src == '443') # packet coming from server port 443

        # convert quics to list (even if only 1 element)
        if (type(quics) == dict):
            quics = [quics]

        # loop through each quic packet
        for quic in quics:
            time = float(udp['Timestamps']['udp.time_relative']) * 1000  # (ms)

            # get packet number (sequence number)
            pkt_num = quic.get('quic.packet_number')
            if pkt_num is None:
                quic_short = quic.get('quic.short')
                if quic_short is not None:
                    pkt_num = quic_short.get('quic.packet_number')
            if pkt_num is None:
                continue
            pkt_num = int(pkt_num)

            # get packet length (number of bytes in payload)
            pkt_len = quic.get('quic.packet_length')
            if pkt_len is None:
                print('[ERROR] could not find packet length, skipping...')
            pkt_len = int(pkt_len)
            
            # update bytes outstanding and time for packet number
            if pkt_num not in bytes_outstanding:
                bytes_outstanding[pkt_num] = (0, 0.0)

            new_pkt_len = bytes_outstanding[pkt_num][0] + pkt_len
            bytes_outstanding[pkt_num] = (new_pkt_len, time)

            # convert frames to list (even if only 1 element)
            frames = quic['quic.frame']
            if type(frames) == dict:
                frames = [frames]
            
            # loop through each quic frame
            for frame in frames:
                # process ACK frame
                if (frame['quic.frame_type'] == ACK_TYPE) and (not is_receive):
                    ack = int(frame['quic.ack.largest_acknowledged'])
                    ack_range = int(frame['quic.ack.first_ack_range'])

                    # calculate bytes ACKed by this ACK frame
                    bytes_acked = 0
                    for pkt_num in range(ack, ack - ack_range - 1, -1):
                        if pkt_num in bytes_outstanding:
                            if rtt is None: # estimate RTT
                                rtt = time - bytes_outstanding[pkt_num][1]
                            bytes_acked += bytes_outstanding[pkt_num][0]
                            bytes_outstanding[pkt_num] = (0, 0.0)
                    times.append(time)
                    acks.append(bytes_acked)

                    # update cumulative bytes ACKed
                    if len(cum_acks) == 0:
                        cum_acks.append(bytes_acked)
                    else:
                        cum_acks.append(cum_acks[-1] + bytes_acked)

    # normalize times by RTT
    rtts: list[float] = []
    for time in times:
        rtts.append(time / rtt)
                    
    return {
        'times': np.array(times),
        'rtts': np.array(rtts),
        'acks': np.array(acks),
        'cum_acks': np.array(cum_acks)
    }

def get_plot_title(client: str | None) -> str:
    ''' Given client name, returns title of scatterplot
    
        @param client - Name of client (or None)
        @res Title of scatterplot
    '''
    title = 'Bytes ACKed vs RTT'
    if (client is not None):
        title = title + f' for {client}'
    return title

def get_plot_filename(pcap_file: str, alg: Changepoint) -> str:
    """ Given pcap file name and changepoint
    
    Args:
        pcap_file (str): name of pcap file
        alg (Changepoint): changepoint detection algorithm used
        
    Returns:
        plot_file (str): name of plot file
    """
    plot_file = str.replace(pcap_file, 'json', 'pdf')
    plot_file = str.replace(plot_file, 'pcap', PLOTS_DIR)
    if alg is not None:
        plot_file = plot_file[:-4] + f'-{alg.name}' + plot_file[-4:]
    return plot_file


def generate_plot_tcp(pcap_file: str, client: Optional[str] = None,
                      algs: Optional[list[Changepoint]] = None):
    print(f'--- GENERATING TCP PLOT FOR {pcap_file} ---')
    make_dirs(DIRS)

    res = analyze_pcap_tcp_cum(pcap_file)
    rtts, acks, cum_acks = res['rtts'], res['acks'], res['cum_acks']

    plt.close('all')             # close all previously opened plots
    plt.scatter(rtts, cum_acks)  # generate scatterplot

    # Generate axis labels
    plt.xlabel('RTT')
    plt.ylabel('bytes acked')

    # Generate title for scatterplot
    title: str = get_plot_title(client)
    plt.title(title)

    # Use PELT for changepoint detection if @algs not provided
    if algs is None:
        algs = [Changepoint.PELT]

    # Changepoint detection
    for alg in algs:
        brkps = predict_changepoints(rtts, cum_acks, alg)
        brkps = [0] + brkps[:-1] + [-1]  # ignore last breakpoint
        
        # Visualize changepoints by changing segment background color
        colors = ['#1f77b4', '#ff7f0e']
        num_colors = len(colors)
        y_min, y_max = plt.ylim()
        for i in range(len(brkps) - 1):
            color = colors[i % num_colors]
            start, end = brkps[i], brkps[i + 1]
            x_start, x_end = rtts[start], rtts[end]
            rect = ptch.Rectangle( (x_start, y_min), width=(x_end - x_start), 
                                    height=(y_max - y_min), facecolor=color,
                                    alpha=0.3,  # more transparent
                                    zorder=0)   # put rectangles behind points
            plt.gca().add_patch(rect)

        # Save plot as pdf file
        plot_file = get_plot_filename(pcap_file, alg)
        plt.savefig(plot_file, format='pdf', bbox_inches='tight')

def get_csv_filename(pcap_file: str) -> str:
    csv_file = str.replace(pcap_file, 'json', 'csv')
    csv_file = str.replace(pcap_file, 'pcap', CSV_DIR)
    return csv_file

def read_csv_quic(csv_file: str) -> np.ndarray:
    raw: np.ndarray = np.genfromtxt(csv_file, delimiter=CSV_DELIM)

    if (len(raw) == 0):
        return None
    
    times = raw[0]
    rtts = raw[1]
    acks = raw[2]
    cum_acks = raw[3]
    return {
        'times': times,
        'rtts': rtts,
        'acks': acks,
        'cum_acks': cum_acks
    }

def generate_csv_quic(pcap_file: str, client: Optional[str] = None) -> str:
    print(f'--- GENERATING QUIC CSV FOR {pcap_file} ---')
    make_dirs(DIRS)

    res = analyze_pcap_quic(pcap_file)
    times, rtts, acks, cum_acks = res['times'], res['rtts'], res['acks'], res['cum_acks']
    out = np.asarray([times, rtts, acks, cum_acks])
    csv_file = get_csv_filename(pcap_file)
    np.savetxt(csv_file, out, delimiter=CSV_DELIM)

    raw = read_csv_quic(csv_file)
    if raw is not None:
        print(raw['times'])
        print(raw['rtts'])
        print(raw['acks'])
        print(raw['cum_acks'])

    return csv_file

def generate_plot_quic(pcap_file: str, client: Optional[str] = None, 
                       algs: Optional[list[Changepoint]] = None):
    print(f'--- GENERATING QUIC PLOT FOR {pcap_file} ---')
    make_dirs(DIRS)

    res = analyze_pcap_quic(pcap_file)
    times, rtts, acks, cum_acks = res['times'], res['rtts'], res['acks'], res['cum_acks']

    # Use PELT for changepoint detection if @algs not provided
    if algs is None:
        algs = [Changepoint.PELT]

    # Plot using each changepoint algorithm
    for alg in algs:
        plt.close('all')             # close all previously opened plots
        plt.scatter(rtts, cum_acks)  # generate scatterplot
        
        plt.xlabel('RTT')
        plt.ylabel('bytes acked')

        # Generate title for scatterplot
        title: str = get_plot_title(client)
        plt.title(title)

        # Run changepoint detection algorithm
        if (len(rtts) > 0) and (len(cum_acks) > 0):
            brkps = predict_changepoints(rtts, cum_acks, alg)
            brkps = [0] + brkps[:-1] + [-1]  # ignore last breakpoint
        
            # Visualize changepoints by changing segment background color
            colors = ['#1f77b4', '#ff7f0e']
            num_colors = len(colors)
            y_min, y_max = plt.ylim()
            for i in range(len(brkps) - 1):
                color = colors[i % num_colors]
                start, end = brkps[i], brkps[i + 1]
                x_start, x_end = rtts[start], rtts[end]
                rect = ptch.Rectangle( (x_start, y_min), width=(x_end - x_start), 
                                        height=(y_max - y_min), facecolor=color,
                                        alpha=0.3,  # more transparent
                                        zorder=0)   # put rectangles behind points
                plt.gca().add_patch(rect)

        # Save plot as pdf file
        plot_file = get_plot_filename(pcap_file, alg)
        plt.savefig(plot_file, format='pdf', bbox_inches='tight')

def generate_plot_quic_csv(csv_file: str,
                           correct_brkps: Optional[list[int]] = None,
                           alg: Optional[Changepoint] = None,
                           min_size: Optional[int] = None,
                           jump: Optional[int] = None,
                           sigma: Optional[float] = None,
                           width: Optional[int] = None):
    print(f'--- GENERATING QUIC PLOT FOR {csv_file} ---')
    make_dirs(DIRS)

    res = read_csv_quic(csv_file)
    rtts, cum_acks = res['rtts'], res['cum_acks']

    plt.close('all')             # close all previously opened plots
    plt.scatter(rtts, cum_acks)  # generate scatterplot
    
    plt.xlabel('RTT')
    plt.ylabel('bytes acked')

    # # Plot correct changepoints
    # brkps = correct_brkps
    # for brkp in brkps:
    #     plt.axvline(x=rtts[brkp], color='k', linestyle='--')

    # Plot predicted changepoints
    if alg is not None:
        brkps = predict_changepoints(rtts, cum_acks, alg, min_size=min_size, 
                                    jump=jump, sigma=sigma, width=width)
        brkps = brkps[:-1]  # ignore last breakpoint
        for brkp in brkps:
            plt.axvline(x=rtts[brkp], color='g', linestyle='--')

    # Save plot as pdf file
    plot_file = get_plot_filename(csv_file, alg=alg)
    plt.savefig(plot_file, format='pdf', bbox_inches='tight')


# --- test quic ---
# file_name = './pcap/out-2024-12-04-03:42:03.json'
# generate_plot_quic(file_name)
