# --- Import external libraries ---
import json
from typing import Optional, NamedTuple
from enum import Enum

# --- Constants ---
ACK_TYPE = '0x0000000000000002'

class ProtocolType(Enum):
    PROTOCOL_TCP  = 1
    PROTOCOL_QUIC = 2

# --- Helper Functions ---
def pcap_file_to_json(pcap_file: str):
    try: 
        with open(pcap_file) as f:
            d = json.load(f)
            return d
    except OSError:
        print(f'[ERROR] could not open file: {pcap_file}, exiting.')
        return None
    
def normalize_by_RTT(times: list[float], rtt: float) -> list[float]:
    return list(map(lambda t: t / rtt, times))
    
# --- Extract Data --- 
def get_rtt_static_tcp(pcap_file: str) -> Optional[float]:
    d = pcap_file_to_json(pcap_file)
    if not d:
        return None
    
    # We use TCP-provided initial RTT estimate
    initial_rtt = None
    for packet in d:
        tcp = packet['_source']['layers']['tcp']
        tcp_analysis = tcp.get('tcp.analysis')
        if (tcp_analysis is not None):
            tcp_analysis_initial_rtt = tcp_analysis.get('tcp.analysis.initial_rtt')
            if (tcp_analysis_initial_rtt is not None):
                initial_rtt = float(tcp_analysis_initial_rtt) * 1000  # [ms]
                break

    return initial_rtt

def get_rtt_static_quic(pcap_file: str) -> Optional[float]:
    d = pcap_file_to_json(pcap_file)
    if not d:
        return None

    # We sample initial RTT from Client Hello -> Server Hello
    initial_rtt = None
    for packet in d:
        layers = packet['_source']['layers']
        udp = layers.get('udp')
        if (udp is None):
            continue 

        time = float(udp['Timestamps']['udp.time_relative']) * 1000  # [ms]
        udp_srcport = int(udp['udp.srcport']) 
        is_incoming: bool = (udp_srcport == 443)

        if is_incoming:
            initial_rtt = time 
            break 
    return initial_rtt

class CumAckTime(NamedTuple):
    times: list[float]
    acks: list[int]
    cum_acks: list[int]

def get_cumack_tcp(pcap_file: str) -> Optional[CumAckTime]:
    d = pcap_file_to_json(pcap_file)
    if not d:
        return None
    
    acks: list[int]     = []
    cum_acks: list[int] = []
    times: list[float]  = []

    for packet in d:
        tcp = packet['_source']['layers']['tcp']

        tcp_srcport = int(tcp['tcp.srcport'])
        is_incoming: bool = (tcp_srcport == 443)  # incoming packet from server port 443
        is_outgoing: bool = not is_incoming
        is_fin: bool = (tcp['tcp.flags_tree']['tcp.flags.fin'] == '1')

        if (is_outgoing and not is_fin):  # we send ACK to server
            time = float(tcp['Timestamps']['tcp.time_relative']) * 1000  # [ms]
            ack = int(tcp['tcp.ack'])
            times.append(time)
            acks.append(ack)

            if (len(cum_acks) == 0):
                cum_acks.append(ack)
            else:
                cum_acks.append(cum_acks[-1] + ack)

    ret = CumAckTime(
        times = times, 
        acks = acks, 
        cum_acks = cum_acks,
    )
    return ret

def get_cumack_quic(pcap_file: str) -> Optional[CumAckTime]:
    d = pcap_file_to_json(pcap_file)
    if not d:
        return None
    
    acks: list[int]     = []
    cum_acks: list[int] = []
    times: list[float]  = []

    # {packet number : (bytes in flight, latest timestamp)}
    bif: dict[int, tuple[int, float]] = {}

    for packet in d:
        layers = packet['_source']['layers']
        udp = layers.get('udp')

        if (udp is None) or (quics is None):
            continue

        time = float(udp['Timestamps']['udp.time_relative']) * 1000  # [ms]
        udp_srcport = int(udp['udp.srcport']) 
        is_incoming: bool = (udp_srcport == 443)

        quics = layers.get('quic')
        if (type(quics) == dict): 
            quics = [quics]

        # Loop through each QUIC packet
        for quic in quics:
            if is_incoming:  # receive data from servers
                # Get packet number
                pkt_num : str = quic.get('quic.packet_number')
                if pkt_num is None:
                    quic_short = quic.get('quic.short')
                    if quic_short is not None:
                        pkt_num = quic_short.get('quic.packet_number')
                if pkt_num is None:
                    continue
                pkt_num : int = int(pkt_num)

                # Get packet length (size of payload in bytes)
                pkt_len : str = quic.get('quic.packet_length')
                if pkt_len is None:
                    continue
                pkt_len : int = int(pkt_len)

                # Update bytes-in-flight and timestamp
                if pkt_num not in bif:
                    bif[pkt_num] = (0, 0.0)  # default value
                updated_bif : int = bif[pkt_num][0] + pkt_len
                bif[pkt_num] = (updated_bif, time)

            else:  # send ACK to server
                frames = quic.get('quic.frame')
                if frames is None:
                    continue
                if (type(frames) == dict): 
                    frames = [frames]

                # Loop through each QUIC frame
                bytes_acked: int = 0
                for frame in frames:
                    if (frame['quic.frame_type'] == ACK_TYPE):
                        ack_target = int(frame['quic.ack.largest_acknowledged'])
                        ack_range  = int(frame['quic.ack.first_ack_range'])

                        # Calculate bytes ACKed by this ACK frame
                        for pkt_num in range(ack_target - ack_range, ack_target + 1):
                            if pkt_num in bif:  
                                (bytes_outstanding, _) = bif[pkt_num]
                                bytes_acked += bytes_outstanding
                                del bif[pkt_num]
                            else:
                                print(f'[ERROR] ACK sent for non-existing packet number {pkt_num}\n')

                times.append(time)
                acks.append(bytes_acked)
                if (len(cum_acks) == 0):
                    cum_acks.append(bytes_acked)
                else:
                    cum_acks.append(cum_acks[-1] + bytes_acked)
    
    ret = ret = CumAckTime(
        times = times, 
        acks = acks, 
        cum_acks = cum_acks,
    )
    return ret

class CumAckRTT(NamedTuple):
    times: list[float]
    acks: list[int]
    cum_acks: list[int]
    rtts: list[float]

def get_cumack_rtt(pcap_file: str, type: ProtocolType) -> Optional[CumAckRTT]:
    """ 
    This is the main exported function of this file. Given a PCAP file and 
    @type specifying whether the PCAP file holds TCP or QUIC traffic, this 
    function processes data and returns 4 lists: times (in ms), bytes ACKed, 
    cumulative bytes ACKed, and RTT-normalized times.
    """

    rtt: Optional[float] = None
    match type:
        case ProtocolType.PROTOCOL_TCP:  rtt = get_rtt_static_tcp(pcap_file)
        case ProtocolType.PROTOCOL_QUIC: rtt = get_rtt_static_quic(pcap_file)
    if (rtt is None):
        return None 
    
    cum_ack_times: Optional[CumAckTime] = None
    match type:
        case ProtocolType.PROTOCOL_TCP:  cum_ack_times = get_cumack_tcp(pcap_file)
        case ProtocolType.PROTOCOL_QUIC: cum_ack_times = get_cumack_quic(pcap_file)
    if (cum_ack_times is None):
        return None 
    
    times: list[float]  = cum_ack_times.times
    acks: list[int]     = cum_ack_times.acks 
    cum_acks: list[int] = cum_ack_times.cum_acks 
    assert(len(times) == len(acks))
    assert(len(times) == len(cum_acks))
    
    rtts: list[float] = normalize_by_RTT(times, rtt)
    ret = CumAckRTT(
        times = times, 
        acks = acks, 
        cum_acks = cum_acks, 
        rtts = rtts,
    )
    return ret
