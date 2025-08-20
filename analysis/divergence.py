from typing import Optional, Tuple
from analysis.analyze import *
from analysis.changepoint import *
from analysis.polyfit import *

def get_poly_mse(poly1: np.ndarray, poly2: np.ndarray) -> float:
    """
    Computes the MSE of the coefficients of 2 equal-degree polynomials.
    """
    assert(len(poly1) == len(poly2))
    total_sq_err: float = 0.0
    n = len(poly1)
    for i in range(n):
        coeff1, coeff2 = poly1[i], poly2[i]
        total_sq_err += (coeff1 - coeff2)**2
    mse : float = total_sq_err / n
    return mse

class DivergenceResults(NamedTuple):
    is_different:   bool 
    msg:            str
    div_start_idx:  Optional[int]

def check_divergence(pcap_file1: str, pcap_file2: str) -> DivergenceResults:
    # Get cumulative bytes ACKed vs RTT
    cumack_rtt1: CumAckRTT = get_cumack_rtt(pcap_file1, ProtocolType.PROTOCOL_QUIC)
    cumack_rtt2: CumAckRTT = get_cumack_rtt(pcap_file2, ProtocolType.PROTOCOL_QUIC)

    # Get changepoints
    P = 1.2  # penalty factor for PELT changepoint detection algorithm
    MARGIN = 5.0  # MSE between 2 polys must be greater than this

    rtts1, cum_acks1, times1 = cumack_rtt1.rtts, cumack_rtt1.cum_acks, cumack_rtt1.times
    rtts1, cum_acks1 = np.ndarray(rtts1), np.ndarray(cum_acks1)
    brkps1 = get_cp_pelt(rtts1, cum_acks1, P)

    rtts2, cum_acks2, times2 = cumack_rtt2.rtts, cumack_rtt2.cum_acks, cumack_rtt2.times
    rtts2, cum_acks2 = np.ndarray(rtts2), np.ndarray(cum_acks2)
    brkps2 = get_cp_pelt(rtts2, cum_acks2, P)

    ret = DivergenceResults(
        is_different = False,
        msg = f'the two traces are the same!',
        div_start_idx = None,
    )

    if (len(brkps1) != len(brkps2)):  # number of segments is different
        num_segs1, num_segs2 = len(brkps1), len(brkps2)
        ret = DivergenceResults(
            is_different = True, 
            msg = f'number of segments for pcap_file1 is {num_segs1}, pcap_file2 is {num_segs2}',
            div_start_idx = None, 
        )
    else:
        # Perform segment-by-segment comparison
        if (len(brkps1) != 0): brkps1 = brkps1[:-1]
        if (len(brkps2) != 0): brkps2 = brkps2[:-1]
        polys1: list[np.ndarray] = get_best_polys(rtts1, cum_acks1, brkps1)
        polys2: list[np.ndarray] = get_best_polys(rtts2, cum_acks2, brkps2)
        assert(len(polys1) == len(polys2))

        for i in range(len(polys1)):
            poly1, poly2 = polys1[i], polys2[i]
            num_coeff1, num_coeff2 = len(poly1), len(poly2)
            if (num_coeff1 != num_coeff2):
                ret = DivergenceResults(
                    is_different = True,
                    msg = f'polynomial degree for pcap_file1 is {num_coeff1 - 1}, '
                          f'pcap_file2 is {num_coeff2 - 1}',
                    div_start_idx = i
                )
                break
            
            mse: float = get_poly_mse(poly1, poly2)
            if (mse >= MARGIN):
                ret = DivergenceResults(
                    is_different = True,
                    msg = f'polynomial for pcap_file1 is {poly1}, pcap_file2 is {poly2}, '
                          f'MSE of coefficients is {mse} >= margin {MARGIN}',
                    div_start_idx = i
                )
                break

    return ret
