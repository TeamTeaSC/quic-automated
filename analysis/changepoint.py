import numpy as np
import ruptures as rpt
from utils.logging import *

class CDAType(Enum):
    PELT     = 1
    BINSEG   = 2
    BOTTOMUP = 3
    WINDOW   = 4
    CUSUM    = 5
        
def post_process_changepoints(x_vals: np.ndarray, y_vals: np.ndarray, 
                              bkps: list) -> list:
    n = len(bkps)
    slopes = []
    for i in range(n):
        bkp = bkps[i]
        slope = (y_vals[bkp] - y_vals[bkp - 1]) / (x_vals[bkp] - x_vals[bkp - 1])
        slopes.append(slope)

    remove = set()
    threshold = 100000
    for i in range(len(slopes) - 1):
        if (abs(slopes[i] - slopes[i + 1]) < threshold):
            remove.add(i)

    post_process_bkps = []
    for i in range(n):
        if i not in remove: 
            post_process_bkps.append(bkps[i])
    
    print(slopes)
    print(remove)

    return post_process_bkps

def get_cp_pelt(x_vals: np.ndarray, y_vals: np.ndarray, p: float) -> list:
    """
    Docs: https://centre-borelli.github.io/ruptures-docs/user-guide/detection/pelt/
    """
    signal = np.column_stack((x_vals, y_vals))
    model = 'l1'
    n = len(x_vals)

    algo = rpt.Pelt(model=model, min_size=3, jump=5).fit(signal)
    my_bkps = algo.predict(pen=p * np.log(n))
    return my_bkps

def get_cp_binseg(x_vals: np.ndarray, y_vals: np.ndarray, p: float) -> list:
    """ 
    Docs: https://centre-borelli.github.io/ruptures-docs/user-guide/detection/binseg/
    """
    signal = np.column_stack((x_vals, y_vals))
    model = 'l2'
    n = len(x_vals)
    dim = 2
    
    algo = rpt.Binseg(model=model).fit(signal)
    my_bkps = algo.predict(pen=np.log(n) * dim * p**2)
    return my_bkps

def get_cp_bottomup(x_vals: np.ndarray, y_vals: np.ndarray, p: float) -> list:
    """
    Docs: https://centre-borelli.github.io/ruptures-docs/user-guide/detection/bottomup/
    """
    signal = np.column_stack((x_vals, y_vals))
    model = 'l2'
    n = len(x_vals)
    dim = 2
    
    algo = rpt.BottomUp(model=model).fit(signal)
    my_bkps = algo.predict(pen=np.log(n) * dim * p**2)
    return my_bkps

def get_cp_window(x_vals: np.ndarray, y_vals: np.ndarray, p: float, width: int) -> list:
    """
    Docs: https://centre-borelli.github.io/ruptures-docs/user-guide/detection/window/
    """
    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # "l1", "rbf", "linear", "normal", "ar"
    n = len(x_vals)
    dim = 2

    algo = rpt.Window(width=width, model=model).fit(signal)
    my_bkps = algo.predict(pen=np.log(n) * dim * p**2)
    return my_bkps

def get_cp_cusum(x_vals: np.ndarray, y_vals: np.ndarray, threshold: float = 28.0, 
                 drift: float = 1.0) -> list:
    # Initialize parameters for CUSUM
    y_len  = len(y_vals)
    y_mean = np.mean(y_vals)
    y_std  = np.std(y_vals)

    drift = 1.0
    threshold = 10.0
    
    # Initialize cumulative sums in positive and negative directions
    s_pos = np.zeros(y_len)
    s_neg = np.zeros(y_len)

    # Initialize array of changepoints
    bkps = []

    for i in range(1, y_len):
        s_pos[i] = max(0, s_pos[i-1] + (y_vals[i] - y_mean) / y_std - drift)
        s_neg[i] = max(0, s_neg[i-1] - (y_vals[i] - y_mean) / y_std - drift)
        
        # Check if cumulative sums have exceeded threshold
        if (s_pos[i] > threshold) or (s_neg[i] > threshold):
            # Predict changepoint
            bkps.append(i)

            # Reset cumulative sums
            s_pos[i] = 0
            s_neg[i] = 0 
    
    # bkps = post_process_changepoints(x_vals, y_vals, bkps)
    return bkps
