import numpy as np
from bisect import bisect_left

def get_nearest_bkp(bkp: int, bkps_correct: list[int], x_vals: np.ndarray) -> tuple[int, int]:
    """ Given @bkp, returns the @elem in @bkps_correct such that 
        @x_vals[@bkp] - @elem is minimized.

    Args:
        bkp (int): breakpoint index
        bkps_correct (list): list of breakpoint indices
        
    Returns:
        value (int): @elem in @bkps_correct such that 
                     @x_vals[@bkp] - @elem is minimized.
    """
    N = len(bkps_correct)
    idx = bisect_left(bkps_correct, bkp)
    if (idx == 0):    # bkp is smaller than every element
        return bkps_correct[0]
    elif (idx == N):  # bkp is larger than every element
        return bkps_correct[N-1]
    else:             # check if bkp is closer to left or right
        left = bkps_correct[idx-1]
        right = bkps_correct[idx]
        if np.abs(x_vals[left] - x_vals[bkp]) <= np.abs(x_vals[right] - x_vals[bkp]):
            return left
        else:
            return right

def changepoint_loss(bkps_pred: list[int], bkps_correct: list[int], 
                     x_vals: np.ndarray) -> float:
    """ Returns the total absolute distance error of @bkps_pred against 
        @bkps_correct, using @x_vals as the distance metric.
    
    Args:
        bkps_pred (list[int]): predicted breakpoints
        bkps_correct (list[int]): correct breakpoints
        x_vals (np.ndarray): underlying x-values
        
    Returns:
        total_err (float): total absolute distance error (calculated from 
                           @x_vals) between each breakpoint in @bkps_pred 
                           to the nearest breakpoint in @bkps_correct
    """
    total_err = 0.0
    N = len(bkps_pred)
    for i in range(N):
        bkp = bkps_pred[i]
        (_, val) = get_nearest_bkp(bkp, bkps_correct)
        err = abs(x_vals[val] - x_vals[bkp])
        total_err += err
    return total_err
