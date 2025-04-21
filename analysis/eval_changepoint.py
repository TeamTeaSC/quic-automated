import numpy as np
from bisect import bisect_left
from analysis.changepoint import *

def get_nearest_bkp(bkp: int, bkps_correct: list[int], x_vals: np.ndarray) -> int:
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

        if right >= len(x_vals):
            return left

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
    # Compute total distance error on the space @x_vals
    total_err = 0.0
    N = len(bkps_correct)
    for i in range(N):
        bkp = bkps_correct[i]
        val = get_nearest_bkp(bkp, bkps_pred, x_vals)
        err = abs(x_vals[val] - x_vals[bkp])
        total_err += err

    # Penalize predicting too many breakpoints
    n_pred = len(bkps_pred)
    n_correct = len(bkps_correct)
    penalty_factor = 1.0
    penalty = penalty_factor * np.abs(n_pred - n_correct)

    return total_err + penalty

def best_params_pelt(x_vals: np.ndarray, y_vals: np.ndarray, 
                     bkps_correct: list[int]) -> tuple[float, int, int]:
    N = len(x_vals)

    # Keep track of best error and parameters encountered so far
    best_err = None
    best_min_size = None
    best_jump = None
    
    for min_size in range(1, N//4):  # try different values for min_size
        for jump in range(1, 20):    # try different values for jump
            print(f'trying min_size = {min_size}, jump = {jump}')
            bkps_pred = predict_changepoints_pelt(x_vals, y_vals, 
                            min_size=min_size, jump=jump)
            bkps_pred = bkps_pred[:-1]  # discard last item
            err = changepoint_loss(bkps_pred, bkps_correct, x_vals)
            print(f'err is = {err}')

            # Save best error and parameters
            if (best_err is None) or (err <= best_err):
                best_err = err
                best_min_size = min_size
                best_jump = jump

    # Return best parameters
    return (best_err, best_min_size, best_jump)

def best_params_binseg(x_vals: np.ndarray, y_vals: np.ndarray, 
                       bkps_correct: list[int]) -> tuple[float, float]:
    N = len(x_vals)

    # Keep track of best error and parameters encountered so far
    best_err = None
    best_sigma = None

    delta = 10000
    num_iters = 100
    for i in range(1, num_iters + 1):
        sigma = i * delta
        bkps_pred = predict_changepoints_binseg(x_vals, y_vals, sigma=sigma)
        err = changepoint_loss(bkps_pred, bkps_correct, x_vals)

        # Save best error and parameters
        if (best_err is None) or (err <= best_err):
            best_err = err
            best_sigma = sigma
    
    # Return best parameters
    return (best_err, best_sigma)

def best_params_bottomup(x_vals: np.ndarray, y_vals: np.ndarray, 
                         bkps_correct: list[int]) -> tuple[float, float]:
    N = len(x_vals)

    # Keep track of best error and parameters encountered so far
    best_err = None
    best_sigma = None

    delta = 10000
    num_iters = 100
    for i in range(1, num_iters + 1):
        sigma = i * delta
        bkps_pred = predict_changepoints_bottomup(x_vals, y_vals, sigma=sigma)
        err = changepoint_loss(bkps_pred, bkps_correct, x_vals)

        # Save best error and parameters
        if (best_err is None) or (err <= best_err):
            best_err = err
            best_sigma = sigma
    
    # Return best parameters
    return (best_err, best_sigma)

def best_params_window(x_vals: np.ndarray, y_vals: np.ndarray, 
                         bkps_correct: list[int]) -> tuple[float, float, int]:
    N = len(x_vals)

    # Keep track of best error and parameters encountered so far
    best_err = None
    best_sigma = None
    best_width = None

    delta = 0.1
    num_iters = 100
    for i in range(1, num_iters + 1):
        sigma = i * delta
        for width in range(1, N//4):
            print(f'Trying sigma: {sigma}, width: {width}')
            try:
                bkps_pred = predict_changepoints_window(x_vals, y_vals, sigma=sigma,
                                                        width=width)
            except:
                continue
            err = changepoint_loss(bkps_pred, bkps_correct, x_vals)

            # Save best error and parameters
            if (best_err is None) or (err <= best_err):
                best_err = err
                best_sigma = sigma
                best_width = width
    
    # Return best parameters
    return (best_err, best_sigma, best_width)
