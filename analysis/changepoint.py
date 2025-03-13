import numpy as np
import ruptures as rpt
from typing import Optional
from enum import Enum

class Changepoint(Enum):
    """
    This class is an enum type for changepoint algorithms.
    """
    PELT = 0
    BINSEG = 1
    BOTTOMUP = 2
    WINDOW = 3
    CUSUM = 4

def predict_changepoints(x_vals: np.ndarray, y_vals: np.ndarray, alg: Changepoint) -> list:
    """ Runs the specified changepoint detection algorithm specified by @alg,
        on @x_vals and @y_vals.
    
    Args:
        x_vals (np.ndarray): 1-dimensional array of x-values.
        y_vals (np.ndarray): 1-dimensional array of y-values.
        alg (Changepoint): changepoint detection algorithm to be run.
        
    Returns:
        bkps (list): breakpoints (index into x_vals)
    """
    match alg:
        case Changepoint.PELT: return predict_changepoints_pelt(x_vals, y_vals)
        case Changepoint.BINSEG: return predict_changepoints_binseg(x_vals, y_vals)
        case Changepoint.BOTTOMUP: return predict_changepoints_bottomup(x_vals, y_vals)
        case Changepoint.WINDOW: return predict_changepoints_window(x_vals, y_vals)
        case _:  # invalid alg 
            print(f'[changepoint.py]: invalid @alg')
            return []

def predict_changepoints_pelt(x_vals: np.ndarray, y_vals: np.ndarray) -> list:
    """ Predict changepoints in 2-dimensional data using PELT
        (Pruned Exact Linear Time) algorithm (offline method).
    
    Args:
        x_vals (np.ndarray): 1-dimensional array of x-values.
        y_vals (np.ndarray): 1-dimensional array of y-values.
        
    Returns:
        bkps (list): breakpoints (index into x_vals)
    """
    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm (better for 2-dimensional data)
    algo = rpt.Pelt(model=model, min_size=20, jump=5).fit(signal)
    bkps = algo.predict(pen=10)
    return bkps

def predict_changepoints_binseg(x_vals: np.ndarray, y_vals: np.ndarray) -> list:
    """ Predict changepoints in 2-dimensional data using Binary
        Segmentation algorithm (offline method).
    
    Args:
        x_vals (np.ndarray): 1-dimensional array of x-values.
        y_vals (np.ndarray): 1-dimensional array of y-values.
        
    Returns:
        bkps (list): breakpoints (index into x_vals)
    """
    # Parameters for Binary Segmentation algorithm
    n = len(x_vals)
    dim = 2
    sigma = 10  #! Change this later

    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm (better for 2-dimensional data)
    algo = rpt.Binseg(model=model).fit(signal)
    bkps = algo.predict(pen=np.log(n) * dim * sigma**2)
    return bkps

def predict_changepoints_bottomup(x_vals: np.ndarray, y_vals: np.ndarray) -> list:
    """ Predict changepoints in 2-dimensional data using Bottom-up
        segmentation algorithm (offline method).
    
    Args:
        x_vals (np.ndarray): 1-dimensional array of x-values.
        y_vals (np.ndarray): 1-dimensional array of y-values.
        
    Returns:
        bkps (list): breakpoints (index into x_vals)
    """
    # Parameters for Bottom-up Segmentation algorithm
    n = len(x_vals)
    dim = 2
    sigma = 3  #! Change this later

    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm (better for 2-dimensional data)
    algo = rpt.BottomUp(model=model).fit(signal)
    bkps = algo.predict(pen=np.log(n) * dim * sigma**2)
    return bkps

def predict_changepoints_window(x_vals: np.ndarray, y_vals: np.ndarray) -> list:
    """ Predict changepoints in 2-dimensional data using Window-sliding
        segmentation algorithm (offline method).
    
    Args:
        x_vals (np.ndarray): 1-dimensional array of x-values.
        y_vals (np.ndarray): 1-dimensional array of y-values.
        
    Returns:
        bkps (list): breakpoints (index into x_vals)
    """
    # Parameters for Window-sliding Segmentation algorithm
    n = len(x_vals)
    dim = 2
    sigma = 3  #! Change this later
    width = 3  #! Change this later

    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm (better for 2-dimensional data)
    algo = rpt.Window(width=width, model=model).fit(signal)
    bkps = algo.predict(pen=np.log(n) * dim * sigma**2)
    return bkps
