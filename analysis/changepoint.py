import numpy as np
import ruptures as rpt
from typing import Optional
from enum import Enum
from utils.logging import *

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

def predict_changepoints_pelt(x_vals: np.ndarray, y_vals: np.ndarray,
                              min_size: Optional[int] = None, 
                              jump: Optional[int] = None) -> list:
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
    n = len(x_vals)

    if min_size is None:
        min_size = max(5, n // 10)
        min_size = min(20, min_size)
    
    if jump is None:
        jump = 5

    algo = rpt.Pelt(model=model, min_size=min_size, jump=jump).fit(signal)
    bkps = algo.predict(pen=10)
    return bkps

def predict_changepoints_binseg(x_vals: np.ndarray, y_vals: np.ndarray,
                                sigma: Optional[float] = None) -> list:
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
    
    # Provide default value for @sigma if None
    if sigma is None:
        sigma = 10.0 

    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm (better for 2-dimensional data)
    algo = rpt.Binseg(model=model).fit(signal)
    bkps = algo.predict(pen=np.log(n) * dim * sigma**2)
    return bkps

def predict_changepoints_bottomup(x_vals: np.ndarray, y_vals: np.ndarray,
                                  sigma: Optional[float] = None) -> list:
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

    # Provide default value for @sigma if None
    if sigma is None:
        sigma = 10.0

    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm (better for 2-dimensional data)
    algo = rpt.BottomUp(model=model).fit(signal)
    bkps = algo.predict(pen=np.log(n) * dim * sigma**2)
    return bkps

def predict_changepoints_window(x_vals: np.ndarray, y_vals: np.ndarray,
                                sigma: Optional[float] = None,
                                width: Optional[int] = None) -> list:
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

    # Provide default value for @sigma if None
    if sigma is None:
        sigma = 3.0

    # Provide default value for @width if None
    if width is None:
        width = 3 
        
    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm (better for 2-dimensional data)
    algo = rpt.Window(width=width, model=model).fit(signal)
    bkps = algo.predict(pen=np.log(n) * dim * sigma**2)
    return bkps
