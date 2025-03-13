import numpy as np
import ruptures as rpt

def predict_changepoints_pelt(x_vals: np.ndarray, y_vals: np.ndarray) -> list:
    """ Predict changepoints in 2-dimensional data using PELT
        (Pruned Exact Linear Time) algorithm.
    
    Args:
        x_vals (np.ndarray): 1-dimensional array of x-values.
        y_vals (np.ndarray): 1-dimensional array of y-values.
        
    Returns:
        bkps (list): breakpoints (index into x_vals)
    """
    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm (better for 2-dimensional data)
    algo = rpt.Pelt(model=model, min_size=3, jump=5).fit(signal)
    bkps = algo.predict(pen=10)
    return bkps

def predict_changepoints_binseg(x_vals: np.ndarray, y_vals: np.ndarray) -> list:
    """ Predict changepoints in 2-dimensional data using Binary
        Segmentation algorithm.
    
    Args:
        x_vals (np.ndarray): 1-dimensional array of x-values.
        y_vals (np.ndarray): 1-dimensional array of y-values.
        
    Returns:
        bkps (list): breakpoints (index into x_vals)
    """
    # Parameters for Binary Segmentation algorithm
    n = len(x_vals)
    dim = 2
    sigma = 3  #! Change this later

    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm (better for 2-dimensional data)
    algo = rpt.Binseg(model=model).fit(signal)
    bkps = algo.predict(pen=np.log(n) * dim * sigma**2)
    return bkps
