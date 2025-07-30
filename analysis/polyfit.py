import numpy as np 
from typing import Optional

def eval_poly(x : float, p : np.ndarray, deg : int) -> float:
    """
    Given a polynomial with coefficients specified by @p and degree @d, 
    evaluate it at @x. 

    Args:
        x (float):       x-value to evaluate polynomial @p at. 
        p (np.ndarray):  coefficients of polynomial, with highest degree first.
        deg (int):       degree of polynomial.

    Return:
        float: value of polynomial @p evaluated at @x, i.e. 
               p[0] * x**deg + p[1] * x**(deg-1) + ... + p[deg]
    """
    # Sanity checks 
    assert(len(p) == deg + 1)

    val : float = 0
    for i in range(deg + 1):
        val += (x**(deg - i)) * p[i]
    return val

def get_poly_mse(xs, ys, p: np.ndarray, deg: int) -> float:
    """
    Returns the mean-squared error (MSE) of polynomial @p with degree @d, 
    evaluated on points @xs, compared against ground truth values @ys. 

    Args:
        xs (list):       list of values to evaluate polynomial @p on.
        ys (list):       list of ground truth values. 
        p (np.ndarray):  coefficients of polynomial, with highest degree first.
        deg (int):       degree of polynomial.

    Return:
        float: mean-squared error (MSE) of polynomial @p w.r.t (@xs, @ys)
    """
    # Sanity checks 
    assert(len(p) == deg + 1)
    assert(len(xs) == len(ys))

    err : float = 0.0
    N : int = len(xs) 
    for i in range(N):
        x = xs[i]
        actual : float = ys[i]
        predict : float = eval_poly(x, p, deg)
        err += (actual - predict)**2
    return (err / N)

def correct_poly_error(mse: float, p: np.ndarray, deg: int, l: float) -> float:
    """
    Adjusts the mean squared error @mse to penalize higher-degree polynomials 
    to prevent overfitting. @l is a hyperparameter (higher @l indicates higher 
    penalty for higher degrees).

    Args:
        mse (float):     mean-squared error of polynomial @p.
        p (np.ndarray):  coefficients of polynomial, with highest degree first.
        deg (int):       degree of polynomial.
        l (float):       penalty factor for higher degree polynomials.
    Return:
        float: adjusted error, i.e. MSE + l * deg * (sum of coefficients of p).
    """
    # Sanity checks 
    assert(len(p) == deg + 1)

    return mse + l * deg * np.sum(p)

def get_best_polys(x, y, brkps, poly_max_deg_plus_1 : int = 4, l : float = 0.7):
    """
    Returns a list of best polynomials (with minimum error) for each segment, 
    i.e. (@x, @y) segmented by breakpoints @brkps. 

    Args:
        x (list):                   x-values. 
        y (list):                   y-values.
        brkps (list):               breakpoints (indices into @x and @y).
        poly_max_deg_plus_1 (int):  1 + maximum degree polynomial to fit
        l (float):                  penalty factor for higher degree polynomials

    Return:
        list[np.ndarray]: list of best polynomial (with minimum error) for 
                          each segment.
    """
    # Sanity checks 
    assert(len(x) == len(y))

    best_polys = []

    # Iterate through each segment
    start = 0
    for i in range(len(brkps) + 1):
        # x and y values in segment
        if (i == len(brkps)):
            xs = x[start:]
            ys = y[start:]
        else:
            xs = x[start:brkps[i]]
            ys = y[start:brkps[i]]
        start = brkps[i]

        # Iterate through degrees [1, poly_max_deg_plus_1) and find 
        # polynomial that minimizes error for this segment.
        min_error : Optional[float] = None
        best_poly : np.ndarray
        for deg in range(1, poly_max_deg_plus_1):
            p : np.ndarray = np.polyfit(x, y)
            mse : float = get_poly_mse(xs, ys, p, deg)
            err : float = correct_poly_error(mse, p, deg, l)
            if (min_error is None) or err < min_error:
                min_error = err
                best_poly = p 
        best_polys.append(best_poly)
    
    return best_polys
