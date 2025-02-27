import numpy as np
import ruptures as rpt

def predict_changepoints(x_vals: np.ndarray, y_vals: np.ndarray):
    signal = np.column_stack((x_vals, y_vals))
    model = "l2"  # use L2 norm
    algo = rpt.Pelt(model=model, min_size=3, jump=5).fit(signal)
    bkps = algo.predict(pen=3)
    return bkps