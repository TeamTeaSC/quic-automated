import numpy as np
import ruptures as rpt

def predict_changepoints(signal: np.ndarray):
    model = "l1"  # "l2", "rbf"
    algo = rpt.Pelt(model=model, min_size=3, jump=5).fit(signal)
    bkps = algo.predict(pen=3)
    return bkps