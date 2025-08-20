from analysis.changepoint import *
from ruptures.metrics import precision_recall, hausdorff, randindex
from typing import Optional, Tuple

"""
Docs: 
- https://centre-borelli.github.io/ruptures-docs/user-guide/metrics/precisionrecall/
- https://centre-borelli.github.io/ruptures-docs/user-guide/metrics/hausdorff/
- https://centre-borelli.github.io/ruptures-docs/user-guide/metrics/randindex/
"""

# the higher the better
def compute_f1_score(precision: float, recall: float) -> float:
    return (2 * precision * recall) / (precision + recall)

def grid_search_p(x_vals: np.ndarray, y_vals: np.ndarray, true_bkps: list, 
                  cda_type: CDAType) -> Tuple[float, float]:
    NUMBER_ITERS = 1e4
    max_x = np.max(x_vals)
    max_y = np.max(y_vals)
    max_p = max(max_x, max_y)

    best_p: Optional[float] = None
    best_f1_score: Optional[float] = None

    for i in range(1, NUMBER_ITERS + 1):
        p = i * (max_p / NUMBER_ITERS)

        match cda_type:
            case CDAType.PELT: my_bkps = get_cp_pelt(x_vals, y_vals, p)
            case CDAType.BINSEG: my_bkps = get_cp_binseg(x_vals, y_vals, p)
            case CDAType.BOTTOMUP: my_bkps = get_cp_bottomup(x_vals, y_vals, p)
            case _: 
                print('[ERROR]: invalid CDA type provided to grid_search_p\n')
                assert(False)  # panic
        
        precision, recall = precision_recall(true_bkps, my_bkps, margin=5)
        f1_score = compute_f1_score(precision, recall)

        if (best_f1_score is None) or (f1_score > best_f1_score):
            best_f1_score = f1_score 
            best_p = p 

    return (best_p, best_f1_score)

def grid_search_p_width(x_vals: np.ndarray, y_vals: np.ndarray, true_bkps: list, 
                        cda_type: CDAType) -> Tuple[float, float]:
    NUMBER_ITERS_P = 1e4
    NUMBER_ITERS_WIDTH = 1e2

    max_width = len(x_vals)
    max_x = np.max(x_vals)
    max_y = np.max(y_vals)
    max_p = max(max_x, max_y)

    best_p: Optional[float] = None
    best_width: Optional[int] = None
    best_f1_score: Optional[float] = None

    for i in range(1, NUMBER_ITERS_P + 1):
        for j in range(1, NUMBER_ITERS_WIDTH + 1):
            p     = i * (max_p / NUMBER_ITERS_P)
            width = j * (max_width // NUMBER_ITERS_WIDTH)

            match cda_type:
                case CDAType.WINDOW: my_bkps = get_cp_window(x_vals, y_vals, p)
                case _: 
                    print('[ERROR]: invalid CDA type provided to grid_search_p_width\n')
                    assert(False)  # panic

            precision, recall = precision_recall(true_bkps, my_bkps, margin=5)
            f1_score = compute_f1_score(precision, recall)

            if (best_f1_score is None) or (f1_score > best_f1_score):
                best_f1_score = f1_score 
                best_p = p 
                best_width = width 

    return (best_p, best_width, best_f1_score)
