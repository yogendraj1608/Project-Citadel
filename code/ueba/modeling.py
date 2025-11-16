import numpy as np
from sklearn.ensemble import IsolationForest

def per_user_iforest_scores(df, X, min_events=30, contamination=0.03, n_estimators=200, random_state=42):
    scores = np.zeros(len(df))
    for u, idx in df.groupby("user").indices.items():
        rows = np.array(list(idx))
        if rows.size < min_events:
            scores[rows] = 0.3
            continue
        Xi = X.iloc[rows].values
        clf = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=random_state)
        clf.fit(Xi)
        s = clf.decision_function(Xi) 
        s = (s - s.min()) / (s.max() - s.min() + 1e-9)
        scores[rows] = 1.0 - s        
    return scores
