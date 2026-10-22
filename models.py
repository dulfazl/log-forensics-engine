"""
models.py

Two KNN models.

SeverityClassifier
    KNeighborsClassifier over a sliding window of (features, seed label)
    pairs, with a StandardScaler fitted at retrain time so that a feature
    measured in hundreds (message length) does not drown out 0/1 flags.

AnomalyDetector
    NearestNeighbors fitted on a baseline window assumed to be mostly
    normal. A record's score is its mean distance to the k nearest
    baseline points (in standardized space); it is anomalous when that
    exceeds a threshold taken from a percentile of the baseline's own
    k-distances.

Why a sliding-window refit instead of "online" KNN
    KNN is a lazy learner: "training" is just storing the points and
    building a search index (a KD-tree, ball tree or brute-force matrix).
    scikit-learn's KNeighborsClassifier and NearestNeighbors have no
    partial_fit, and their index is immutable once built, so adding one
    point means rebuilding it. The StandardScaler's mean and variance
    would also shift with every point. The practical compromise is to
    keep the most recent W points in a bounded deque and refit every R
    records: memory stays O(W), cost is one O(W log W) rebuild per R
    records, and the model follows drift with a lag of at most R records.
"""

from collections import deque

import numpy as np
from sklearn.metrics import confusion_matrix
from sklearn.neighbors import KNeighborsClassifier, NearestNeighbors
from sklearn.preprocessing import StandardScaler

SEVERITY_LABELS = ["CRITICAL", "ERROR", "WARNING", "INFO"]


class SeverityClassifier:
    def __init__(self, k=5, window_size=500):
        self.k = k
        self.window_size = window_size
        self.X_window = deque(maxlen=window_size)
        self.y_window = deque(maxlen=window_size)
        self.scaler = None
        self.model = None
        self.retrain_count = 0

    def add_labeled(self, features, label):
        """Append one example; the oldest falls out once the window is full."""
        self.X_window.append(list(features))
        self.y_window.append(label)

    def retrain(self):
        """Refit scaler + KNN on the current window. False if too little data."""
        if len(self.X_window) < max(2, min(self.k, self.window_size)):
            return False
        X = np.asarray(self.X_window, dtype=float)
        y = np.asarray(self.y_window)
        self.scaler = StandardScaler().fit(X)
        self.model = KNeighborsClassifier(n_neighbors=min(self.k, len(X)))
        self.model.fit(self.scaler.transform(X), y)
        self.retrain_count += 1
        return True

    @property
    def is_trained(self):
        return self.model is not None

    def predict(self, features):
        if self.model is None:
            return None
        return self.predict_batch([features])[0]

    def predict_batch(self, X):
        """Predict many rows with one kneighbors call (much faster than a
        Python loop over predict)."""
        if self.model is None:
            return [None] * len(X)
        Xs = self.scaler.transform(np.asarray(X, dtype=float))
        return [str(label) for label in self.model.predict(Xs)]

    def evaluate(self, X, y):
        """Accuracy and confusion matrix (rows = true, cols = predicted,
        order SEVERITY_LABELS plus any unexpected labels) against `y`."""
        if self.model is None or len(X) == 0:
            return {"accuracy": None, "n": len(X), "labels": SEVERITY_LABELS,
                    "confusion_matrix": None}
        y_true = [str(v) for v in y]
        y_pred = self.predict_batch(X)
        labels = SEVERITY_LABELS + sorted(set(y_true) - set(SEVERITY_LABELS))
        cm = confusion_matrix(y_true, y_pred, labels=labels)
        accuracy = float(np.mean([a == b for a, b in zip(y_true, y_pred)]))
        return {"accuracy": accuracy, "n": len(y_true), "labels": labels,
                "confusion_matrix": cm.tolist()}


class AnomalyDetector:
    def __init__(self, k=5, threshold_percentile=99.5, max_baseline=5000,
                 refresh_accept_percentile=75.0):
        self.k = k
        self.threshold_percentile = threshold_percentile
        self.max_baseline = max_baseline
        self.refresh_accept_percentile = refresh_accept_percentile
        self.baseline_raw = None   # unscaled baseline, kept to refit the scaler
        self.baseline = None       # standardized baseline
        self.scaler = None
        self.nn_model = None
        self.threshold = None
        self.baseline_distances = None
        self.refresh_count = 0

    @property
    def is_fitted(self):
        return self.nn_model is not None

    def fit(self, baseline_features):
        """
        Fit on a baseline (rows of features), standardizing first so no
        single raw feature dominates the Euclidean distance. The threshold
        is data-driven: a percentile of the baseline's own k-distances.
        """
        raw = np.asarray(baseline_features, dtype=float)
        if raw.ndim != 2 or len(raw) < 2:
            raise ValueError("AnomalyDetector.fit needs at least 2 baseline rows")
        raw = raw[-self.max_baseline:]
        self.baseline_raw = raw
        self.scaler = StandardScaler().fit(raw)
        self.baseline = self.scaler.transform(raw)
        self.nn_model = NearestNeighbors(n_neighbors=min(self.k, len(raw)))
        self.nn_model.fit(self.baseline)

        # Score the baseline against itself. Each point's nearest neighbour
        # is itself at distance 0, which would deflate the threshold, so we
        # ask for k+1 neighbours and drop column 0 (the self-match). With
        # exact duplicates the dropped 0 may belong to a twin instead of
        # the point itself; the result is identical either way.
        n_self = min(self.k + 1, len(self.baseline))
        distances, _ = self.nn_model.kneighbors(self.baseline, n_neighbors=n_self)
        self.baseline_distances = distances[:, 1:].mean(axis=1)
        self.threshold = float(np.percentile(self.baseline_distances,
                                             self.threshold_percentile))
        return self

    def set_threshold_percentile(self, percentile):
        """Move the threshold without refitting the index."""
        self.threshold_percentile = percentile
        if self.baseline_distances is not None:
            self.threshold = float(np.percentile(self.baseline_distances, percentile))

    def _require_fit(self):
        if self.nn_model is None:
            raise RuntimeError("AnomalyDetector.fit() must be called before scoring")

    def score(self, features):
        """(is_anomalous, mean k-distance) for one feature vector."""
        flags, distances = self.score_batch([features])
        return bool(flags[0]), float(distances[0])

    def score_batch(self, X):
        """Vectorised score: (bool array, distance array) for many rows."""
        self._require_fit()
        Xs = self.scaler.transform(np.asarray(X, dtype=float))
        distances, _ = self.nn_model.kneighbors(Xs)
        mean = distances.mean(axis=1)
        return mean > self.threshold, mean

    def explain(self, features, names):
        """
        Which feature pushed this point away from its neighbours most?
        Returns [(name, standardized difference)] sorted by magnitude,
        comparing the point to the mean of its k nearest baseline points.
        """
        self._require_fit()
        xs = self.scaler.transform(np.asarray([features], dtype=float))
        _, idx = self.nn_model.kneighbors(xs)
        diff = xs[0] - self.baseline[idx[0]].mean(axis=0)
        order = np.argsort(-np.abs(diff))
        return [(names[i], float(diff[i])) for i in order]

    def refresh_baseline(self, new_features):
        """
        Fold recent traffic into the baseline to follow drift, accepting
        ONLY points the current model scores as normal, so an attack that
        is being flagged cannot drag "normal" towards itself.

        "Normal" here is stricter than "below the threshold": a point must
        sit within the refresh_accept_percentile (default 75th) of the
        baseline's own k-distances. Measured on the synthetic data (5 seeds
        x 3,000 lines), accepting everything below the threshold let
        borderline slow brute-force attempts leak in, and each refresh made
        the next attempts look more normal: slow_bruteforce recall fell
        from 0.60 (no refresh) to 0.33. With the 75th-percentile cut-off it
        is 0.62. A patient enough attacker can still poison any
        self-updating baseline, which is why refresh is optional
        (refresh_every=0 disables it in the engine).

        The baseline stays capped at max_baseline rows (oldest dropped).
        Returns the number of points accepted.
        """
        if new_features is None or len(new_features) == 0:
            return 0
        self._require_fit()
        X = np.asarray(new_features, dtype=float)
        _, distances = self.score_batch(X)
        cutoff = min(self.threshold, float(np.percentile(self.baseline_distances,
                                                         self.refresh_accept_percentile)))
        accepted = X[distances <= cutoff]
        if len(accepted) == 0:
            return 0
        self.fit(np.vstack([self.baseline_raw, accepted]))
        self.refresh_count += 1
        return int(len(accepted))
