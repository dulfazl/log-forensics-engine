import numpy as np
import pytest

from models import AnomalyDetector, SeverityClassifier

# Two tight, obvious clusters.
LOW = [[0.0, 0.0], [0.1, 0.0], [0.0, 0.1], [0.1, 0.1], [0.05, 0.05]]
HIGH = [[10.0, 10.0], [10.1, 10.0], [10.0, 10.1], [10.1, 10.1], [10.05, 10.05]]


def test_classifier_needs_training():
    clf = SeverityClassifier(k=3)
    assert clf.predict([0, 0]) is None
    assert clf.predict_batch([[0, 0]]) == [None]
    assert clf.retrain() is False


def test_classifier_obvious_neighbours():
    clf = SeverityClassifier(k=3, window_size=100)
    for x in LOW:
        clf.add_labeled(x, "INFO")
    for x in HIGH:
        clf.add_labeled(x, "ERROR")
    assert clf.retrain()
    assert clf.predict([0.02, 0.03]) == "INFO"
    assert clf.predict([9.9, 10.2]) == "ERROR"
    assert clf.predict_batch([[0, 0], [10, 10]]) == ["INFO", "ERROR"]


def test_classifier_scales_features():
    # Feature 0 is huge and irrelevant; feature 1 decides the label. Without
    # scaling, distance would be dominated by feature 0.
    clf = SeverityClassifier(k=1)
    clf.add_labeled([1000.0, 0.0], "INFO")
    clf.add_labeled([5000.0, 1.0], "ERROR")
    clf.add_labeled([9000.0, 0.0], "INFO")
    clf.retrain()
    assert clf.predict([5000.0, 0.0]) == "INFO"


def test_classifier_window_is_bounded():
    clf = SeverityClassifier(k=1, window_size=4)
    for i in range(100):
        clf.add_labeled([i, i], "INFO")
    assert len(clf.X_window) == 4 and clf.X_window[0] == [96, 96]


def test_classifier_evaluate():
    clf = SeverityClassifier(k=3)
    for x in LOW:
        clf.add_labeled(x, "INFO")
    for x in HIGH:
        clf.add_labeled(x, "ERROR")
    clf.retrain()
    report = clf.evaluate([[0, 0], [10, 10], [0.1, 0.1]], ["INFO", "ERROR", "ERROR"])
    assert report["accuracy"] == pytest.approx(2 / 3)
    cm = np.array(report["confusion_matrix"])
    labels = report["labels"]
    assert cm[labels.index("ERROR"), labels.index("INFO")] == 1
    assert cm.sum() == 3


def test_detector_threshold_excludes_self_match():
    det = AnomalyDetector(k=2, threshold_percentile=100)
    det.fit(LOW)
    # With the self-match kept, every point's nearest distance would be 0
    # and the threshold would be far smaller than the real spacing.
    assert det.threshold > 0.5
    assert det.baseline_distances.min() > 0


def test_detector_scores_obvious_points():
    det = AnomalyDetector(k=2, threshold_percentile=95)
    det.fit(LOW + [[0.02, 0.08], [0.07, 0.02]])
    near, d_near = det.score([0.05, 0.06])
    far, d_far = det.score([5.0, 5.0])
    assert not near and far
    assert d_far > det.threshold > d_near
    flags, dists = det.score_batch([[0.05, 0.06], [5.0, 5.0]])
    assert flags.tolist() == [False, True]
    assert dists[1] == pytest.approx(d_far)


def test_detector_requires_fit():
    with pytest.raises(RuntimeError):
        AnomalyDetector().score([0, 0])
    with pytest.raises(ValueError):
        AnomalyDetector().fit([[1, 2]])


def test_explain_names_the_feature_that_differs():
    det = AnomalyDetector(k=2)
    det.fit([[0.0, float(i % 3)] for i in range(30)])
    top = det.explain([25.0, 1.0], ["rate", "length"])
    assert top[0][0] == "rate" and top[0][1] > 0


def test_refresh_baseline_rejects_attack_points():
    rng = np.random.default_rng(0)
    base = rng.normal(0, 1, size=(200, 2))
    det = AnomalyDetector(k=5, threshold_percentile=99)
    det.fit(base)
    before = len(det.baseline_raw)
    normal_new = rng.normal(0, 1, size=(50, 2))
    attack = np.full((50, 2), 25.0) + rng.normal(0, 0.1, size=(50, 2))
    accepted = det.refresh_baseline(np.vstack([normal_new, attack]))
    assert 0 < accepted <= 50
    assert len(det.baseline_raw) == before + accepted
    assert det.baseline_raw.max() < 10  # no attack point got in
    assert det.score([25.0, 25.0])[0]   # attack still anomalous after refresh


def test_refresh_respects_max_baseline():
    det = AnomalyDetector(k=3, max_baseline=100)
    det.fit(np.random.default_rng(1).normal(size=(100, 2)))
    det.refresh_baseline(np.random.default_rng(2).normal(size=(80, 2)))
    assert len(det.baseline_raw) == 100


def test_set_threshold_percentile():
    det = AnomalyDetector(k=2, threshold_percentile=50)
    det.fit(np.random.default_rng(3).normal(size=(100, 2)))
    t50 = det.threshold
    det.set_threshold_percentile(99)
    assert det.threshold > t50
