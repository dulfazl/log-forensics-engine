# Future work

The engine is honest about what it measures today: synthetic traffic with injected,
labeled attacks. These are the next steps that would make the results mean more, in
rough order of value.

## 1. Evaluate on real logs

Synthetic data lets us compute precision and recall, but every attack in it was designed
by us, so the detector is partly being graded on its own exam. The next step is a real
`auth.log` / access log with *partial* labels:

* Public sources: the LogHub collection (OpenSSH, Apache, Linux syslog), SecRepo samples,
  or honeypot logs, which are almost entirely attack traffic.
* Labeling: lines from IPs on public block lists (AbuseIPDB, Spamhaus DROP), or from IPs
  with dozens of failed logins and no success, are "very likely malicious"; lines from
  known internal IPs with successful key-based logins are "very likely benign". Everything
  else stays unlabeled.
* Metrics: precision on the likely-malicious set and false-positive rate on the
  likely-benign set, reported separately, plus a manual review of the top-N anomalies
  ("of the 50 highest scores, how many would an analyst care about?").

`pipeline.py --file /path/to/auth.log` already runs the engine on a real file; what is
missing is the labeling script and the report.

## 2. Per-host (and per-service) baselines

One global baseline mixes very different traffic: a bastion host sees constant SSH, a
database host almost none, and a web server mostly HTTP. A burst that is normal on one is
alarming on another. Keep a small `AnomalyDetector` per host (or per host+process), each
with a capped baseline, falling back to the global model until a host has enough history.
Memory stays bounded by capping the number of host models with the same LRU idea the
featurizer uses for IPs.

## 3. Hour of day with a week-long baseline

`featurize(..., use_hour=True)` already encodes the hour as sin/cos so that 23:00 and
01:00 are neighbours, but it is off by default: a baseline of a few hundred lines covers
minutes, so every later hour would look anomalous. With a baseline spanning at least
seven days (sampled down to a few thousand points, e.g. a reservoir sample per hour
bucket) the hour features become a real signal for "admin logs in at 03:00". Today the
`odd_hour` anomalies are caught only because the synthetic generator jumps the clock to
03:00, which shows up as a long time gap, not because the model knows the hour.

## 4. Compare against Isolation Forest and LOF

KNN distance is simple and explainable, but it is not the only option:

| Method | Why compare |
|---|---|
| Local Outlier Factor (`sklearn.neighbors.LocalOutlierFactor(novelty=True)`) | Same neighbourhood idea, but density-relative: copes better when normal traffic has dense and sparse regions (our "rare but legitimate system messages" false positives). |
| Isolation Forest (`sklearn.ensemble.IsolationForest`) | Scales to large baselines (no pairwise distances), handles irrelevant features better, and is the usual industry baseline. |
| One-class SVM | A classic boundary-based alternative, for completeness. |

All three fit the same interface (`fit` on the baseline, `score_samples` per batch), so
the comparison is a new detector class plus a `--detector` flag on `evaluate.py`,
reported with the same per-type recall table.

## 5. Smaller items

* **Learned feature weights.** All features count equally after standardization. A
  validation run could pick per-feature weights (or a Mahalanobis metric) instead.
* **Sequence features.** Count distinct users per IP, or distinct ports per IP, over a
  window: credential stuffing and port scans show up there more clearly than in rates.
* **Safer baseline refresh.** Refresh still lets a patient attacker leak into the
  baseline. Options: require a point to stay normal for several refresh cycles before it
  is accepted, or cap how much of the baseline any single IP may contribute.
* **Dashboard persistence and auth.** The dashboard keeps everything in memory and has no
  login; a deployment beyond a demo needs authentication and an append-only anomaly store.
* **TCP/TLS syslog (RFC 5425)** in addition to UDP, so delivery is reliable and encrypted.
