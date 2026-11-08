# PHISHGUARD model card (generated)

Generated: 2026-11-08T07:44:38.053372Z
Model version: `1.0.0` · feature contract: `2`

## Served model

- Feature set: `live` (18 features)
- Algorithm: `xgboost`
- Decision threshold: `0.545` (tuned on validation phishing F1)

| Metric | Validation | Test (held out) |
|---|---|---|
| accuracy | 0.9983 | 0.9968 |
| precision_phishing | 0.9995 | 0.9993 |
| recall_phishing | 0.9960 | 0.9932 |
| f1_phishing | 0.9977 | 0.9963 |
| roc_auc | 0.9987 | 0.9983 |
| pr_auc | 0.9989 | 0.9986 |

## All runs (test split)

| Feature set | Algorithm | Threshold | Accuracy | Phishing precision | Phishing recall | Phishing F1 | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|
| full_offline | logistic_regression | 0.600 | 0.9991 | 0.9997 | 0.9982 | 0.9990 | 1.0000 | 1.0000 |
| full_offline | random_forest | 0.340 | 0.9998 | 0.9996 | 0.9999 | 0.9997 | 1.0000 | 1.0000 |
| full_offline | xgboost | 0.920 | 0.9999 | 1.0000 | 0.9997 | 0.9998 | 1.0000 | 1.0000 |
| live | logistic_regression | 0.445 | 0.9944 | 0.9996 | 0.9872 | 0.9933 | 0.9979 | 0.9983 |
| live | random_forest | 0.610 | 0.9958 | 0.9992 | 0.9908 | 0.9950 | 0.9983 | 0.9987 |
| live | xgboost | 0.545 | 0.9968 | 0.9993 | 0.9932 | 0.9963 | 0.9983 | 0.9986 |

## Split provenance

- Grouped by registrable domain; fingerprint `d155592404622e4de879b9b0881d6d0a0ae231f0fd690d8afebcaa48d985ec1e`.
- Seed `42`; 166,343 train / 32,556 validation / 35,099 test rows.
- Removed 425 duplicate-URL rows and 1,372 rows in domains that carry both labels.

## Limits

- The `full_offline` models use page-content features and are not servable
  without controlled inspection. Only the `live` model is served.
- Metrics are measured on one split of one dataset; they are not a claim about
  live traffic. No metric in this card is a target or an estimate.
- SHAP values explain the model margin, not causality.
