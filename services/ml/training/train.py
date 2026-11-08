"""Training CLI: audit -> split -> train 3 algorithms x 2 feature sets -> select.

Run from ``services/ml``::

    uv run python -m training.train

Artifacts are written to ``artifacts/``. Nothing in this module invents a metric:
every number in ``metrics.json`` and ``MODEL_CARD.md`` is measured on the
held-out test split.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import matplotlib
import numpy as np
from matplotlib import pyplot as plt
from sklearn.pipeline import Pipeline

matplotlib.use("Agg")

from phishguard_contracts import ModelMetadata, ModelMetrics  # noqa: E402

from .config import (  # noqa: E402
    ARTIFACTS_DIR,
    DEFAULT_CSV,
    FEATURE_CONTRACT_VERSION,
    FEATURE_SETS,
    LABEL_COLUMN,
    MODEL_VERSION,
    RANDOM_STATE,
)
from .dataset import (  # noqa: E402
    DatasetSplits,
    audit_dataset,
    build_splits,
    load_dataset,
    write_json,
)
from .explain import (  # noqa: E402
    ExplainerUnavailable,
    build_explainer,
    global_importance,
)
from .features import build_feature_contract, build_manifest  # noqa: E402
from .modeling import (  # noqa: E402
    ALGORITHMS,
    evaluate,
    is_phishing,
    phishing_probability,
    tune_threshold,
)

logger = logging.getLogger("phishguard.ml.train")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plot_confusion(matrix: list[list[int]], title: str, path: Path) -> None:
    array = np.asarray(matrix)
    figure, axis = plt.subplots(figsize=(4.2, 3.6))
    image = axis.imshow(array, cmap="Blues")
    axis.set_xticks([0, 1], ["legitimate", "phishing"])
    axis.set_yticks([0, 1], ["legitimate", "phishing"])
    axis.set_xlabel("Predicted")
    axis.set_ylabel("Actual")
    axis.set_title(title)
    for row in range(2):
        for column in range(2):
            axis.text(
                column,
                row,
                f"{array[row, column]:,}",
                ha="center",
                va="center",
                color="white" if array[row, column] > array.max() / 2 else "black",
            )
    figure.colorbar(image, ax=axis)
    figure.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=140)
    plt.close(figure)


def _fit_and_score(
    algorithm: str,
    columns: tuple[str, ...],
    splits: DatasetSplits,
    run_dir: Path,
) -> dict[str, Any]:
    from .modeling import build_pipeline

    train_frame = splits.train.frame
    val_frame = splits.validation.frame
    test_frame = splits.test.frame

    x_train = train_frame[list(columns)].to_numpy(dtype=float)
    x_val = val_frame[list(columns)].to_numpy(dtype=float)
    x_test = test_frame[list(columns)].to_numpy(dtype=float)
    y_train = is_phishing(train_frame[LABEL_COLUMN])
    y_val = is_phishing(val_frame[LABEL_COLUMN])
    y_test = is_phishing(test_frame[LABEL_COLUMN])

    pipeline = build_pipeline(algorithm, list(columns))
    pipeline.fit(x_train, y_train)

    validation_probabilities = phishing_probability(pipeline, x_val)
    tuned = tune_threshold(y_val, validation_probabilities)
    threshold = tuned["threshold"]
    validation = evaluate(y_val, validation_probabilities, threshold)
    test = evaluate(y_test, phishing_probability(pipeline, x_test), threshold)

    run_dir.mkdir(parents=True, exist_ok=True)
    model_path = run_dir / "model.joblib"
    preprocessor_path = run_dir / "preprocessor.joblib"
    joblib.dump(pipeline, model_path)
    joblib.dump(pipeline[:-1], preprocessor_path)

    write_json(
        run_dir / "metrics.json",
        {"algorithm": algorithm, "validation": validation, "test": test},
    )
    write_json(run_dir / "classification_report.json", test["classification_report"])
    _plot_confusion(
        test["confusion_matrix"]["matrix"],
        f"{algorithm} (phishing F1={test['f1_phishing']:.3f})",
        run_dir / "confusion_matrix.png",
    )
    write_json(
        run_dir / "checksums.json",
        {
            "model.joblib": _sha256(model_path),
            "preprocessor.joblib": _sha256(preprocessor_path),
        },
    )

    return {
        "algorithm": algorithm,
        "columns": tuple(columns),
        "threshold": threshold,
        "validation": validation,
        "test": test,
        "pipeline": pipeline,
        "model_path": model_path,
        "artifact_sha256": _sha256(model_path),
    }


def _metadata(
    algorithm: str,
    metrics: dict[str, Any],
    artifact_sha256: str,
    rows: int,
    feature_count: int,
) -> ModelMetadata:
    return ModelMetadata(
        name=f"phiusiil-{algorithm}",
        version=MODEL_VERSION,
        trained_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        dataset=f"PhiUSIIL ({rows} rows x {feature_count} live features)",
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        label_map={"0": "phishing", "1": "legitimate"},
        metrics=ModelMetrics(
            accuracy=metrics["accuracy"],
            precision=metrics["precision_phishing"],
            recall=metrics["recall_phishing"],
            f1=metrics["f1_phishing"],
            roc_auc=metrics["roc_auc"],
            pr_auc=metrics["pr_auc"],
        ),
        artifact_sha256=artifact_sha256,
    )


def _model_card(
    selected: dict[str, Any], runs: list[dict[str, Any]], summary: dict[str, Any]
) -> str:
    lines = [
        "# PHISHGUARD model card (generated)",
        "",
        f"Generated: {datetime.now(UTC).isoformat().replace('+00:00', 'Z')}",
        f"Model version: `{MODEL_VERSION}` · feature contract: `{FEATURE_CONTRACT_VERSION}`",
        "",
        "## Served model",
        "",
        f"- Feature set: `{selected['feature_set']}` ({selected['feature_count']} features)",
        f"- Algorithm: `{selected['algorithm']}`",
        f"- Decision threshold: `{selected['threshold']:.3f}` (tuned on validation phishing F1)",
        "",
        "| Metric | Validation | Test (held out) |",
        "|---|---|---|",
    ]
    for key in (
        "accuracy",
        "precision_phishing",
        "recall_phishing",
        "f1_phishing",
        "roc_auc",
        "pr_auc",
    ):
        lines.append(
            f"| {key} | {selected['validation'][key]:.4f} | {selected['test'][key]:.4f} |"
        )
    lines += [
        "",
        "## All runs (test split)",
        "",
        "| Feature set | Algorithm | Threshold | Accuracy | Phishing precision | "
        "Phishing recall | Phishing F1 | ROC-AUC | PR-AUC |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for run in runs:
        test = run["test"]
        lines.append(
            "| {feature_set} | {algorithm} | {threshold:.3f} | {accuracy:.4f} | "
            "{precision_phishing:.4f} | {recall_phishing:.4f} | {f1_phishing:.4f} | "
            "{roc_auc:.4f} | {pr_auc:.4f} |".format(
                feature_set=run["feature_set"], algorithm=run["algorithm"], **test
            )
        )
    lines += [
        "",
        "## Split provenance",
        "",
        f"- Grouped by registrable domain; fingerprint `{summary['assignment_sha256']}`.",
        f"- Seed `{summary['seed']}`; {summary['splits']['train']['rows']:,} train / "
        f"{summary['splits']['validation']['rows']:,} validation / "
        f"{summary['splits']['test']['rows']:,} test rows.",
        f"- Removed {summary['duplicate_url_rows_removed']:,} duplicate-URL rows and "
        f"{summary['ambiguous_domain_rows_removed']:,} rows in domains that carry both labels.",
        "",
        "## Limits",
        "",
        "- The `full_offline` models use page-content features and are not servable",
        "  without controlled inspection. Only the `live` model is served.",
        "- Metrics are measured on one split of one dataset; they are not a claim about",
        "  live traffic. No metric in this card is a target or an estimate.",
        "- SHAP values explain the model margin, not causality.",
    ]
    return "\n".join(lines) + "\n"


def run(
    csv_path: str | Path = DEFAULT_CSV,
    artifacts_dir: str | Path = ARTIFACTS_DIR,
    seed: int = RANDOM_STATE,
) -> dict[str, Any]:
    artifacts = Path(artifacts_dir)
    artifacts.mkdir(parents=True, exist_ok=True)

    logger.info("loading dataset from %s", csv_path)
    frame = load_dataset(csv_path)
    audit = audit_dataset(frame)
    write_json(artifacts / "dataset_audit.json", audit)

    logger.info("building domain-grouped splits (seed=%s)", seed)
    splits = build_splits(frame, seed)
    write_json(artifacts / "split_summary.json", splits.summary)

    manifest = build_manifest()
    write_json(artifacts / "feature_manifest.json", manifest)

    all_runs: list[dict[str, Any]] = []
    for feature_set in FEATURE_SETS:
        missing = [name for name in feature_set.columns if name not in frame.columns]
        if missing:
            raise ValueError(f"feature set {feature_set.name} references absent columns: {missing}")
        for algorithm in ALGORITHMS:
            logger.info("training %s / %s", feature_set.name, algorithm)
            run_dir = artifacts / "runs" / feature_set.name / algorithm
            result = _fit_and_score(algorithm, feature_set.columns, splits, run_dir)
            all_runs.append(
                {
                    "feature_set": feature_set.name,
                    "feature_count": len(feature_set.columns),
                    "columns": feature_set.columns,
                    "algorithm": algorithm,
                    "threshold": result["threshold"],
                    "validation": result["validation"],
                    "test": result["test"],
                    "artifact_sha256": result["artifact_sha256"],
                    "pipeline": result["pipeline"],
                    "model_path": result["model_path"],
                }
            )

    def best(feature_set_name: str) -> dict[str, Any]:
        candidates = [run for run in all_runs if run["feature_set"] == feature_set_name]
        return max(candidates, key=lambda run: run["validation"]["f1_phishing"])

    served = best("live")
    best_full = best("full_offline")

    served_pipeline: Pipeline = served["pipeline"]
    served_model_path = artifacts / "model.joblib"
    served_preprocessor_path = artifacts / "preprocessor.joblib"
    joblib.dump(served_pipeline, served_model_path)
    joblib.dump(served_pipeline[:-1], served_preprocessor_path)

    contract = build_feature_contract(
        manifest,
        tuple(served["columns"]),
        version=FEATURE_CONTRACT_VERSION,
        model_version=MODEL_VERSION,
        dataset={
            "name": "PhiUSIIL Phishing URL (Website) Dataset",
            "rows": int(
                len(splits.train.frame) + len(splits.validation.frame) + len(splits.test.frame)
            ),
            "feature_count": len(served["columns"]),
            "class_counts": {
                "0_phishing": int((frame[LABEL_COLUMN] == 0).sum()),
                "1_legitimate": int((frame[LABEL_COLUMN] == 1).sum()),
            },
        },
    )
    write_json(artifacts / "feature_contract.json", contract)

    artifact_sha256 = _sha256(served_model_path)
    metadata = _metadata(
        served["algorithm"],
        served["test"],
        artifact_sha256,
        len(frame),
        len(contract["features"]),
    )

    comparison = {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "seed": seed,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "model_version": MODEL_VERSION,
        "runs": [
            {
                "feature_set": run["feature_set"],
                "feature_count": run["feature_count"],
                "algorithm": run["algorithm"],
                "threshold": run["threshold"],
                "validation": run["validation"],
                "test": run["test"],
                "artifact_sha256": run["artifact_sha256"],
            }
            for run in all_runs
        ],
        "selection_rule": "highest validation phishing F1 within each feature set",
        "served": {
            "feature_set": "live",
            "algorithm": served["algorithm"],
            "feature_count": served["feature_count"],
            "threshold": served["threshold"],
            "validation": served["validation"],
            "test": served["test"],
            "artifact_sha256": artifact_sha256,
        },
        "best_full_offline": {
            "algorithm": best_full["algorithm"],
            "feature_count": best_full["feature_count"],
            "threshold": best_full["threshold"],
            "validation": best_full["validation"],
            "test": best_full["test"],
        },
    }
    write_json(artifacts / "metrics.json", comparison)

    write_json(
        artifacts / "selected.json",
        {
            "served": comparison["served"],
            "model": metadata.model_dump(),
            "feature_contract_version": FEATURE_CONTRACT_VERSION,
            "feature_order": list(served["columns"]),
            "threshold": served["threshold"],
        },
    )

    # SHAP: global importance for the served model. A failed explainer must not
    # block serving, so it is recorded explicitly instead of being hidden.
    shap_path = artifacts / "shap_global.json"
    try:
        background = splits.train.frame[list(served["columns"])].to_numpy(
            dtype=float
        )[:200]
        explainer, method = build_explainer(served_pipeline, background)
        sample = splits.test.frame[list(served["columns"])].to_numpy(dtype=float)[
            :1000
        ]
        importance = global_importance(
            served_pipeline,
            explainer,
            tuple(served["columns"]),
            sample,
        )
        write_json(
            shap_path,
            {"method": method, "sample_rows": len(sample), "importance": importance},
        )
    except ExplainerUnavailable as exc:
        logger.warning("SHAP unavailable for served model: %s", exc)
        write_json(shap_path, {"method": "unavailable", "reason": str(exc), "importance": []})

    (artifacts / "MODEL_CARD.md").write_text(
        _model_card(comparison["served"], all_runs, splits.summary), encoding="utf-8"
    )
    write_json(
        artifacts / "checksums.json",
        {
            "model.joblib": artifact_sha256,
            "preprocessor.joblib": _sha256(served_preprocessor_path),
            "feature_contract.json": _sha256(artifacts / "feature_contract.json"),
            "feature_manifest.json": _sha256(artifacts / "feature_manifest.json"),
        },
    )

    logger.info(
        "served model: %s / %s (test phishing F1=%.4f)",
        served["feature_set"],
        served["algorithm"],
        served["test"]["f1_phishing"],
    )
    return comparison


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate PHISHGUARD models")
    parser.add_argument("--csv", default=os.environ.get("PHIUSIIL_CSV", str(DEFAULT_CSV)))
    parser.add_argument("--artifacts", default=str(ARTIFACTS_DIR))
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    comparison = run(args.csv, args.artifacts, args.seed)
    print(json.dumps(comparison["served"], indent=2))


if __name__ == "__main__":
    main()
