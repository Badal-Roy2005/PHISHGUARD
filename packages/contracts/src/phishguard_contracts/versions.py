"""Version constants shared by every PHISHGUARD service."""

SERVICE_VERSION = "0.1.0"

#: Bump on any breaking wire change, together with docs/api-contracts.md.
CONTRACT_VERSION = "2026-11-08.1"

SCHEMA_VERSION = 1

#: Version of the ML feature contract. Bumped by M2 when the feature list changes.
FEATURE_SCHEMA_VERSION = "1"

#: PhiUSIIL label mapping. 0 = phishing, 1 = legitimate. Never invert.
LABEL_MAP: dict[str, str] = {"0": "phishing", "1": "legitimate"}
