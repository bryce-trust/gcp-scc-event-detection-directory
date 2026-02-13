# gcp-scc-event-detection-directory

A directory of potential Google Cloud Security Command Center (SCC) Event Threat Detection (ETD) finding types.

This repository catalogs *potential* ETD finding types and provides stable identifiers for downstream processing.

## Output Contract

Every entry includes:
- namespace
- id

## Generated Files
- event_threat_detection_finding_types.json (generated)

## Local usage

python scripts/sync_threat_findings.py
python scripts/validate_directory.py
