#!/usr/bin/env python3
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

THREAT_FINDINGS_INDEX_URL = "https://docs.cloud.google.com/security-command-center/docs/threat-findings-index"
OUTPUT_FILE = "event_threat_detection_finding_types.json"


def _slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def normalize_doc_url(href: str) -> str:
    """
    Convert href from the Threat Findings Index into a clean absolute URL.
    """
    if href.startswith("http"):
        return href
    if href.startswith("/"):
        return "https://docs.cloud.google.com" + href
    return "https://docs.cloud.google.com/" + href


# Threat Findings Index "Resource category" -> (namespace, api_service)
# IMPORTANT: keys must match the category strings on the index page exactly.
RESOURCE_CATEGORY_MAP: dict[str, tuple[str, str | None]] = {
    # Common ones (expand as you discover more):
    "Backup and DR Service": ("backupdr", "backupdr.googleapis.com"),
    "Backup and DR": ("backupdr", "backupdr.googleapis.com"),
    "Compute Engine": ("compute", "compute.googleapis.com"),
    "Identity and Access Management": ("iam", "iam.googleapis.com"),
    "IAM": ("iam", "iam.googleapis.com"),
    "Google Kubernetes Engine": ("container", "container.googleapis.com"),
    "Cloud Storage": ("storage", "storage.googleapis.com"),
    "BigQuery": ("bigquery", "bigquery.googleapis.com"),
    "Pub/Sub": ("pubsub", "pubsub.googleapis.com"),
    "Cloud DNS": ("dns", "dns.googleapis.com"),
    "Cloud Logging": ("logging", "logging.googleapis.com"),
    "Cloud KMS": ("kms", "cloudkms.googleapis.com"),
    "Secret Manager": ("secretmanager", "secretmanager.googleapis.com"),
    "Cloud SQL": ("cloudsql", "sqladmin.googleapis.com"),
    "Cloud Run": ("run", "run.googleapis.com"),
    "Network": ("networking", "compute.googleapis.com"),
    "Google Workspace": ("iam", "iam.googleapis.com"),
    "AI": ("aiplatform", "aiplatform.googleapis.com"),
    "Database": ("cloudsql", "sqladmin.googleapis.com"),
}


# Fallback hints (URL/display-name tokens) used only if resource category isn't mapped
SERVICE_HINTS: list[tuple[str, tuple[str, str | None]]] = [
    ("backupdr", ("backupdr", "backupdr.googleapis.com")),
    ("iam", ("iam", "iam.googleapis.com")),
    ("serviceaccount", ("iam", "iam.googleapis.com")),
    ("compute", ("compute", "compute.googleapis.com")),
    ("gce", ("compute", "compute.googleapis.com")),
    ("ssh", ("compute", "compute.googleapis.com")),
    ("kubernetes", ("container", "container.googleapis.com")),
    ("gke", ("container", "container.googleapis.com")),
    ("container", ("container", "container.googleapis.com")),
    ("cloudrun", ("run", "run.googleapis.com")),
    ("run", ("run", "run.googleapis.com")),
    ("cloudfunctions", ("cloudfunctions", "cloudfunctions.googleapis.com")),
    ("functions", ("cloudfunctions", "cloudfunctions.googleapis.com")),
    ("pubsub", ("pubsub", "pubsub.googleapis.com")),
    ("bigquery", ("bigquery", "bigquery.googleapis.com")),
    ("storage", ("storage", "storage.googleapis.com")),
    ("gcs", ("storage", "storage.googleapis.com")),
    ("cloudsql", ("cloudsql", "sqladmin.googleapis.com")),
    ("sql", ("cloudsql", "sqladmin.googleapis.com")),
    ("spanner", ("spanner", "spanner.googleapis.com")),
    ("dns", ("dns", "dns.googleapis.com")),
    ("firewall", ("networking", None)),
    ("vpc", ("networking", None)),
    ("network", ("networking", None)),
    ("logging", ("logging", "logging.googleapis.com")),
    ("log", ("logging", "logging.googleapis.com")),
    ("kms", ("kms", "cloudkms.googleapis.com")),
    ("secretmanager", ("secretmanager", "secretmanager.googleapis.com")),
    ("secret", ("secretmanager", "secretmanager.googleapis.com")),
]


def derive_from_resource_category(resource_category: str | None) -> tuple[str | None, str | None, str]:
    """
    Returns (namespace, api_service, source)
    """
    if not resource_category:
        return None, None, "resource_category:missing"

    rc = resource_category.strip()
    if rc in RESOURCE_CATEGORY_MAP:
        ns, api = RESOURCE_CATEGORY_MAP[rc]
        return ns, api, "resource_category:map"

    return None, None, "resource_category:unmapped"


def derive_namespace_fallback(display_name: str, doc_url: str | None) -> tuple[str, str | None, str]:
    """
    Fallback: derive from doc_url tokens first, then display_name tokens.
    Returns (namespace, api_service, source)
    """
    candidates: list[str] = []

    if doc_url:
        path = urlparse(doc_url).path.lower()
        candidates.extend([t for t in re.split(r"[^a-z0-9]+", path) if t])

    candidates.extend([t for t in re.split(r"[^a-z0-9]+", display_name.lower()) if t])

    cand_set = set(candidates)
    for hint, (ns, api) in SERVICE_HINTS:
        if hint in cand_set:
            return ns, api, f"fallback:hint:{hint}"

    return "securitycenter", None, "fallback:default"


def report_unmapped_categories(categories: set[str]):
    """
    Print resource categories that are not covered by RESOURCE_CATEGORY_MAP.
    """
    unmapped = sorted([c for c in categories if c and c not in RESOURCE_CATEGORY_MAP])

    print("\n=== Unmapped Resource Categories (need mapping) ===")
    if not unmapped:
        print("All categories are mapped. ✅")
    else:
        for c in unmapped:
            print(f"- {c}")
    print("===============================================\n")


def report_unmapped_findings(findings: list[dict]):
    """
    Print findings whose resource_category is not mapped in RESOURCE_CATEGORY_MAP.
    """
    print("\n=== Findings in Unmapped Resource Categories ===")

    count = 0
    for f in findings:
        rc = f.get("resource_category")
        if rc not in RESOURCE_CATEGORY_MAP:
            count += 1
            print(f"- [{rc}] {f['display_name']}")

    if count == 0:
        print("All findings are mapped. ✅")
    else:
        print(f"\nTotal unmapped findings: {count}")

    print("==============================================\n")


def fetch_index_html() -> str:
    resp = requests.get(THREAT_FINDINGS_INDEX_URL, timeout=30)
    resp.raise_for_status()
    return resp.text


def parse_etd_rows(html: str):
    soup = BeautifulSoup(html, "html.parser")
    findings = []
    seen_categories: set[str] = set()

    for tr in soup.find_all("tr"):
        tds = tr.find_all(["td", "th"])
        if not tds or len(tds) < 3:
            continue

        row_text = " | ".join(td.get_text(" ", strip=True) for td in tds)
        if "Event Threat Detection" not in row_text:
            continue

        # Typical columns:
        # 0: Name, 1: Resource category, 2: Detection service
        finding_name = tds[0].get_text(" ", strip=True)
        resource_category = tds[1].get_text(" ", strip=True)
        seen_categories.add(resource_category)

        finding_id = _slugify(finding_name)

        doc_url = None
        link = tds[0].find("a")
        if link and link.get("href"):
            doc_url = normalize_doc_url(link["href"])

        # 1) Primary: resource category mapping
        ns, api_service, ns_source = derive_from_resource_category(resource_category)

        # 2) Fallback: token heuristics
        if ns is None:
            ns, api_service, ns_source = derive_namespace_fallback(finding_name, doc_url)

        findings.append(
            {
                "namespace": ns,
                "id": finding_id,
                "display_name": finding_name,
                "detection_service": "Event Threat Detection",
                "resource_category": resource_category,
                "api_service": api_service,
                "doc_url": doc_url,
                "namespace_source": ns_source,
            }
        )

    # Deduplicate by (namespace,id)
    dedup = {}
    for f in findings:
        key = (f["namespace"], f["id"])
        if key not in dedup:
            dedup[key] = f

    out = list(dedup.values())
    out.sort(key=lambda x: (x["namespace"], x["id"]))

    report_unmapped_categories(seen_categories)
    report_unmapped_findings(out)

    return out


def main():
    html = fetch_index_html()
    etd = parse_etd_rows(html)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": THREAT_FINDINGS_INDEX_URL,
        "items": etd,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")

    print(f"Wrote {len(etd)} ETD finding types to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
