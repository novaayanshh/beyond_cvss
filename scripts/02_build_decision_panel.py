"""Build NVD SSOT and the historical decision-date panel.

Run from the repository root with the project environment:
    python scripts/02_build_decision_panel.py

Raw inputs are read only. Outputs are written to data/processed/ and outputs/.
Missing EPSS snapshots are reported and skipped; they are never substituted by
the current EPSS feed.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
TABLES = ROOT / "outputs" / "tables"
DATES = [pd.Timestamp(f"{year}-{month:02d}-19") for year in range(2022, 2027) for month in (2, 8)]


def metric_for(cve: dict) -> tuple[str | None, dict]:
    """Select one score, preferring CVSS 3.1/3.0 as the SRS specifies."""
    metrics = cve.get("metrics", {})
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((x for x in entries if x.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        impact = entry.get("impactScore")
        exploitability = entry.get("exploitabilityScore")
        attack_vector = data.get("attackVector", data.get("accessVector"))
        if attack_vector is not None:
            attack_vector = str(attack_vector).strip().upper().replace("ADJACENT_NETWORK", "ADJACENT")
        impacts = [data.get("confidentialityImpact"), data.get("integrityImpact"), data.get("availabilityImpact")]
        return version, {
            "cvss_score": data.get("baseScore"),
            "cvss_severity": data.get("baseSeverity"),
            "cvss_vector": data.get("vectorString"),
            "attack_vector": attack_vector,
            "attack_complexity": data.get("attackComplexity", data.get("accessComplexity")),
            "privileges_required": data.get("privilegesRequired", data.get("authentication")),
            "user_interaction": data.get("userInteraction"),
            "scope": data.get("scope"),
            "confidentiality_impact": data.get("confidentialityImpact"),
            "integrity_impact": data.get("integrityImpact"),
            "availability_impact": data.get("availabilityImpact"),
            "cvss_impact_score": impact,
            "cvss_exploitability_score": exploitability,
            "cvss_v2_partial_impact_flag": int(version == "2.0" and any(value == "PARTIAL" for value in impacts)),
            "cvss_v2_complete_impact_flag": int(version == "2.0" and any(value == "COMPLETE" for value in impacts)),
        }
    return None, {}


def cve_row(item: dict) -> dict:
    cve = item["cve"]
    version, score = metric_for(cve)
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for entry in weakness.get("description", []):
            if entry.get("lang") == "en" and entry.get("value", "").startswith("CWE-"):
                cwes.append(entry["value"])
    vendor_products = set()
    cpe_criteria = set()

    def visit(node):
        for match in node.get("cpeMatch", []):
            parts = match.get("criteria", "").split(":")
            if match.get("criteria"):
                cpe_criteria.add(match["criteria"])
            if len(parts) > 4:
                vendor_products.add((parts[3], parts[4]))
        for child in node.get("nodes", []):
            visit(child)

    for config in cve.get("configurations", []):
        visit(config)
    vendors = sorted({x[0] for x in vendor_products})
    products = sorted({x[1] for x in vendor_products})
    references = cve.get("references", [])
    reference_tags = [str(tag) for ref in references for tag in ref.get("tags", [])]
    cve_tag_values = [str(tag) for group in cve.get("cveTags", []) for tag in group.get("tags", [])]
    cwe_values = sorted(set(cwes))
    return {
        "cve_id": str(cve.get("id", "")).strip().upper(),
        "published_date": cve.get("published"),
        "last_modified_date": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cvss_version": version,
        **score,
        "cwe": ";".join(sorted(set(cwes))) or None,
        "cwe_count": len(cwe_values),
        "has_cwe": int(bool(cwe_values)),
        "vendor": ";".join(vendors) or None,
        "product": ";".join(products) or None,
        "cpe_match_count": len(cpe_criteria),
        "affected_vendor_count": len(vendors),
        "affected_product_count": len(products),
        "reference_count": len(references),
        "reference_tag_count": len(reference_tags),
        "exploit_reference_count": sum("exploit" in x.casefold() for x in reference_tags),
        "patch_reference_count": sum("patch" in x.casefold() for x in reference_tags),
        "advisory_reference_count": sum("advisory" in x.casefold() for x in reference_tags),
        "cve_tag_count": len(cve_tag_values),
        "cve_tag_values": ";".join(sorted(set(cve_tag_values))) or None,
        "description_length_chars": len(description or ""),
        "description_word_count": len((description or "").split()),
        "description": description,
    }


def load_nvd() -> pd.DataFrame:
    rows = []
    files = sorted(RAW.glob("nvdcve-2.0-*.json.gz"))
    if not files:
        raise FileNotFoundError(f"No NVD year feeds found under {RAW}")
    for path in files:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        parsed = [cve_row(item) for item in payload.get("vulnerabilities", [])]
        rows.extend(parsed)
        print(f"Loaded {len(parsed):,} CVEs from {path.name}")
    frame = pd.DataFrame(rows)
    frame["published_date"] = pd.to_datetime(frame["published_date"], utc=True, errors="coerce").dt.tz_localize(None).dt.normalize()
    frame["last_modified_date"] = pd.to_datetime(frame["last_modified_date"], utc=True, errors="coerce").dt.tz_localize(None).dt.normalize()
    frame["cvss_score"] = pd.to_numeric(frame["cvss_score"], errors="coerce")
    rejected = frame["vuln_status"].fillna("").str.casefold().eq("rejected")
    rejected_count = int(rejected.sum())
    frame = frame.loc[~rejected].copy()
    # A CVE should be unique across NVD year feeds. If it is duplicated, retain
    # the most recently modified record and make the count visible in the log.
    duplicate_rows = int(frame["cve_id"].duplicated(keep=False).sum())
    if duplicate_rows:
        frame = frame.sort_values("last_modified_date").drop_duplicates("cve_id", keep="last")
    frame["has_cvss_score"] = frame["cvss_score"].notna().astype("int8")
    if not frame["cvss_score"].dropna().between(0, 10).all():
        raise ValueError("CVSS base score outside the expected [0, 10] range")
    frame["cve_age_days"] = np.nan
    frame = frame.sort_values("cve_id").reset_index(drop=True)
    print(f"NVD unique non-rejected CVEs: {len(frame):,}; rejected dropped: {rejected_count:,}; duplicate rows resolved: {duplicate_rows:,}")
    return frame


def load_kev() -> pd.DataFrame:
    path = RAW / "known_exploited_vulnerabilities.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing CISA KEV catalogue: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    kev = pd.DataFrame(payload.get("vulnerabilities", []))
    kev = kev.rename(columns={"cveID": "cve_id", "dateAdded": "kev_date_added"})
    kev["cve_id"] = kev["cve_id"].astype(str).str.strip().str.upper()
    kev["kev_date_added"] = pd.to_datetime(kev["kev_date_added"], errors="coerce").dt.normalize()
    return kev[["cve_id", "kev_date_added"]].drop_duplicates("cve_id", keep="first")


def load_epss(date: pd.Timestamp) -> tuple[pd.DataFrame, str] | None:
    path = RAW / "epss_decision_dates" / f"epss_scores-{date:%Y-%m-%d}.csv.gz"
    if not path.exists():
        return None
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        metadata = handle.readline().strip()
        scores = pd.read_csv(handle)
    version = metadata.partition("model_version:")[2].partition(",")[0].removeprefix("v")
    if scores["cve"].duplicated().any():
        raise ValueError(f"Duplicate CVE IDs in {path.name}")
    scores = scores.rename(columns={"cve": "cve_id", "epss": "epss_at_decision", "percentile": "epss_percentile_at_decision"})
    scores["cve_id"] = scores["cve_id"].astype(str).str.strip().str.upper()
    scores["epss_at_decision"] = pd.to_numeric(scores["epss_at_decision"], errors="coerce")
    scores["epss_percentile_at_decision"] = pd.to_numeric(scores["epss_percentile_at_decision"], errors="coerce")
    for column in ("epss_at_decision", "epss_percentile_at_decision"):
        if not scores[column].dropna().between(0, 1).all():
            raise ValueError(f"{column} outside the expected [0, 1] range in {path.name}")
    return scores[["cve_id", "epss_at_decision", "epss_percentile_at_decision"]], version


def main() -> None:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    TABLES.mkdir(parents=True, exist_ok=True)
    nvd = load_nvd()
    nvd.to_csv(PROCESSED / "ssot_clean.csv", index=False, date_format="%Y-%m-%d")
    kev = load_kev()
    panels, date_rows = [], []
    for date in DATES:
        epss = load_epss(date)
        if epss is None:
            print(f"MISSING EPSS snapshot: {date:%Y-%m-%d} (not replaced with current scores)")
            date_rows.append({"decision_date": date.date().isoformat(), "snapshot_available": False})
            continue
        scores, model_version = epss
        base = nvd.loc[nvd["published_date"].lt(date)].copy()
        base = base.merge(kev, on="cve_id", how="left", validate="one_to_one")
        base = base.loc[base["kev_date_added"].isna() | base["kev_date_added"].gt(date)].copy()
        base = base.merge(scores, on="cve_id", how="left", validate="one_to_one")
        base["decision_date"] = date
        base["cve_age_days"] = (date - base["published_date"]).dt.days
        label_end = date + pd.Timedelta(days=30)
        base["kev_30d_label"] = (base["kev_date_added"].gt(date) & base["kev_date_added"].le(label_end)).fillna(False).astype("int8")
        base["epss_model_version"] = model_version
        base["has_epss_at_decision"] = base["epss_at_decision"].notna().astype("int8")
        if base["cve_id"].duplicated().any():
            raise ValueError(f"Duplicate CVEs remain in panel for {date:%Y-%m-%d}")
        if not base["published_date"].lt(date).all():
            raise ValueError(f"Future publication date found in panel for {date:%Y-%m-%d}")
        if (base["kev_date_added"].le(date).fillna(False)).any():
            raise ValueError(f"Previously listed KEV remains in panel for {date:%Y-%m-%d}")
        if not base["epss_at_decision"].dropna().between(0, 1).all():
            raise ValueError(f"EPSS outside [0, 1] in panel for {date:%Y-%m-%d}")
        panels.append(base)
        date_rows.append({
            "decision_date": date.date().isoformat(), "snapshot_available": True,
            "epss_model_version": model_version, "rows": len(base),
            "positives": int(base["kev_30d_label"].sum()),
            "positive_rate": float(base["kev_30d_label"].mean()) if len(base) else np.nan,
            "missing_epss": float(base["epss_at_decision"].isna().mean()) if len(base) else np.nan,
            "pool_has_cvss": int(base["has_cvss_score"].sum()),
        })
        print(f"{date:%Y-%m-%d}: rows={len(base):,}, positives={int(base['kev_30d_label'].sum())}, model={model_version}")
    if not panels:
        raise RuntimeError("No matching dated EPSS snapshots were found")
    panel = pd.concat(panels, ignore_index=True)
    panel.to_csv(PROCESSED / "ssot_decision_panel.csv", index=False, date_format="%Y-%m-%d")
    panel.drop(columns=["description"], errors="ignore").to_csv(PROCESSED / "ssot_final.csv", index=False, date_format="%Y-%m-%d")
    pd.DataFrame(date_rows).to_csv(TABLES / "panel_summary.csv", index=False)
    missing = panel.isna().mean().rename_axis("column").reset_index(name="missing_fraction")
    missing.to_csv(TABLES / "missingness.csv", index=False)
    print(f"Saved panel: {len(panel):,} rows, {panel['cve_id'].nunique():,} unique CVEs across dates")
    print("Note: current NVD enrichments and current rejection status are not historical snapshots.")


if __name__ == "__main__":
    main()
