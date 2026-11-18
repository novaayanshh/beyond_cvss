"""Attach decision-date CVSS 3.0/3.1 values reconstructed from NVD history.

This script never falls back to the current NVD score. It selects the last
timestamped vector recorded strictly before 00:00 UTC on each decision date, prefers an NVD
("NIST") vector when more than one source is recorded, and otherwise keeps the
latest available source vector. Missing history stays missing.
"""
from __future__ import annotations

import gzip
import json
import re
from collections import defaultdict
from pathlib import Path

import pandas as pd
from cvss import CVSS3, CVSS4

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "data" / "processed" / "ssot_final.csv"
HISTORY = ROOT / "data" / "raw" / "nvd_cvss_history"
OUTPUT = ROOT / "data" / "processed" / "ssot_historical.csv"
ASOF_ROWS = ROOT / "data" / "processed" / "cvss_asof_by_decision.csv"
SUMMARY = ROOT / "outputs" / "tables" / "historical_cvss_coverage.csv"
VECTOR3_RE = re.compile(r"(?:CVSS:3\.[01]/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]")
VECTOR4_RE = re.compile(r"(?:CVSS:4\.0/)?AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPR]/VC:[NLH]/VI:[NLH]/VA:[NLH]/SC:[NLH]/SI:[NLH]/SA:[NLH]")
VERSION_RE = re.compile(r"CVSS V(3\.0|3\.1|4\.0)$", re.IGNORECASE)


def parse_metric_value(value: object, version: str) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    match = (VECTOR4_RE if version == "4.0" else VECTOR3_RE).search(value)
    if not match:
        return None
    vector = match.group(0)
    if not vector.startswith("CVSS:"):
        vector = f"CVSS:{version}/{vector}"
    source = value[:match.start()].strip(" \t:()[]") or "unspecified"
    source_key = "NIST" if "nist" in source.casefold() or "nvd" in source.casefold() else source
    return source_key, vector


def vector_fields(vector: str, version: str, source: str) -> dict:
    scorer = CVSS3(vector)
    score = float(scorer.scores()[0])
    severity = scorer.severities()[0]
    parts = dict(item.split(":", 1) for item in vector.split("/")[1:] if ":" in item)
    return {
        "cvss_version_asof": version,
        "cvss_score_asof": score,
        "cvss_severity_asof": severity,
        "cvss_vector_asof": vector,
        "cvss_source_asof": source,
        "attack_vector_asof": {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}.get(parts.get("AV")),
        "attack_complexity_asof": {"L": "LOW", "H": "HIGH"}.get(parts.get("AC")),
        "privileges_required_asof": {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(parts.get("PR")),
        "user_interaction_asof": {"N": "NONE", "R": "REQUIRED"}.get(parts.get("UI")),
        "scope_asof": {"U": "UNCHANGED", "C": "CHANGED"}.get(parts.get("S")),
        "confidentiality_impact_asof": {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(parts.get("C")),
        "integrity_impact_asof": {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(parts.get("I")),
        "availability_impact_asof": {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(parts.get("A")),
    }


def apply_details(details: list[dict], state: dict) -> None:
    for detail in details:
        match = VERSION_RE.fullmatch(str(detail.get("type", "")))
        if not match:
            continue
        version = match.group(1)
        action = str(detail.get("action", "")).casefold()
        parsed = parse_metric_value(detail.get("newValue"), version)
        if action in {"added", "changed"} and parsed:
            source, vector = parsed
            if action == "changed":
                old = parse_metric_value(detail.get("oldValue"), version)
                if old and old[0] != source:
                    state.pop((version, old[0]), None)
            try:
                (CVSS4 if version == "4.0" else CVSS3)(vector)
            except Exception:
                continue
            state.pop((version, source), None)
            state[(version, source)] = vector
        elif action == "removed":
            old = parse_metric_value(detail.get("oldValue"), version)
            if old:
                state.pop((version, old[0]), None)
            else:
                for key in [key for key in state if key[0] == version]:
                    state.pop(key, None)


def select_asof(state: dict) -> dict:
    result = {
        "cvss_version_asof": None, "cvss_score_asof": None,
        "cvss_severity_asof": None, "cvss_vector_asof": None,
        "cvss_source_asof": None, "attack_vector_asof": None,
        "attack_complexity_asof": None, "privileges_required_asof": None,
        "user_interaction_asof": None, "scope_asof": None,
        "confidentiality_impact_asof": None, "integrity_impact_asof": None,
        "availability_impact_asof": None,
        "cvss4_score_asof": None, "cvss4_vector_asof": None, "cvss4_source_asof": None,
        "cvss_any_version_asof": None, "cvss_any_score_asof": None,
    }
    for version in ("3.1", "3.0"):
        candidates = [(source, vector) for (v, source), vector in state.items() if v == version]
        if not candidates:
            continue
        source, vector = next((pair for pair in candidates if pair[0] == "NIST"), candidates[-1])
        result.update(vector_fields(vector, version, source))
        result["cvss_any_version_asof"] = version
        result["cvss_any_score_asof"] = result["cvss_score_asof"]
        break
    candidates4 = [(source, vector) for (version, source), vector in state.items() if version == "4.0"]
    if candidates4:
        source4, vector4 = next((pair for pair in candidates4 if pair[0] == "NIST"), candidates4[-1])
        result["cvss4_score_asof"] = float(CVSS4(vector4).scores()[0])
        result["cvss4_vector_asof"] = vector4
        result["cvss4_source_asof"] = source4
        if result["cvss_any_score_asof"] is None:
            result["cvss_any_version_asof"] = "4.0"
            result["cvss_any_score_asof"] = result["cvss4_score_asof"]
    return result


def main() -> None:
    if not PANEL.exists():
        raise FileNotFoundError(f"Build the decision panel first: {PANEL}")
    panel = pd.read_csv(PANEL, usecols=["cve_id", "decision_date", "kev_30d_label"],
                        dtype={"cve_id": str}, parse_dates=["decision_date"])
    panel["decision_date"] = panel["decision_date"].dt.strftime("%Y-%m-%d")
    dates_by_id = panel.groupby("cve_id", sort=False)["decision_date"].unique().to_dict()
    cve_ids = sorted(dates_by_id)
    batches = (len(cve_ids) + 99) // 100
    ASOF_ROWS.parent.mkdir(parents=True, exist_ok=True)
    ASOF_ROWS.unlink(missing_ok=True)
    write_header = True

    for batch_index in range(batches):
        path = HISTORY / f"batch_{batch_index:05d}.json.gz"
        if not path.exists():
            raise FileNotFoundError(f"History batch is incomplete: {path}")
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        events_by_id: dict[str, list[dict]] = defaultdict(list)
        for item in payload.get("cveChanges", []):
            change = item.get("change", {})
            if any(str(d.get("type", "")).startswith(("CVSS V3.", "CVSS V4.")) for d in change.get("details", [])):
                events_by_id[str(change.get("cveId", "")).upper()].append(change)

        batch_rows = []
        for cve_id in payload.get("cveIds", []):
            events = sorted(events_by_id.get(cve_id, []), key=lambda item: item.get("created", ""))
            decision_dates = sorted(pd.Timestamp(d) for d in dates_by_id.get(cve_id, []))
            state: dict[tuple[str, str], str] = {}
            event_index = 0
            for decision_date in decision_dates:
                cutoff = decision_date.tz_localize("UTC")
                while event_index < len(events):
                    created = pd.to_datetime(events[event_index].get("created"), utc=True, errors="coerce")
                    if pd.isna(created) or created >= cutoff:
                        if pd.isna(created):
                            event_index += 1
                            continue
                        break
                    apply_details(events[event_index].get("details", []), state)
                    event_index += 1
                batch_rows.append({"cve_id": cve_id, "decision_date": decision_date.strftime("%Y-%m-%d"), **select_asof(state)})
        if batch_rows:
            pd.DataFrame(batch_rows).to_csv(ASOF_ROWS, mode="a", header=write_header, index=False)
            write_header = False
        if (batch_index + 1) % 100 == 0 or batch_index + 1 == batches:
            print(f"Reconstructed {min((batch_index + 1) * 100, len(cve_ids)):,}/{len(cve_ids):,} CVE histories", flush=True)

    values = pd.read_csv(ASOF_ROWS, parse_dates=["decision_date"], low_memory=False)
    panel = pd.read_csv(PANEL, parse_dates=["published_date", "last_modified_date", "decision_date", "kev_date_added"], low_memory=False)
    if values.duplicated(["cve_id", "decision_date"]).any() or len(values) != len(panel):
        raise ValueError("Historical CVSS rows do not form a one-to-one match with the decision panel")
    panel = panel.merge(values, on=["cve_id", "decision_date"], how="left", validate="one_to_one")
    for score_col in ("cvss_score_asof", "cvss4_score_asof", "cvss_any_score_asof"):
        scores = pd.to_numeric(panel[score_col], errors="coerce").dropna()
        if not scores.between(0, 10).all():
            raise ValueError(f"{score_col} outside expected [0, 10] range")
    panel["cvss_v3"] = pd.to_numeric(panel["cvss_score_asof"], errors="coerce").where(panel["cvss_version_asof"].astype(str).isin({"3.0", "3.1"}))
    panel["cvss_any_score_asof"] = pd.to_numeric(panel["cvss_any_score_asof"], errors="coerce")
    panel["has_historical_cvss_3x"] = panel["cvss_v3"].notna().astype("int8")
    panel["has_historical_cvss_any"] = panel["cvss_any_score_asof"].notna().astype("int8")
    panel.to_csv(OUTPUT, index=False, date_format="%Y-%m-%d")
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    coverage = panel.groupby("decision_date").agg(
        eligible_rows=("cve_id", "size"),
        historical_cvss_3x_rows=("has_historical_cvss_3x", "sum"),
        historical_cvss_any_rows=("has_historical_cvss_any", "sum"),
        historical_cvss_4_rows=("cvss4_score_asof", "count"),
        future_kev_rows=("kev_30d_label", "sum"),
    ).reset_index()
    positive_coverage = panel.loc[panel["kev_30d_label"].eq(1)].groupby("decision_date")["has_historical_cvss_3x"].sum()
    coverage["future_kev_with_cvss"] = coverage["decision_date"].map(positive_coverage).fillna(0).astype(int)
    coverage["historical_cvss_3x_rate"] = coverage["historical_cvss_3x_rows"] / coverage["eligible_rows"]
    coverage.to_csv(SUMMARY, index=False)
    print(f"Wrote {OUTPUT} and {SUMMARY}", flush=True)


if __name__ == "__main__":
    main()
