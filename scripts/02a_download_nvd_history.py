"""Download timestamped NVD CVE histories in resumable batches.

The NVD history endpoint returns changes (including CVSS vector changes), not
complete historical CVE snapshots. Raw JSON pages are preserved as gzip files.
Set NVD_API_KEY to use the higher authenticated request limit; without a key,
the script spaces requests to remain under the public limit.
"""
from __future__ import annotations

import gzip
import json
import os
import time
from pathlib import Path
from urllib.parse import urlencode

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "data" / "processed" / "ssot_final.csv"
OUTPUT = ROOT / "data" / "raw" / "nvd_cvss_history"
BASE_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
BATCH_SIZE = 100
PAGE_SIZE = 5000
PUBLIC_MIN_REQUEST_INTERVAL = 6.1


def main() -> None:
    if not PANEL.exists():
        raise FileNotFoundError(f"Build the decision panel first: {PANEL}")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    cve_ids = pd.read_csv(PANEL, usecols=["cve_id"], dtype={"cve_id": str})["cve_id"]
    cve_ids = sorted(cve_ids.dropna().str.strip().str.upper().unique())
    batches = [cve_ids[i:i + BATCH_SIZE] for i in range(0, len(cve_ids), BATCH_SIZE)]
    api_key = os.environ.get("NVD_API_KEY")
    min_interval = 0.61 if api_key else PUBLIC_MIN_REQUEST_INTERVAL
    headers = {"apiKey": api_key} if api_key else {}
    session = requests.Session()
    last_request_started = 0.0
    completed = 0
    total_events = 0

    def get_page(params: dict) -> dict:
        nonlocal last_request_started
        for attempt in range(8):
            wait = min_interval - (time.monotonic() - last_request_started)
            if wait > 0:
                time.sleep(wait)
            last_request_started = time.monotonic()
            try:
                response = session.get(BASE_URL, params=params, headers=headers, timeout=90)
                if response.status_code == 429:
                    time.sleep(max(30, int(response.headers.get("Retry-After", "30"))))
                    continue
                response.raise_for_status()
                return response.json()
            except (requests.RequestException, ValueError):
                if attempt == 7:
                    raise
                time.sleep(min(60, 2 ** (attempt + 1)))
        raise RuntimeError("NVD history request retries exhausted")

    for index, ids in enumerate(batches):
        destination = OUTPUT / f"batch_{index:05d}.json.gz"
        if destination.exists():
            completed += 1
            continue
        records = []
        start_index = 0
        while True:
            params = {"cveIds": ",".join(ids), "resultsPerPage": PAGE_SIZE, "startIndex": start_index}
            payload = get_page(params)
            page = payload.get("cveChanges", [])
            records.extend(page)
            start_index += len(page)
            if start_index >= int(payload.get("totalResults", 0)) or not page:
                break
        saved = {"format": "NVD_CVEHistory", "version": "2.0", "cveIds": ids, "cveChanges": records}
        temporary = destination.with_suffix(destination.suffix + ".partial")
        with gzip.open(temporary, "wt", encoding="utf-8") as handle:
            json.dump(saved, handle, separators=(",", ":"))
        temporary.replace(destination)
        completed += 1
        total_events += len(records)
        if completed % 10 == 0 or completed == len(batches):
            print(f"History batches complete: {completed:,}/{len(batches):,}; events downloaded this run: {total_events:,}", flush=True)
    print(f"Done. {len(cve_ids):,} CVE IDs; batches saved under {OUTPUT}.", flush=True)


if __name__ == "__main__":
    main()
