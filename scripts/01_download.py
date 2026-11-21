"""Download public NVD, EPSS, and CISA KEV source files.

Existing raw files are skipped. New downloads are written to a temporary file and
renamed only after the response has completed successfully.
"""
from __future__ import annotations

import csv
import datetime as dt
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
EPSS_DIR = RAW / "epss_decision_dates"
NVD_YEARS = range(2021, 2027)
DATES = [f"{year}-{month:02d}-19" for year in range(2022, 2027) for month in (2, 8)]
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
LOG = RAW / "download_log.csv"
LOG_HEADER = ("path", "url", "download_date")


def download(url: str, path: Path) -> None:
    if path.exists():
        print("skip (exists):", path.relative_to(ROOT))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    response = requests.get(url, timeout=120, stream=True)
    response.raise_for_status()
    try:
        with temporary.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    handle.write(chunk)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        response.close()

    needs_header = not LOG.exists() or LOG.stat().st_size == 0
    with LOG.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if needs_header:
            writer.writerow(LOG_HEADER)
        writer.writerow([str(path.relative_to(ROOT)), url, dt.date.today().isoformat()])
    print("downloaded:", path.relative_to(ROOT))


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    EPSS_DIR.mkdir(parents=True, exist_ok=True)
    download(KEV_URL, RAW / "known_exploited_vulnerabilities.json")
    for year in NVD_YEARS:
        download(NVD_URL.format(year=year), RAW / f"nvdcve-2.0-{year}.json.gz")
    for date in DATES:
        download(EPSS_URL.format(d=date), EPSS_DIR / f"epss_scores-{date}.csv.gz")


if __name__ == "__main__":
    main()
