"""01_download.py: re-download EPSS decision-date files and the KEV catalogue.
Raw files are never edited. Existing files are skipped.
Run from the repo root: python scripts/01_download.py
"""
import csv
import datetime
import os
import requests

RAW = "data/raw"
EPSS_DIR = os.path.join(RAW, "19th_Feb")
DATES = ["2022-02-19", "2023-02-19", "2024-02-19", "2025-02-19", "2026-02-19"]
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
LOG = os.path.join(RAW, "download_log.csv")


def download(url, path):
    if os.path.exists(path):
        print("skip (exists):", path)
        return
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    with open(path, "wb") as f:
        f.write(r.content)
    with open(LOG, "a", newline="") as f:
        csv.writer(f).writerow([path, url, datetime.date.today().isoformat()])
    print("downloaded:", path)


os.makedirs(EPSS_DIR, exist_ok=True)
download(KEV_URL, os.path.join(RAW, "known_exploited_vulnerabilities.json"))
for d in DATES:
    download(EPSS_URL.format(d=d), os.path.join(EPSS_DIR, f"epss_scores-{d}.csv.gz"))
