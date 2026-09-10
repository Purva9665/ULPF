"""
Download the CIC-IDS2017 training corpus.

    python scripts/fetch_corpus.py

Only needed to *retrain* or *re-evaluate* the model. Running the prototype does
not require it - a trained model ships in `models/`.

Why a mirror
------------
The Canadian Institute for Cybersecurity now serves its download links behind a
registration page, so the official URL returns HTML rather than the archive.
This pulls the `GeneratedLabelledFlows` variant from a public HuggingFace
mirror and then verifies it, because a mirror is only trustworthy if you check
it: the loader must find exactly 2,830,743 usable flows, which is the flow
count published for this dataset. A mirror that has been altered will not match.

The IP-bearing variant is used deliberately. The more commonly cited
`MachineLearningCSV` variant strips source and destination addresses, and
without them entity behaviour profiling is impossible.

Citation
--------
Sharafaldin, Lashkari & Ghorbani, "Toward Generating a New Intrusion Detection
Dataset and Intrusion Traffic Characterization", ICISSP 2018.
"""

from __future__ import annotations

import os
import sys
import urllib.request

URL = ("https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/"
       "csvs/GeneratedLabelledFlows.zip")
DEST = os.path.join("data", "raw", "GeneratedLabelledFlows.zip")
EXPECTED_BYTES = 283_876_488
EXPECTED_FLOWS = 2_830_743


def _progress(count: int, block: int, total: int) -> None:
    if total <= 0:
        return
    done = min(100.0, count * block / total * 100)
    sys.stdout.write(f"\r    {done:5.1f}%  ({count * block / 1048576:.0f} MB)")
    sys.stdout.flush()


def main() -> int:
    os.makedirs(os.path.dirname(DEST), exist_ok=True)

    if os.path.exists(DEST) and os.path.getsize(DEST) == EXPECTED_BYTES:
        print(f"Corpus already present at {DEST}")
    else:
        print(f"Downloading CIC-IDS2017 (~271 MB) to {DEST}")
        urllib.request.urlretrieve(URL, DEST, _progress)
        print()

    size = os.path.getsize(DEST)
    if size != EXPECTED_BYTES:
        print(f"WARNING: expected {EXPECTED_BYTES:,} bytes, got {size:,}. "
              "The mirror may have changed; verify before training on it.")

    print("Verifying against the published flow count...")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from backend.ml.eval.corpus import LoadStats, iter_flows

    stats = LoadStats()
    for _ in iter_flows(DEST, stats=stats):
        pass

    print(f"    rows read       {stats.rows_read:,}")
    print(f"    usable flows    {stats.flows_yielded:,}")
    print(f"    blank rows      {stats.blank_rows:,}  (known defect in the "
          f"WebAttacks file)")
    print(f"    malformed       {stats.malformed_rows:,}")

    if stats.flows_yielded == EXPECTED_FLOWS:
        print(f"\nOK - {EXPECTED_FLOWS:,} flows, matching the published count.")
        return 0
    print(f"\nMISMATCH - expected {EXPECTED_FLOWS:,} flows, found "
          f"{stats.flows_yielded:,}. Do not train on this copy without "
          f"establishing why it differs.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
