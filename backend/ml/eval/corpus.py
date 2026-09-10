"""
CIC-IDS2017 corpus loader.

Source: Sharafaldin, Lashkari & Ghorbani, "Toward Generating a New Intrusion
Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.
Capture window: Monday 3 July - Friday 7 July 2017.

We use the `GeneratedLabelledFlows` variant rather than the more commonly cited
`MachineLearningCSV` variant for one specific reason: it retains **Source IP**
and **Destination IP**. Entity behaviour profiling is impossible without them,
and the ML variant strips them. Papers that use the ML variant therefore cannot
do per-entity baselining at all, which is part of why per-flow classification
is the norm in that literature.

Known defects, handled explicitly rather than silently
------------------------------------------------------
* 288,602 completely empty rows padding the WebAttacks file. Skipped and
  counted, not quietly dropped.
* Attack labels use a Windows-1252 en-dash (0x96) in "Web Attack - *".
  Normalised to ASCII so downstream code never has to think about encoding.
* Some flows carry infinite or NaN rate columns (division by zero duration).
  We do not read those columns, but the row is still validated.
* Label quality issues are documented by Engelen, Rimmer & Joosen, "Troubleshooting
  an Intrusion Detection Dataset: the CICIDS2017 Case Study" (IEEE S&P Workshops,
  2021). We do not attempt to correct labels - we report the dataset as
  published and cite the caveat.

Only the columns a perimeter device would actually emit are read. CIC-IDS2017
carries 85 columns, most derived from full packet capture (per-direction IAT
standard deviations, bulk rates, subflow statistics). A firewall or IDS log
does not contain those. Training on them would inflate every metric and produce
a model that cannot run on the data this framework is built to ingest.
"""

from __future__ import annotations

import csv
import io
import os
import zipfile
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterator, List, Optional, Sequence

#: Default corpus location, overridable for CI or an alternate checkout.
DEFAULT_CORPUS = os.environ.get(
    "ULPF_CORPUS_PATH",
    os.path.join("data", "raw", "GeneratedLabelledFlows.zip"),
)

#: IANA protocol numbers that appear in this corpus.
PROTOCOL_NAMES: Dict[int, str] = {0: "HOPOPT", 1: "ICMP", 6: "TCP", 17: "UDP"}

#: Capture day -> the attack families introduced that day. Used for the
#: cross-day generalisation protocol, and to explain results.
DAY_ATTACKS: Dict[str, List[str]] = {
    "Monday": [],
    "Tuesday": ["FTP-Patator", "SSH-Patator"],
    "Wednesday": ["DoS Hulk", "DoS GoldenEye", "DoS slowloris",
                  "DoS Slowhttptest", "Heartbleed"],
    "Thursday": ["Web Attack - Brute Force", "Web Attack - XSS",
                 "Web Attack - Sql Injection", "Infiltration"],
    "Friday": ["Bot", "PortScan", "DDoS"],
}

#: Column indices in the GeneratedLabelledFlows schema. Positional rather than
#: by-name because the published headers carry inconsistent leading whitespace
#: and one duplicated name ("Fwd Header Length" appears twice).
COL = {
    "src_ip": 1, "src_port": 2, "dst_ip": 3, "dst_port": 4, "protocol": 5,
    "timestamp": 6, "duration": 7,
    "fwd_packets": 8, "bwd_packets": 9, "fwd_bytes": 10, "bwd_bytes": 11,
    "label": 84,
}


@dataclass(frozen=True)
class FlowRecord:
    """One labelled flow, reduced to what a perimeter device could report."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    timestamp: datetime
    duration_us: int
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    label: str
    day: str
    source_file: str

    @property
    def is_attack(self) -> bool:
        return self.label != "BENIGN"

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets


@dataclass
class LoadStats:
    """What the loader saw, so data loss is reported rather than assumed."""

    rows_read: int = 0
    flows_yielded: int = 0
    blank_rows: int = 0
    malformed_rows: int = 0
    unparseable_timestamps: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "rows_read": self.rows_read,
            "flows_yielded": self.flows_yielded,
            "blank_rows": self.blank_rows,
            "malformed_rows": self.malformed_rows,
            "unparseable_timestamps": self.unparseable_timestamps,
        }


def normalise_label(raw: str) -> str:
    """ASCII-normalise a published label.

    The corpus encodes "Web Attack \\x96 Brute Force" in Windows-1252. Left
    alone it produces encoding errors on every Windows console and silently
    splits one class into two whenever a consumer decodes differently.
    """
    text = raw.strip().replace("\x96", "-").replace("–", "-")
    return " ".join(text.split())


def day_of(filename: str) -> str:
    base = os.path.basename(filename)
    for day in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday"):
        if base.lower().startswith(day.lower()):
            return day
    return "Unknown"


def _parse_timestamp(text: str) -> Optional[datetime]:
    """Parse the corpus timestamp.

    The capture ran 3-7 July 2017, so a leading value above 12 disambiguates
    day-first from month-first. Both orders appear across the files, and
    getting this wrong silently reorders the entire corpus - which would
    destroy any chronological split built on top of it.
    """
    text = text.strip()
    if not text:
        return None
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
                "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _as_int(text: str) -> int:
    try:
        value = float(text)
    except (TypeError, ValueError):
        return 0
    if value != value or value in (float("inf"), float("-inf")):  # NaN / inf
        return 0
    return int(value)


def iter_flows(
    corpus_path: str = DEFAULT_CORPUS,
    *,
    days: Optional[Sequence[str]] = None,
    limit: Optional[int] = None,
    stats: Optional[LoadStats] = None,
) -> Iterator[FlowRecord]:
    """Stream labelled flows from the corpus zip.

    Streams rather than loading into a DataFrame: the full corpus is 1.1 GB of
    CSV and only a dozen of its 85 columns are ever used. Streaming keeps peak
    memory flat and lets a caller take a slice without paying for the rest.

    `days` filters by capture day, which is how the cross-day generalisation
    protocol is expressed.
    """
    if not os.path.exists(corpus_path):
        raise FileNotFoundError(
            f"Corpus not found at {corpus_path}. "
            "Run scripts/fetch_corpus.py, or set ULPF_CORPUS_PATH."
        )
    st = stats if stats is not None else LoadStats()
    wanted = set(days) if days else None
    yielded = 0

    with zipfile.ZipFile(corpus_path) as archive:
        names = sorted(n for n in archive.namelist() if n.endswith(".csv"))
        for name in names:
            day = day_of(name)
            if wanted is not None and day not in wanted:
                continue
            with archive.open(name) as handle:
                # latin-1 never raises on arbitrary bytes, so a stray 0x96 in a
                # label cannot abort a 700 MB read partway through.
                reader = csv.reader(io.TextIOWrapper(handle, encoding="latin-1"))
                try:
                    next(reader)
                except StopIteration:
                    continue
                for row in reader:
                    st.rows_read += 1
                    if not row or not any(cell.strip() for cell in row):
                        st.blank_rows += 1
                        continue
                    if len(row) <= COL["label"]:
                        st.malformed_rows += 1
                        continue
                    ts = _parse_timestamp(row[COL["timestamp"]])
                    if ts is None:
                        st.unparseable_timestamps += 1
                        continue
                    proto_num = _as_int(row[COL["protocol"]])
                    record = FlowRecord(
                        src_ip=row[COL["src_ip"]].strip(),
                        src_port=_as_int(row[COL["src_port"]]),
                        dst_ip=row[COL["dst_ip"]].strip(),
                        dst_port=_as_int(row[COL["dst_port"]]),
                        protocol=PROTOCOL_NAMES.get(proto_num, f"PROTO_{proto_num}"),
                        timestamp=ts,
                        duration_us=_as_int(row[COL["duration"]]),
                        fwd_packets=_as_int(row[COL["fwd_packets"]]),
                        bwd_packets=_as_int(row[COL["bwd_packets"]]),
                        fwd_bytes=_as_int(row[COL["fwd_bytes"]]),
                        bwd_bytes=_as_int(row[COL["bwd_bytes"]]),
                        label=normalise_label(row[COL["label"]]),
                        day=day,
                        source_file=os.path.basename(name),
                    )
                    if not record.src_ip or not record.dst_ip:
                        st.malformed_rows += 1
                        continue
                    st.flows_yielded += 1
                    yielded += 1
                    yield record
                    if limit is not None and yielded >= limit:
                        return


def summarise(corpus_path: str = DEFAULT_CORPUS,
              limit: Optional[int] = None) -> Dict[str, object]:
    """Label and day distribution. Used by the corpus verification test."""
    from collections import Counter

    st = LoadStats()
    labels: "Counter[str]" = Counter()
    by_day: "Counter[str]" = Counter()
    for flow in iter_flows(corpus_path, limit=limit, stats=st):
        labels[flow.label] += 1
        by_day[flow.day] += 1
    return {
        "stats": st.as_dict(),
        "labels": dict(labels.most_common()),
        "by_day": dict(by_day),
        "attack_ratio": round(
            sum(v for k, v in labels.items() if k != "BENIGN") / max(sum(labels.values()), 1), 4
        ),
    }
