"""
ULPF throughput benchmark.

Design target is 1,000-10,000 events/sec. This script measures what the
implementation actually achieves; it does not assert the target.

Reported numbers are single-process CPython on the machine that runs the
script. Any multi-worker figure printed here is an arithmetic projection and is
labelled as such - it has not been measured.

Throughput is reported as the MEDIAN of several independent runs together with
the observed range, and the design target is assessed against the SLOWEST run.
A single run of this workload varies by 20-30% on a general-purpose OS, so a
one-shot figure is not a measurement - it is a sample, and quoting the best
sample is the most common way benchmarks mislead.

Usage
    python scripts/benchmark.py                  # default: 5000 events
    python scripts/benchmark.py --events 20000
    python scripts/benchmark.py --json results.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.core.registry import default_registry  # noqa: E402
from backend.pipeline.orchestrator import PipelineOrchestrator  # noqa: E402
from backend.sample_data import SAMPLE_LOGS  # noqa: E402

STAGES = ["INGEST", "PARSE", "NORMALIZE", "VALIDATE", "STORE", "ML", "STANDARDIZED"]


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def build_corpus(n: int, realistic_mix: bool) -> List[str]:
    """Return n raw log lines.

    The 12 bundled samples are deliberately attack-heavy for demonstration. A
    realistic perimeter feed is overwhelmingly benign, and SIEM routing rates
    measured on the demo set would be misleading, so the realistic mix weights
    the benign samples to roughly 92% of traffic.
    """
    benign = {"cisco_asa_normal_http", "palo_alto_traffic_normal", "zeek_conn_log"}
    if not realistic_mix:
        pool = [s["raw"] for s in SAMPLE_LOGS]
    else:
        pool = []
        for s in SAMPLE_LOGS:
            weight = 23 if s["id"] in benign else 1
            pool.extend([s["raw"]] * weight)
    return [pool[i % len(pool)] for i in range(n)]


def run(events: int, realistic_mix: bool, warmup: int, batch_size: int = 0) -> Dict[str, Any]:
    tmp_dir = tempfile.mkdtemp(prefix="ulpf_bench_")
    db_path = os.path.join(tmp_dir, "bench.db")
    orch = PipelineOrchestrator(registry=default_registry, db_path=db_path)

    corpus = build_corpus(events + warmup, realistic_mix)

    # Warm up: import caches, first regex compiles, SQLite page cache. Measuring
    # these as steady-state throughput would understate it.
    for raw in corpus[:warmup]:
        orch.process_sync(raw)

    measured = corpus[warmup:]
    per_event_us: List[float] = []
    stage_us: Dict[str, List[float]] = {s: [] for s in STAGES}
    siem_routed = 0
    failures = 0

    wall_start = time.perf_counter()
    if batch_size:
        contexts = orch.process_batch(measured, batch_size=batch_size)
        per_event_us = [float(c.total_duration_us or 0) for c in contexts]
    else:
        contexts = []
        for raw in measured:
            t0 = time.perf_counter_ns()
            contexts.append(orch.process_sync(raw))
            per_event_us.append((time.perf_counter_ns() - t0) / 1000.0)

    for ctx in contexts:
        if ctx.error:
            failures += 1
            continue
        for m in ctx.stage_metrics:
            name = m.stage.value if hasattr(m.stage, "value") else str(m.stage)
            if name in stage_us:
                stage_us[name].append(float(m.duration_us))
        if ctx.normalized_event is not None:
            cls = ctx.normalized_event.classification or {}
            if cls.get("is_security_relevant"):
                siem_routed += 1
    wall = time.perf_counter() - wall_start

    n = len(measured)
    eps = n / wall if wall > 0 else 0.0

    return {
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "cpu_count": os.cpu_count(),
        },
        "config": {
            "events_measured": n,
            "warmup_events": warmup,
            "corpus": "realistic_mix" if realistic_mix else "demo_samples",
            "storage": "SQLite WAL (3 databases: primary, siem, datalake)",
            "ml_inference": (f"batched (size {batch_size})" if batch_size
                             else "per-event"),
        },
        "throughput": {
            "events_per_second": round(eps, 1),
            "wall_seconds": round(wall, 3),
            "failures": failures,
        },
        "latency_us": {
            "mean": round(statistics.fmean(per_event_us), 1),
            "p50": round(percentile(per_event_us, 50), 1),
            "p95": round(percentile(per_event_us, 95), 1),
            "p99": round(percentile(per_event_us, 99), 1),
            "max": round(max(per_event_us), 1),
        },
        "stage_mean_us": {
            s: round(statistics.fmean(v), 1) for s, v in stage_us.items() if v
        },
        "routing": {
            "security_relevant": siem_routed,
            "total": n,
            "siem_rate_pct": round(100.0 * siem_routed / n, 1) if n else 0.0,
        },
    }


def report(r: Dict[str, Any]) -> None:
    env, cfg = r["environment"], r["config"]
    tp, lat = r["throughput"], r["latency_us"]

    print()
    print("=" * 68)
    print("  ULPF THROUGHPUT BENCHMARK")
    print("=" * 68)
    print(f"  {env['implementation']} {env['python']} on {env['platform']}")
    print(f"  {env['cpu_count']} logical CPUs")
    print(f"  Corpus: {cfg['corpus']}  |  Storage: {cfg['storage']}")
    print(f"  ML inference: {cfg['ml_inference']}")
    print(f"  Measured {cfg['events_measured']} events "
          f"(after {cfg['warmup_events']} warm-up)")
    print("-" * 68)

    print(f"  MEASURED THROUGHPUT   {tp['events_per_second']:>12,.1f} events/sec"
          "   (median, 1 process, 1 core)")
    if tp.get("runs", 1) > 1:
        spread = ", ".join(f"{v:,.0f}" for v in tp["observed_eps"])
        print(f"  Range over {tp['runs']} runs      "
              f"{tp['min_eps']:>12,.1f} - {tp['max_eps']:,.1f} EPS   [{spread}]")
    print(f"  Wall time (median run){tp['wall_seconds']:>12.3f} s")
    print(f"  Failures              {tp['failures']:>12}")
    print()
    print("  Per-event latency (microseconds)")
    print(f"    mean {lat['mean']:>9,.1f}   p50 {lat['p50']:>9,.1f}   "
          f"p95 {lat['p95']:>9,.1f}   p99 {lat['p99']:>9,.1f}")
    print()
    print("  Mean time per stage (microseconds)")
    total_stage = sum(r["stage_mean_us"].values()) or 1.0
    for stage, us in sorted(r["stage_mean_us"].items(), key=lambda kv: -kv[1]):
        share = 100.0 * us / total_stage
        bar = "#" * max(1, int(share / 2.5))
        print(f"    {stage:<14} {us:>9,.1f}  {share:>5.1f}%  {bar}")
    print()

    rt = r["routing"]
    print(f"  Routing: {rt['security_relevant']}/{rt['total']} security-relevant "
          f"({rt['siem_rate_pct']}% to SIEM, 100% to Data Lake)")
    print("-" * 68)

    eps = tp.get("min_eps", tp["events_per_second"])   # judge on the worst run
    target_lo, target_hi = 1_000, 10_000
    print("  AGAINST THE 1,000-10,000 EPS DESIGN TARGET")
    print("  (assessed against the SLOWEST run, not the median)")
    if eps >= target_hi:
        print(f"    Single process meets the full target range.")
    elif eps >= target_lo:
        need = target_hi / eps
        print(f"    Single process meets the lower bound ({target_lo:,} EPS).")
        print(f"    Reaching {target_hi:,} EPS needs ~{need:.1f} parallel workers.")
    else:
        need = target_lo / eps
        print(f"    Single process is BELOW the lower bound.")
        print(f"    Reaching {target_lo:,} EPS needs ~{need:.1f} parallel workers.")

    print()
    print("  Projection (arithmetic, NOT measured - CPython releases the GIL")
    print("  only around I/O, so real scaling will be lower):")
    for w in (2, 4, 8):
        if w <= (r["environment"]["cpu_count"] or 1):
            print(f"    {w} workers  ->  ~{eps * w:>10,.0f} EPS (unverified)")
    print("=" * 68)
    print()


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure ULPF pipeline throughput.")
    ap.add_argument("--events", type=int, default=5000)
    ap.add_argument("--warmup", type=int, default=500)
    ap.add_argument("--demo-mix", action="store_true",
                    help="Use the attack-heavy demo samples instead of a "
                         "realistic mostly-benign traffic mix.")
    ap.add_argument("--batch", type=int, default=0,
                    help="Batch model inference at this size. 0 = per-event.")
    ap.add_argument("--repeat", type=int, default=3,
                    help="Independent runs. Throughput is reported as the "
                         "median with the observed range, because single-run "
                         "figures vary by 20-30%% on a general-purpose OS.")
    ap.add_argument("--json", type=str, default=None)
    args = ap.parse_args()

    runs = [
        run(args.events, realistic_mix=not args.demo_mix,
            warmup=args.warmup, batch_size=args.batch)
        for _ in range(max(1, args.repeat))
    ]
    observed = sorted(r["throughput"]["events_per_second"] for r in runs)
    result = runs[len(runs) // 2]          # the median run
    result["throughput"]["events_per_second"] = statistics.median(observed)
    result["throughput"]["runs"] = len(runs)
    result["throughput"]["observed_eps"] = observed
    result["throughput"]["min_eps"] = observed[0]
    result["throughput"]["max_eps"] = observed[-1]
    report(result)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"  Machine-readable results written to {args.json}\n")


if __name__ == "__main__":
    main()
