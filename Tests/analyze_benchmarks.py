
import csv
import random
import statistics
from collections import defaultdict
from pathlib import Path

# Project folders
ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "Results"

QUERY_FILE = RESULTS / "benchmark_query_results.csv"
CONNECTION_FILE = RESULTS / "benchmark_connection_results.csv"

# New output files. Existing files will never be overwritten.
OUTPUT_FILES = [
    RESULTS / "query_run_summaries.csv",
    RESULTS / "connection_run_summaries.csv",
    RESULTS / "tls_overhead_summary.csv",
    RESULTS / "analysis_report.txt",
]

BOOTSTRAP_ITERATIONS = 20000
RANDOM_SEED = 42


def read_csv(path):
    with path.open("r", newline="", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def summarize_runs(rows, group_fields):
    groups = defaultdict(list)

    for row in rows:
        key = tuple(row[field] for field in group_fields)
        groups[key].append(float(row["latency_ms"]))

    summaries = []
    for key, values in sorted(groups.items()):
        summaries.append({
            **dict(zip(group_fields, key)),
            "observations": len(values),
            "median_ms": statistics.median(values),
            "p95_ms": percentile(values, 0.95),
        })

    return summaries


def write_csv(path, rows):
    if not rows:
        raise ValueError(f"No data to write: {path.name}")

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def bootstrap_median_ci(values, rng):
    """Percentile bootstrap CI of the median of paired run-level effects."""
    estimates = []
    for _ in range(BOOTSTRAP_ITERATIONS):
        sample = [rng.choice(values) for _ in values]
        estimates.append(statistics.median(sample))

    return percentile(estimates, 0.025), percentile(estimates, 0.975)


def analyze_overhead(query_summaries, connection_summaries):
    rng = random.Random(RANDOM_SEED)
    results = []

    datasets = [
        ("query", query_summaries, ["driver", "query"]),
        ("connection", connection_summaries, ["driver"]),
    ]

    for dataset_name, summaries, dimensions in datasets:
        lookup = {}

        for row in summaries:
            key = tuple(row[field] for field in dimensions)
            lookup[(key, row["tls_mode"], row["run"])] = row["median_ms"]

        all_keys = sorted({key for key, _, _ in lookup})

        for key in all_keys:
            for tls_mode in ("encrypted_only", "verified_tls"):
                differences = []
                percentages = []

                for run in ("1", "2", "3", "4", "5"):
                    plain_key = (key, "plaintext", run)
                    tls_key = (key, tls_mode, run)

                    if plain_key not in lookup or tls_key not in lookup:
                        raise ValueError(
                            f"Missing paired run data: {dataset_name}, {key}, "
                            f"{tls_mode}, run {run}"
                        )

                    plain = lookup[plain_key]
                    secure = lookup[tls_key]

                    differences.append(secure - plain)
                    percentages.append(100 * (secure - plain) / plain)

                diff_ci = bootstrap_median_ci(differences, rng)
                pct_ci = bootstrap_median_ci(percentages, rng)

                row = {
                    "dataset": dataset_name,
                    **dict(zip(dimensions, key)),
                    "tls_mode": tls_mode,
                    "paired_runs": len(differences),
                    "median_difference_ms": statistics.median(differences),
                    "difference_ci95_low_ms": diff_ci[0],
                    "difference_ci95_high_ms": diff_ci[1],
                    "median_overhead_percent": statistics.median(percentages),
                    "overhead_ci95_low_percent": pct_ci[0],
                    "overhead_ci95_high_percent": pct_ci[1],
                }
                results.append(row)

    return results


def main():
    for path in (QUERY_FILE, CONNECTION_FILE):
        if not path.exists():
            raise FileNotFoundError(f"Required input file is missing: {path}")

    existing = [path.name for path in OUTPUT_FILES if path.exists()]
    if existing:
        raise FileExistsError(
            "To protect existing results, the script will not overwrite: "
            + ", ".join(existing)
        )

    print("Reading benchmark data...")
    query_rows = read_csv(QUERY_FILE)
    connection_rows = read_csv(CONNECTION_FILE)

    print(f"Query observations: {len(query_rows)}")
    print(f"Connection observations: {len(connection_rows)}")

    query_summaries = summarize_runs(
        query_rows, ["driver", "tls_mode", "query", "run"]
    )
    connection_summaries = summarize_runs(
        connection_rows, ["driver", "tls_mode", "run"]
    )

    overhead = analyze_overhead(query_summaries, connection_summaries)

    write_csv(OUTPUT_FILES[0], query_summaries)
    write_csv(OUTPUT_FILES[1], connection_summaries)
    write_csv(OUTPUT_FILES[2], overhead)

    with OUTPUT_FILES[3].open("w", encoding="utf-8") as report:
        report.write("T4-B TLS BENCHMARK ANALYSIS\n")
        report.write("===========================\n\n")
        report.write(f"Query observations: {len(query_rows)}\n")
        report.write(f"Connection observations: {len(connection_rows)}\n")
        report.write("Independent runs: 5\n")
        report.write(f"Bootstrap iterations: {BOOTSTRAP_ITERATIONS}\n")
        report.write("Random seed: 42\n\n")
        report.write(
            "Latency summaries use the median and 95th percentile of "
            "observations within each run and condition.\n"
        )
        report.write(
            "Overhead compares paired run-level medians against plaintext.\n"
        )
        report.write(
            "Confidence intervals are percentile bootstrap intervals "
            "resampling the five paired run-level effects.\n\n"
        )
        report.write(
            "IMPORTANT LIMITATION:\n"
            "There are only five independent runs. Bootstrap intervals "
            "based on five run-level effects are exploratory and may be "
            "unstable. Individual observations within a run are not treated "
            "as independent experimental runs.\n"
        )
        report.write(
            "Query latency measures client-observed query execution and "
            "result fetching on an established connection. Connection "
            "latency measures fresh connection establishment separately.\n"
        )

    print("\nAnalysis completed successfully.")
    for path in OUTPUT_FILES:
        print(f"Created: {path}")

    print("\nNo raw benchmark files were modified.")


if __name__ == "__main__":
    main()
