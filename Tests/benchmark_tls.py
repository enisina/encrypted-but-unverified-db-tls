import csv
import os
import random
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

import mysql.connector
import psycopg

DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME = os.environ["DB_NAME"]
PROJECT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_DIR / "Results"
CA_FILE = PROJECT_DIR / "Certificates" / "ca.pem"

CUSTOMER_ID = 5000
WARMUP_QUERIES = 100
MEASURED_QUERIES = 1000
INDEPENDENT_RUNS = 5
BATCH_SIZE = 100

TLS_MODES = ["plaintext", "encrypted_only", "verified_tls"]
DRIVERS = ["postgresql", "mysql"]

QUERIES = {
    "simple": ("SELECT 1", ()),
    "indexed_lookup": (
        "SELECT customer_id, full_name, email, city "
        "FROM customers WHERE customer_id = %s",
        (CUSTOMER_ID,),
    ),
    "join_lookup": (
        "SELECT c.customer_id, c.full_name, o.order_id, "
        "o.order_date, o.amount, o.status "
        "FROM customers c "
        "JOIN orders o ON o.customer_id = c.customer_id "
        "WHERE c.customer_id = %s ORDER BY o.order_id",
        (CUSTOMER_ID,),
    ),
}

OUTPUT_FILE = RESULTS_DIR / "benchmark_query_results.csv"
CONNECTION_OUTPUT_FILE = RESULTS_DIR / "benchmark_connection_results.csv"


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def percentile(values, fraction):
    ordered = sorted(values)
    index = round((len(ordered) - 1) * fraction)
    return ordered[index]


def connection_settings(driver, mode):
    if driver == "postgresql":
        settings = {
            "host": "localhost",
            "port": 5432,
            "dbname": DB_NAME,
            "user": DB_USER,
            "password": DB_PASSWORD,
            "connect_timeout": 5,
        }

        if mode == "plaintext":
            settings["sslmode"] = "disable"
        elif mode == "encrypted_only":
            settings["sslmode"] = "require"
        elif mode == "verified_tls":
            settings["sslmode"] = "verify-full"
            settings["sslrootcert"] = str(CA_FILE)
        else:
            raise ValueError(f"Unknown TLS mode: {mode}")

        return settings

    if driver != "mysql":
        raise ValueError(f"Unknown database driver: {driver}")

    settings = {
        "host": "localhost",
        "port": 3307,
        "database": DB_NAME,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "connection_timeout": 5,
    }

    if mode == "plaintext":
        settings["ssl_disabled"] = True
    elif mode == "encrypted_only":
        settings["ssl_ca"] = str(CA_FILE)
        settings["ssl_verify_cert"] = False
        settings["ssl_verify_identity"] = False
    elif mode == "verified_tls":
        settings["ssl_ca"] = str(CA_FILE)
        settings["ssl_verify_cert"] = True
        settings["ssl_verify_identity"] = True
    else:
        raise ValueError(f"Unknown TLS mode: {mode}")

    return settings


def connect_database(driver, mode):
    settings = connection_settings(driver, mode)

    if driver == "postgresql":
        return psycopg.connect(**settings)

    return mysql.connector.connect(**settings)


def measure_connection_time(driver, mode):
    """Time connection creation/authentication; close after stopping timer."""
    connection = None
    start = time.perf_counter_ns()

    try:
        connection = connect_database(driver, mode)
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        return elapsed_ms
    finally:
        if connection is not None:
            connection.close()


def execute_query(connection, driver, sql, parameters):
    cursor = connection.cursor()
    try:
        cursor.execute(sql, parameters)
        return cursor.fetchall()
    finally:
        cursor.close()


def connection_security(connection, driver):
    if driver == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT ssl, version, cipher "
                "FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
            )
            row = cursor.fetchone()

        if row is None:
            return False, "", "", ""

        return bool(row[0]), row[1] or "", row[2] or "", ""

    cursor = connection.cursor()
    try:
        cursor.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
        cipher_row = cursor.fetchone()
        cursor.execute("SHOW SESSION STATUS LIKE 'Ssl_version'")
        version_row = cursor.fetchone()
    finally:
        cursor.close()

    cipher = cipher_row[1] if cipher_row else ""
    version = version_row[1] if version_row else ""

    return bool(cipher), version, cipher, ""

def measure_connection_observation(driver, mode):
    """Measure connection establishment, then verify TLS separately."""
    settings = connection_settings(driver, mode)
    connection = None

    try:
        start = time.perf_counter_ns()

        if driver == "postgresql":
            connection = psycopg.connect(**settings)
        else:
            connection = mysql.connector.connect(**settings)

        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

        # Check actual TLS state after the timer stops.
        tls_enabled, tls_version, cipher, _ = connection_security(
            connection, driver
        )

        expected_tls = mode != "plaintext"

        if tls_enabled != expected_tls:
            raise RuntimeError(
                f"Unexpected TLS state for {driver} in {mode}: "
                f"tls_enabled={tls_enabled}"
            )

        return elapsed_ms, tls_enabled, tls_version, cipher

    finally:
        if connection is not None:
            connection.close()

def run_condition(driver, mode, run_number, warmups, measurements,
                  writer=None):
    print(f"\n{driver} | {mode} | run {run_number}")

    connection = connect_database(driver, mode)

    try:
        tls_enabled, tls_version, cipher, _ = connection_security(
            connection, driver
        )

        expected_tls = mode != "plaintext"
        if tls_enabled != expected_tls:
            raise RuntimeError(
                f"Unexpected TLS state: {driver}, {mode}, "
                f"TLS enabled={tls_enabled}"
            )

        results = {}
        query_names = list(QUERIES.keys())
        random.shuffle(query_names)

        for query_name in query_names:
            sql, parameters = QUERIES[query_name]

            # Warm-up queries are not included in the measurements.
            for _ in range(warmups):
                execute_query(connection, driver, sql, parameters)

            # Client-observed query round-trip, including fetching all rows.
            observed_results = []
            latencies = []
            for observation in range(1, measurements + 1):
                start = time.perf_counter_ns()
                rows = execute_query(connection, driver, sql, parameters)
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                latencies.append(elapsed_ms)

                if observation == 1:
                    observed_results = rows

                if writer is not None:
                    writer.writerow({
                        "timestamp_utc": timestamp(),
                        "driver": driver,
                        "tls_mode": mode,
                        "run": run_number,
                        "query": query_name,
                        "observation": observation,
                        "latency_ms": f"{elapsed_ms:.6f}",
                        "tls_enabled": tls_enabled,
                        "tls_version": tls_version,
                        "cipher": cipher,
                    })

                if observation % 250 == 0:
                    print(
                        f"  {query_name}: "
                        f"{observation}/{measurements} measured"
                    )

            results[query_name] = observed_results
            if latencies:
                median_ms = statistics.median(latencies)
                print(f"  {query_name}: median {median_ms:.6f} ms")

        return results
    finally:
        connection.close()


def run_connection_smoke_test():
    print("CONNECTION SMOKE TEST: small validation only.")

    for driver in DRIVERS:
        for mode in TLS_MODES:
            print(f"\n{driver} | {mode}")

            for _ in range(2):
                measure_connection_time(driver, mode)

            latencies = []
            for _ in range(3):
                elapsed_ms = measure_connection_time(driver, mode)
                latencies.append(elapsed_ms)

            median_ms = statistics.median(latencies)
            print(f"  Median fresh connection: {median_ms:.3f} ms")

    print("\nCONNECTION SMOKE TEST PASSED.")


def run_smoke_test():
    print("SMOKE TEST: small validation only.")
    print("No benchmark results will be written.")

    reference_results = {}
    for driver in DRIVERS:
        for mode in TLS_MODES:
            results = run_condition(
                driver=driver,
                mode=mode,
                run_number=0,
                warmups=2,
                measurements=3,
            )

            for query_name, rows in results.items():
                key = (driver, query_name)
                if key not in reference_results:
                    reference_results[key] = rows
                elif reference_results[key] != rows:
                    raise RuntimeError(
                        f"Query result mismatch for {driver}, "
                        f"{mode}, {query_name}"
                    )

    print("\nSMOKE TEST PASSED.")
    print("All six driver/mode combinations connected.")
    print("Query results matched across TLS modes.")


def run_full_benchmark():
    if not CA_FILE.exists():
        raise FileNotFoundError(f"CA certificate not found: {CA_FILE}")

    if OUTPUT_FILE.exists():
        raise FileExistsError(
            f"{OUTPUT_FILE} already exists. Refusing to overwrite previous results."
        )

    conditions = [
        (driver, mode)
        for driver in DRIVERS
        for mode in TLS_MODES
    ]

    print("FULL QUERY BENCHMARK")
    print(f"Warm-ups per query/condition/run: {WARMUP_QUERIES}")
    print(f"Measurements per query/condition/run: {MEASURED_QUERIES}")
    print(f"Independent runs: {INDEPENDENT_RUNS}")
    print(f"Raw results file: {OUTPUT_FILE}")
    print("This will take time. Do not interrupt it unnecessarily.")

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "timestamp_utc", "driver", "tls_mode", "run", "query",
            "observation", "latency_ms", "tls_enabled", "tls_version",
            "cipher",
        ]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        file.flush()

        for run_number in range(1, INDEPENDENT_RUNS + 1):
            print(f"\n========== QUERY RUN {run_number} ==========")
            random.shuffle(conditions)

            for driver, mode in conditions:
                run_condition(
                    driver=driver,
                    mode=mode,
                    run_number=run_number,
                    warmups=WARMUP_QUERIES,
                    measurements=MEASURED_QUERIES,
                    writer=writer,
                )
                file.flush()

    print("\nFull query benchmark completed.")
    print(f"Raw query results saved to: {OUTPUT_FILE}")


def run_full_connection_benchmark():
    if not CA_FILE.exists():
        raise FileNotFoundError(f"CA certificate not found: {CA_FILE}")

    if CONNECTION_OUTPUT_FILE.exists():
        raise FileExistsError(
            f"{CONNECTION_OUTPUT_FILE} already exists. "
            "Refusing to overwrite previous results."
        )

    conditions = [
        (driver, mode)
        for driver in DRIVERS
        for mode in TLS_MODES
    ]

    total = INDEPENDENT_RUNS * len(conditions) * (
        WARMUP_QUERIES + MEASURED_QUERIES
    )
    print("FULL FRESH-CONNECTION BENCHMARK")
    print(f"Warm-up connections per condition/run: {WARMUP_QUERIES}")
    print(f"Measured connections per condition/run: {MEASURED_QUERIES}")
    print(f"Independent runs: {INDEPENDENT_RUNS}")
    print(f"Total fresh connections, including warm-ups: {total}")
    print(f"Raw results file: {CONNECTION_OUTPUT_FILE}")
    print("Timing includes connect and authentication, not metadata query or close.")
    print("This will take time. Do not interrupt it unnecessarily.")

    with CONNECTION_OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        fieldnames = [
            "timestamp_utc", "driver", "tls_mode", "run", "observation",
            "latency_ms", "tls_enabled", "tls_version", "cipher",
        ]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        file.flush()

        for run_number in range(1, INDEPENDENT_RUNS + 1):
            print(f"\n========== CONNECTION RUN {run_number} ==========")
            random.shuffle(conditions)

            for driver, mode in conditions:
                print(f"\n{driver} | {mode}")

                # Warm-up connections are validated but not written as data.
                for _ in range(WARMUP_QUERIES):
                    measure_connection_observation(driver, mode)

                latencies = []
                for observation in range(1, MEASURED_QUERIES + 1):
                    elapsed_ms, tls_enabled, tls_version, cipher = (
                        measure_connection_observation(driver, mode)
                    )
                    latencies.append(elapsed_ms)
                    writer.writerow({
                        "timestamp_utc": timestamp(),
                        "driver": driver,
                        "tls_mode": mode,
                        "run": run_number,
                        "observation": observation,
                        "latency_ms": f"{elapsed_ms:.6f}",
                        "tls_enabled": tls_enabled,
                        "tls_version": tls_version,
                        "cipher": cipher,
                    })

                    if observation % 250 == 0:
                        print(
                            f"  {observation}/{MEASURED_QUERIES} measured"
                        )

                print(
                    "  Median fresh connection: "
                    f"{statistics.median(latencies):.3f} ms"
                )
                file.flush()

    print("\nFull fresh-connection benchmark completed.")
    print(f"Raw connection results saved to: {CONNECTION_OUTPUT_FILE}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="TLS database query and connection benchmark"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--smoke-test",
        action="store_true",
        help="Run a small query validation instead of a full benchmark",
    )
    group.add_argument(
        "--connection-smoke-test",
        action="store_true",
        help="Run a small fresh-connection timing validation",
    )
    group.add_argument(
        "--connection-benchmark",
        action="store_true",
        help="Run the full separate fresh-connection benchmark",
    )

    args = parser.parse_args()

    if args.connection_smoke_test:
        run_connection_smoke_test()
    elif args.smoke_test:
        run_smoke_test()
    elif args.connection_benchmark:
        run_full_connection_benchmark()
    else:
        run_full_benchmark()
