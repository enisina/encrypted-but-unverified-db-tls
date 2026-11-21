
import csv
import os
import sys
from datetime import datetime
from pathlib import Path

import psycopg
import mysql.connector


# --------------------------------------------------
# Project paths and test settings
# --------------------------------------------------

PROJECT_FOLDER = Path(__file__).resolve().parent.parent
CERTIFICATE_FILE = PROJECT_FOLDER / "Certificates" / "ca.pem"
RESULTS_FILE = PROJECT_FOLDER / "Results" / "tls_matrix_results.csv"

TRIALS = 5

DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME = os.environ["DB_NAME"]

MODES = {
    "M0": "TLS unavailable",
    "M1": "Untrusted self-signed certificate",
    "M2": "Trusted certificate, correct hostname",
    "M3": "Trusted certificate, incorrect hostname",
}

CSV_FIELDS = [
    "timestamp",
    "mode",
    "mode_description",
    "driver",
    "configuration",
    "trial",
    "connection_success",
    "tls_enabled",
    "tls_version",
    "cipher",
    "error_type",
    "error_message",
    "hostname_test_method",
]


# --------------------------------------------------
# Read the requested server mode
# --------------------------------------------------

if len(sys.argv) != 2:
    print("Please specify one server mode:")
    print("python .\\Tests\\test_tls_matrix.py M2")
    sys.exit(1)

mode = sys.argv[1].upper()

if mode not in MODES:
    print("Invalid mode. Choose M0, M1, M2, or M3.")
    sys.exit(1)

if not CERTIFICATE_FILE.exists():
    print("ERROR: CA certificate not found:")
    print(CERTIFICATE_FILE)
    sys.exit(1)

print("=" * 60)
print("T4-B TLS MATRIX TEST")
print("=" * 60)
print("Mode:", mode)
print("Description:", MODES[mode])
print("Trials per configuration:", TRIALS)
print("Results file:", RESULTS_FILE)
print()
print("IMPORTANT: Confirm that BOTH database servers are")
print("currently configured for the selected mode.")
print()

confirmation = input(
    "Type " + mode + " to confirm the server configuration: "
).strip().upper()

if confirmation != mode:
    print("Confirmation did not match. No tests were run.")
    sys.exit(0)


# --------------------------------------------------
# Hostname test details
# --------------------------------------------------

if mode == "M3":
    POSTGRES_HOST = "wrong.example"
    MYSQL_HOST = "127.0.0.2"

    POSTGRES_HOSTADDR = "127.0.0.1"

    hostname_method = (
        "PostgreSQL: wrong.example routed to 127.0.0.1; "
        "MySQL: 127.0.0.2 differs from certificate SAN 127.0.0.1"
    )
else:
    POSTGRES_HOST = "localhost"
    MYSQL_HOST = "localhost"
    POSTGRES_HOSTADDR = None
    hostname_method = "Correct hostname: localhost"


# --------------------------------------------------
# PostgreSQL test
# --------------------------------------------------

def test_postgresql(configuration, trial):

    print(
        f"PostgreSQL | {configuration} | Trial {trial}",
        flush=True
    )

    connection = None

    row = {
        "timestamp": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "mode": mode,
        "mode_description": MODES[mode],
        "driver": "Psycopg 3.3.9",
        "configuration": configuration,
        "trial": trial,
        "connection_success": "NO",
        "tls_enabled": "",
        "tls_version": "",
        "cipher": "",
        "error_type": "",
        "error_message": "",
        "hostname_test_method": hostname_method,
    }

    try:
        parameters = {
            "host": POSTGRES_HOST,
            "port": 5432,
            "dbname": DB_NAME,
            "user": DB_USER,
            "password": DB_PASSWORD,
            "connect_timeout": 5,
        }

        if POSTGRES_HOSTADDR is not None:
            parameters["hostaddr"] = POSTGRES_HOSTADDR

        if configuration == "verified":
            parameters["sslmode"] = "verify-full"
            parameters["sslrootcert"] = str(CERTIFICATE_FILE)

        connection = psycopg.connect(**parameters)

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT ssl, version, cipher
                FROM pg_stat_ssl
                WHERE pid = pg_backend_pid()
            """)

            result = cursor.fetchone()

        row["connection_success"] = "YES"

        if result:
            row["tls_enabled"] = "YES" if result[0] else "NO"
            row["tls_version"] = result[1] or ""
            row["cipher"] = result[2] or ""

    except Exception as error:
        row["error_type"] = type(error).__name__
        row["error_message"] = str(error)

    finally:
        if connection is not None:
            connection.close()

    return row


# --------------------------------------------------
# MySQL test
# --------------------------------------------------

def test_mysql(configuration, trial):

    print(
        f"MySQL | {configuration} | Trial {trial}",
        flush=True
    )

    connection = None
    cursor = None

    row = {
        "timestamp": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "mode": mode,
        "mode_description": MODES[mode],
        "driver": "MySQL Connector/Python 26.10.0",
        "configuration": configuration,
        "trial": trial,
        "connection_success": "NO",
        "tls_enabled": "",
        "tls_version": "",
        "cipher": "",
        "error_type": "",
        "error_message": "",
        "hostname_test_method": hostname_method,
    }

    try:
        parameters = {
            "host": MYSQL_HOST,
            "port": 3307,
            "database": DB_NAME,
            "user": DB_USER,
            "password": DB_PASSWORD,
            "connection_timeout": 5,
        }

        if configuration == "verified":
            parameters["ssl_ca"] = str(CERTIFICATE_FILE)
            parameters["ssl_verify_cert"] = True
            parameters["ssl_verify_identity"] = True

        connection = mysql.connector.connect(**parameters)

        cursor = connection.cursor()

        cursor.execute(
            "SHOW SESSION STATUS LIKE 'Ssl_cipher'"
        )
        cipher_result = cursor.fetchone()

        cursor.execute(
            "SHOW SESSION STATUS LIKE 'Ssl_version'"
        )
        version_result = cursor.fetchone()

        cipher = cipher_result[1] if cipher_result else ""
        version = version_result[1] if version_result else ""

        row["connection_success"] = "YES"
        row["tls_enabled"] = "YES" if cipher else "NO"
        row["tls_version"] = version or ""
        row["cipher"] = cipher or ""

    except Exception as error:
        row["error_type"] = type(error).__name__
        row["error_message"] = str(error)

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()

    return row


# --------------------------------------------------
# Prepare the CSV results file
# --------------------------------------------------

RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)

write_header = (
    not RESULTS_FILE.exists()
    or RESULTS_FILE.stat().st_size == 0
)


# --------------------------------------------------
# Run all tests and save each result immediately
# --------------------------------------------------

print()
print("Starting tests...")
print()

with RESULTS_FILE.open(
    "a",
    newline="",
    encoding="utf-8"
) as csv_file:

    writer = csv.DictWriter(
        csv_file,
        fieldnames=CSV_FIELDS
    )

    if write_header:
        writer.writeheader()
        csv_file.flush()

    for configuration in ["default", "verified"]:

        for trial in range(1, TRIALS + 1):

            postgres_result = test_postgresql(
                configuration,
                trial
            )

            writer.writerow(postgres_result)
            csv_file.flush()

            mysql_result = test_mysql(
                configuration,
                trial
            )

            writer.writerow(mysql_result)
            csv_file.flush()


print()
print("=" * 60)
print("TEST BATCH COMPLETED")
print("=" * 60)
print("Mode:", mode)
print("Connection attempts:", TRIALS * 2 * 2)
print("Results saved to:")
print(RESULTS_FILE)
print()
print("Remember: connection success and TLS encryption")
print("are separate measurements. Check both in the CSV.")
