import csv
import os
import socket
from contextlib import contextmanager
from pathlib import Path
from importlib.metadata import version

import psycopg2
import pg8000.dbapi
import pymysql


DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME = os.environ["DB_NAME"]

OUTPUT = Path("Results/additional_drivers_default_matrix.csv")

SCENARIOS = {
    "M1": {
        "postgres_port": 55433,
        "mysql_port": 3307,
        "hostname": "localhost",
    },
    "M2": {
        "postgres_port": 55432,
        "mysql_port": 33307,
        "hostname": "localhost",
    },
    "M3": {
        "postgres_port": 55432,
        "mysql_port": 33307,
        "hostname": "wrong.example",
    },
}


@contextmanager
def redirect_wrong_hostname():
    original = socket.create_connection

    def redirected(address, *args, **kwargs):
        host, port = address
        if host == "wrong.example":
            address = ("127.0.0.1", port)
        return original(address, *args, **kwargs)

    socket.create_connection = redirected
    try:
        yield
    finally:
        socket.create_connection = original


def postgres_tls(cursor):
    cursor.execute("""
        SELECT ssl, version, cipher
        FROM pg_stat_ssl
        WHERE pid = pg_backend_pid()
    """)
    result = cursor.fetchone()
    if result:
        encrypted, tls_version, cipher = result
        return tls_version if encrypted else "None", cipher or ""
    return "Unknown", ""


def mysql_tls(cursor):
    cursor.execute("SHOW SESSION STATUS LIKE 'Ssl_version'")
    tls_version = cursor.fetchone()[1]

    cursor.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
    cipher = cursor.fetchone()[1]

    return tls_version or "None", cipher or ""


def run_test(driver, scenario, config):
    hostname = config["hostname"]
    port = (
        config["mysql_port"]
        if driver == "PyMySQL"
        else config["postgres_port"]
    )

    row = {
        "driver": driver,
        "version": "",
        "scenario": scenario,
        "hostname": hostname,
        "port": port,
        "observed_result": "Rejected",
        "exception": "",
        "tls_version": "",
        "cipher": "",
    }

    connection = None
    cursor = None

    try:
        if driver == "psycopg2":
            row["version"] = version("psycopg2-binary")
            kwargs = {
                "host": hostname,
                "port": port,
                "dbname": DB_NAME,
                "user": DB_USER,
                "password": DB_PASSWORD,
                "connect_timeout": 5,
            }
            if scenario == "M3":
                kwargs["hostaddr"] = "127.0.0.1"

            connection = psycopg2.connect(**kwargs)

        elif driver == "pg8000":
            row["version"] = version("pg8000")
            kwargs = {
                "host": hostname,
                "port": port,
                "database": DB_NAME,
                "user": DB_USER,
                "password": DB_PASSWORD,
                "timeout": 5,
            }
            if scenario == "M3":
                with redirect_wrong_hostname():
                    connection = pg8000.dbapi.connect(**kwargs)
            else:
                connection = pg8000.dbapi.connect(**kwargs)

        elif driver == "PyMySQL":
            row["version"] = version("PyMySQL")
            kwargs = {
                "host": hostname,
                "port": port,
                "database": DB_NAME,
                "user": DB_USER,
                "password": DB_PASSWORD,
                "connect_timeout": 5,
            }
            if scenario == "M3":
                with redirect_wrong_hostname():
                    connection = pymysql.connect(**kwargs)
            else:
                connection = pymysql.connect(**kwargs)

        cursor = connection.cursor()

        if driver == "PyMySQL":
            tls_version, cipher = mysql_tls(cursor)
        else:
            tls_version, cipher = postgres_tls(cursor)

        row["observed_result"] = "Accepted"
        row["tls_version"] = tls_version
        row["cipher"] = cipher

    except Exception as error:
        row["exception"] = type(error).__name__ + ": " + str(error)

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()

    print(
        f'{driver} {scenario}: {row["observed_result"]}; '
        f'TLS={row["tls_version"] or "N/A"}; '
        f'exception={row["exception"] or "None"}'
    )

    return row


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    for scenario, config in SCENARIOS.items():
        for driver in ("psycopg2", "pg8000", "PyMySQL"):
            rows.append(run_test(driver, scenario, config))

    fields = [
        "driver", "version", "scenario", "hostname", "port",
        "observed_result", "exception", "tls_version", "cipher",
    ]

    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print("\nTotal observations:", len(rows))
    print("Accepted:", sum(r["observed_result"] == "Accepted" for r in rows))
    print("Rejected:", sum(r["observed_result"] == "Rejected" for r in rows))
    print("Saved:", OUTPUT)


if __name__ == "__main__":
    main()
