from pathlib import Path
import os
import ssl
import psycopg2
import pg8000.dbapi
import pymysql

DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME = os.environ["DB_NAME"]

CA_FILE = Path("Certificates/ca.pem").resolve()


def test_psycopg2():
    print("\n=== Psycopg 2: verify-full ===")
    conn = None
    cur = None
    try:
        conn = psycopg2.connect(
            host="localhost",
            port=5432,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=5,
            sslmode="verify-full",
            sslrootcert=str(CA_FILE)
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT ssl, version, cipher
            FROM pg_stat_ssl
            WHERE pid = pg_backend_pid()
        """)
        print("Connection: SUCCESS")
        print("TLS status:", cur.fetchone())
    except Exception as error:
        print("Connection: FAILED")
        print(type(error).__name__, error)
    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()


def test_pg8000():
    print("\n=== pg8000: verified SSLContext ===")
    conn = None
    cur = None
    try:
        context = ssl.create_default_context(cafile=str(CA_FILE))
        print("Hostname checking:", context.check_hostname)
        print("Certificate verification required:",
              context.verify_mode == ssl.CERT_REQUIRED)

        conn = pg8000.dbapi.connect(
            host="localhost",
            port=5432,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            timeout=5,
            ssl_context=context
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT ssl, version, cipher
            FROM pg_stat_ssl
            WHERE pid = pg_backend_pid()
        """)
        print("Connection: SUCCESS")
        print("TLS status:", cur.fetchone())
    except Exception as error:
        print("Connection: FAILED")
        print(type(error).__name__, error)
    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()


def test_pymysql():
    print("\n=== PyMySQL: certificate and identity verification ===")
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host="localhost",
            port=3307,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=5,
            ssl_ca=str(CA_FILE),
            ssl_verify_cert=True,
            ssl_verify_identity=True
        )
        cur = conn.cursor()
        cur.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
        print("TLS cipher:", cur.fetchone())
        cur.execute("SHOW SESSION STATUS LIKE 'Ssl_version'")
        print("TLS version:", cur.fetchone())
        print("Connection: SUCCESS")
    except Exception as error:
        print("Connection: FAILED")
        print(type(error).__name__, error)
    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()


print("CA file exists:", CA_FILE.exists())
test_psycopg2()
test_pg8000()
test_pymysql()
