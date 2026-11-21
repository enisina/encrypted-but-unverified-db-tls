# Encrypted but Unverified?
## A Measurement Study of TLS Defaults in Database Client Drivers

This repository contains research scripts for measuring TLS encryption, certificate-chain verification, hostname verification, and TLS performance in Python database client drivers.

## Tested drivers

| Driver | Version |
|---|---:|
| Psycopg 3 | 3.3.9 |
| MySQL Connector/Python | 26.10.0 |
| psycopg2 | 2.9.13 |
| pg8000 | 1.31.6 |
| PyMySQL | 1.2.4 |

The documentation audit and performance benchmark focus on Psycopg 3 and MySQL Connector/Python.

## Repository structure

- `Tests/` — experiment and analysis scripts.
- `Certificates/ca.pem` — public test CA certificate.
- `Results/` — destination for generated experiment output.
- `requirements.txt` — Python dependencies.
- `setup-example.ps1` — example database configuration.

No private keys are included.

## Requirements

- Python 3.14 or a compatible version.
- PostgreSQL and MySQL test databases.
- PowerShell for the supplied Windows commands.

## Installation

From the repository root, create a virtual environment and install dependencies:

    py -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt

## Database configuration

Set these environment variables in PowerShell before running experiments:

    $env:DB_USER = "tester"
    $env:DB_PASSWORD = "YOUR_LOCAL_TEST_PASSWORD"
    $env:DB_NAME = "testdb"

Replace the password placeholder with your own local test password. Never commit real credentials or private keys.

## Database endpoints

The main experiment configuration uses local database services:

- PostgreSQL: port 5432.
- MySQL: port 3307.
- Additional TLS scenarios use ports specified in the individual scripts.

A compatible database and test dataset must be running before executing experiments. Docker configuration is not included in this repository yet.

## Running experiments

Run from the repository root:

    .\.venv\Scripts\python.exe .\Tests\test_tls_matrix.py M2
    .\.venv\Scripts\python.exe .\Tests\test_additional_driver_default_matrix.py
    .\.venv\Scripts\python.exe .\Tests\test_additional_driver_verification.py
    .\.venv\Scripts\python.exe .\Tests\benchmark_tls.py
    .\.venv\Scripts\python.exe .\Tests\analyze_benchmarks.py

Check each script's configuration and required database state before running it. Some scripts refuse to overwrite existing result files.

## Experimental interpretation

The research distinguishes:

1. Encryption — whether traffic is protected by TLS.
2. Certificate-chain verification — whether the certificate chains to a trusted CA.
3. Hostname verification — whether the certificate identity matches the requested hostname.

An encrypted connection does not necessarily mean the server's identity has been verified.

Results apply to the tested driver versions and experimental environment, not every version, platform, or production deployment.

## Limitations

The experiments use local database services, test certificates, and a controlled workload. Results may differ under other operating systems, database versions, network conditions, and connection-pooling configurations.

These scripts are research artifacts, not production security recommendations.

## License and citation

Add a suitable license and formal citation information before public redistribution.
