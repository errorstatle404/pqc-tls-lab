Unit tests for the inventory tool. They need no network, no Docker and no AWS account:

- `fixtures/lab-local.txt` is the raw probe output from a real run against the lab's nginx
  (OpenSSL 3.5.4 client and server), recorded with `python -m pqcinv local --via direct`.
- `fixtures/scan-tls12-dns.txt` adds a TLS 1.2-capable endpoint and a name that doesn't resolve.
- AWS collectors run against `moto` (a local fake of the AWS APIs).

Run with `make inventory-test`.
