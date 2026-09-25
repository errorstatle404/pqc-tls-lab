"""pqcinv: a post-quantum readiness inventory for TLS endpoints and AWS accounts.

It reads what AWS says is configured (ACM, load balancers, CloudFront, KMS, EC2 security
groups), probes each TLS endpoint the way different kinds of client would, and writes a
findings report plus a CycloneDX 1.6 CBOM (Cryptography Bill of Materials).
"""

__version__ = "0.1.0"
