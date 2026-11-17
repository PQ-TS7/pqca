"""Settings for the key-generation tests, overridable with environment variables.

Run the discovery commands from the QA guide first, then set whatever differs
in your base image (algorithm name, provider flags, private-key format).
"""

from __future__ import annotations

import os
import shlex

# openssl executable
OPENSSL_BIN = os.environ.get("PQCA_OPENSSL_BIN", "openssl")

# Name OpenSSL uses for the algorithm: "ML-DSA-65" on OpenSSL 3.5+,
# usually "mldsa65" when it comes from oqs-provider.
ALG_NAME = os.environ.get("PQCA_OPENSSL_ALG", "ML-DSA-65")

# Extra flags that load the provider, e.g. "-provider oqsprovider -provider default"
PROVIDER_ARGS = shlex.split(os.environ.get("PQCA_OPENSSL_PROVIDER_ARGS", ""))

# How the wrapper is configured to store private keys: seed | expanded | both
EXPECTED_PRIVATE_FORMAT = os.environ.get("PQCA_EXPECTED_PRIVATE_FORMAT", "both")

# FIPS 204 / RFC 9881 values for ML-DSA-65
ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"
PUBLIC_KEY_BYTES = 1952
PRIVATE_KEY_BYTES = 4032  # expanded form
SEED_BYTES = 32
SIGNATURE_BYTES = 3309
