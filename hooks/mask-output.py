#!/usr/bin/env python3
"""
Cloud Secret Manager output masking for claude-secret-shield.

Reads JSON output from stdin (e.g., from AWS, GCP, Azure secret manager CLIs),
masks sensitive value fields, and prints the masked output to stdout.

Masking strategy (preserves original length so Claude can infer key size):
  - 1-3 chars:  all masked        "***"
  - 4-6 chars:  first 1 + * + last 1  "a****z" (6 chars)
  - 7+ chars:   first 3 + * + last 3  "abc********xyz" (14 chars)

Usage:
  aws secretsmanager get-secret-value --secret-id X | python3 mask-output.py
  gcloud secrets versions access latest --secret=X | python3 mask-output.py --mode=raw
"""

import json
import sys

# Fields that contain secret values in various cloud provider outputs
SECRET_FIELDS = {
    # AWS Secrets Manager
    "SecretString",
    "SecretBinary",
    "RandomPassword",   # get-random-password
    # AWS SSM Parameter Store
    "Value",
    # AWS KMS
    "Plaintext",        # decrypt (capital P)
    "plaintext",
    # Azure Key Vault
    "value",
    # HashiCorp Vault
    "data",             # vault kv get
    # General
    "secret",
    "password",
    "token",
    "key",
    "PrivateKey",
    "privateKey",
}

# Fields that are containers — mask values inside them, not the field itself
CONTAINER_FIELDS = {
    "Parameter",      # AWS SSM wraps Value inside Parameter
    "SecretList",     # AWS batch
    "Parameters",     # AWS SSM batch
    "properties",     # Azure
}


def mask_value(val):
    """Mask a secret value with partial reveal.

    Preserves original length so Claude can infer key size (32-bit vs 64-bit etc.).
    Masked portion uses '*' characters matching the number of hidden characters.
      - 1-3 chars:  all masked             "***"
      - 4-6 chars:  first 1 + mask + last 1  "a****z" (6 chars)
      - 7+ chars:   first 3 + mask + last 3  "abc********xyz" (14 chars)
    """
    if not isinstance(val, str):
        return "***"
    n = len(val)
    if n == 0:
        return "<empty>"
    if n <= 3:
        return "*" * n
    elif n <= 6:
        return val[0] + "*" * (n - 2) + val[-1]
    else:
        return val[:3] + "*" * (n - 6) + val[-3:]


def mask_dict(obj):
    """Recursively mask secret fields in a dict."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k in SECRET_FIELDS:
                if isinstance(v, str):
                    result[k] = mask_value(v)
                elif isinstance(v, dict):
                    # SecretString could be a JSON string that was parsed
                    result[k] = mask_value(json.dumps(v))
                elif isinstance(v, (int, float, bool)):
                    result[k] = "***"
                elif isinstance(v, list):
                    result[k] = mask_value(json.dumps(v))
                else:
                    result[k] = "***"
            else:
                result[k] = mask_dict(v)
        return result
    elif isinstance(obj, list):
        return [mask_dict(item) for item in obj]
    else:
        return obj


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)

    mode = "json"
    if "--mode=raw" in sys.argv:
        mode = "raw"

    if mode == "raw":
        # GCP `gcloud secrets versions access` outputs raw secret value, not JSON
        print(mask_value(raw.strip()))
        return

    # Try to parse as JSON
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        # Not JSON — treat the entire output as a potential secret value
        # This handles cases like `aws ssm get-parameter --query Parameter.Value --output text`
        print(mask_value(raw.strip()))
        return

    masked = mask_dict(data)
    print(json.dumps(masked, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
