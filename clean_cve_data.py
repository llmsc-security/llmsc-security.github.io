#!/usr/bin/env python3
"""Clean CVE data by removing sensitive credentials embedded in descriptions."""

import json
import re

def clean_cve_data():
    with open("data/cve_details.json", "r") as f:
        cve_data = json.load(f)

    # Patterns to match AWS credentials and other sensitive data
    patterns = [
        # AWS Access Key ID
        (r'AKIA[0-9A-Z]{16}', '[AWS_ACCESS_KEY_REDACTED]'),
        # AWS Secret Key
        (r'aws_secret_access_key\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']', 'aws_secret_access_key=[REDACTED]'),
        # AWS credentials in URLs
        (r'X-Amz-Credential=[^&]+', 'X-Amz-Credential=[REDACTED]'),
        (r'X-Amz-Signature=[0-9a-f]+', 'X-Amz-Signature=[REDACTED]'),
        # Azure AD secrets
        (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '[UUID_REDACTED]'),
    ]

    cleaned_count = 0
    for cve_id, data in cve_data.items():
        original = json.dumps(data)

        # Clean details field
        if 'details' in data:
            for pattern, replacement in patterns:
                data['details'] = re.sub(pattern, replacement, data['details'])

        # Clean summary field
        if 'summary' in data:
            for pattern, replacement in patterns:
                data['summary'] = re.sub(pattern, replacement, data['summary'])

        # Clean references
        if 'references' in data:
            for ref in data['references']:
                if 'url' in ref:
                    for pattern, replacement in patterns:
                        ref['url'] = re.sub(pattern, replacement, ref['url'])

        if json.dumps(data) != original:
            cleaned_count += 1

    with open("data/cve_details_cleaned.json", "w") as f:
        json.dump(cve_data, f, indent=2)

    print(f"Cleaned {cleaned_count} CVE entries")
    print(f"Original size: {len(json.dumps(cve_data))} bytes")

    # Check for any remaining AWS keys
    remaining = 0
    for cve_id, data in cve_data.items():
        text = json.dumps(data)
        if re.search(r'AKIA[0-9A-Z]{16}', text):
            remaining += 1
            print(f"WARNING: Still has AWS key in {cve_id}")

    print(f"Remaining CVEs with AWS keys: {remaining}")

if __name__ == "__main__":
    clean_cve_data()
