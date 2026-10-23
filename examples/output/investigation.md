# DNS evidence triage

Offline DNS triage; no live traffic captured or external systems queried.

```json
{
  "schema_version": 1,
  "scope": "Offline DNS triage; no live traffic captured or external systems queried.",
  "rules": {
    "window_seconds": 60,
    "threshold": 3,
    "min_label": 24,
    "min_entropy": 3.2,
    "allowlist": []
  },
  "summary": {
    "query_events": 4,
    "allowlisted_events": 0,
    "alerts": 1
  },
  "limitations": [
    "Grouping uses the last two labels, not a public suffix list.",
    "Entropy and repetition are heuristics; legitimate software can match.",
    "DHCP attribution is interval-based evidence, not authenticated user identity.",
    "Capture coverage, NAT, retries, encrypted DNS and clock quality affect results."
  ],
  "alerts": [
    {
      "rule": "DNS_ENCODED_LABEL_BURST",
      "severity": "medium",
      "src_ip": "192.0.2.10",
      "group_domain_hint": "relay.example",
      "count_in_window": 3,
      "window_seconds": 60,
      "evidence_rows": [
        1,
        2,
        3
      ],
      "ownership": {
        "state": "matched",
        "candidates": [
          "synthetic-workstation"
        ]
      },
      "assessment": "Suspicious encoded-label pattern; not proof of exfiltration or compromise.",
      "next_steps": [
        "Check endpoint process and resolver logs.",
        "Validate telemetry/CDN/AV false positives and collection gaps.",
        "Confirm lease validity; preserve original evidence before escalation."
      ]
    }
  ],
  "timeline": [
    {
      "timestamp": "2026-01-01T10:00:00+00:00",
      "src_ip": "192.0.2.10",
      "query": "[label-redacted].relay.example",
      "evidence_row": 1,
      "group_domain_hint": "relay.example",
      "ownership": {
        "state": "matched",
        "candidates": [
          "synthetic-workstation"
        ]
      },
      "candidate": true,
      "label_sha256": "4cae4773b0addb54a14e3609f3ae919e3bf342086fe70e775cd32af16e963f77",
      "label_length": 31,
      "label_entropy": 4.632
    },
    {
      "timestamp": "2026-01-01T10:00:10+00:00",
      "src_ip": "192.0.2.10",
      "query": "[label-redacted].relay.example",
      "evidence_row": 2,
      "group_domain_hint": "relay.example",
      "ownership": {
        "state": "matched",
        "candidates": [
          "synthetic-workstation"
        ]
      },
      "candidate": true,
      "label_sha256": "6fbe6aa5dab5b33eae4922c094e7a18fcf501d3aa48e821e7b176bfbe550cd85",
      "label_length": 31,
      "label_entropy": 4.696
    },
    {
      "timestamp": "2026-01-01T10:00:20+00:00",
      "src_ip": "192.0.2.10",
      "query": "[label-redacted].relay.example",
      "evidence_row": 3,
      "group_domain_hint": "relay.example",
      "ownership": {
        "state": "matched",
        "candidates": [
          "synthetic-workstation"
        ]
      },
      "candidate": true,
      "label_sha256": "81546fcd69421d46722035da3bb934fed53ab163645ad24c02ed644a240f9d22",
      "label_length": 31,
      "label_entropy": 4.696
    },
    {
      "timestamp": "2026-01-01T10:00:30+00:00",
      "src_ip": "192.0.2.20",
      "query": "[label-redacted].example.com",
      "evidence_row": 4,
      "group_domain_hint": "example.com",
      "ownership": {
        "state": "unattributed",
        "candidates": []
      },
      "candidate": false
    }
  ],
  "provenance": {
    "queries_sha256": "ff770e7ab13182b63516a046e5d4654dfc2b211592e4461cf393c9f321579a61",
    "leases_sha256": "b8019eee61b3f1f559198be7aad3ad59f35b7e98aa5d630ac1fe4b090f7a7c8d",
    "row_numbering": "one-based data record, excluding CSV header"
  }
}
```
