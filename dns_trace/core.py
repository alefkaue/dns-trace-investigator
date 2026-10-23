from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import base64
import csv
import hashlib
import io
import ipaddress
import json
import math
from pathlib import Path
import re


def timestamp(value):
    text = str(value)
    if re.fullmatch(r"\d{10}(?:\.\d+)?", text):
        return datetime.fromtimestamp(float(text), timezone.utc)
    result = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("every timestamp needs a timezone or epoch seconds")
    return result.astimezone(timezone.utc)


def domain(value):
    value = str(value).strip().lower().rstrip(".")
    if len(value) > 253 or not value or any(not re.fullmatch(r"[a-z0-9_-]{1,63}", x) for x in value.split(".")):
        raise ValueError("invalid DNS name; supply ASCII/punycode labels")
    return value


def in_zone(name, suffix):
    return name == suffix or name.endswith("." + suffix)


def read_rows(path):
    with Path(path).open("rb") as stream:
        content = stream.read(10_000_001)
    if len(content) > 10_000_000:
        raise ValueError("input exceeds 10 MB")
    text = content.decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text))) if Path(path).suffix.lower() == ".csv" else json.loads(text)
    if not isinstance(rows, list) or not rows or len(rows) > 100_000:
        raise ValueError("expected 1..100000 CSV/JSON records")
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("each record must be an object")
    return rows, hashlib.sha256(content).hexdigest()


def normalize_queries(rows):
    events = []
    for row_number, row in enumerate(rows, 1):
        if str(row.get("dns.flags.response", "0")) not in {"0", "False", "false"}:
            continue
        address = str(ipaddress.ip_address(row.get("src_ip") or row.get("ip.src") or row.get("ipv6.src") or ""))
        time = timestamp(row.get("timestamp", row.get("frame.time_epoch", "")))
        name = domain(row.get("query", row.get("dns.qry.name", "")))
        events.append({"timestamp": time.isoformat(), "src_ip": address,
                       "query": name, "evidence_row": row_number})
    return sorted(events, key=lambda e: (timestamp(e["timestamp"]), e["evidence_row"]))


def entropy(text):
    return -sum((count / len(text)) * math.log2(count / len(text)) for count in Counter(text).values()) if text else 0


def normalize_leases(rows):
    leases = []
    for row in rows:
        start, end = timestamp(row["start"]), timestamp(row["end"])
        if end <= start:
            raise ValueError("lease end must be after start")
        leases.append({"src_ip": str(ipaddress.ip_address(row["src_ip"])),
                       "hostname": str(row["hostname"]), "start": start, "end": end})
    return leases


def correlate_owner(event, leases):
    time = timestamp(event["timestamp"])
    matches = sorted({lease["hostname"] for lease in leases if lease["src_ip"] == event["src_ip"]
                      and lease["start"] <= time < lease["end"]})
    return {"state": "matched" if len(matches) == 1 else "ambiguous" if matches else "unattributed",
            "candidates": matches}


def investigate(rows, leases=None, allowlist=None, window_seconds=60, threshold=3,
                min_label=24, min_entropy=3.2, reveal_payload=False):
    if not 1 <= threshold <= 10000 or not 1 <= window_seconds <= 86400 or not 1 <= min_label <= 63 or not 0 <= min_entropy <= 8:
        raise ValueError("invalid detection thresholds")
    events = normalize_queries(rows)
    leases = normalize_leases(leases or [])
    allowlist = [domain(suffix) for suffix in (allowlist or [])]
    timeline, windows, candidates, peaks, alerts = [], defaultdict(deque), defaultdict(list), {}, []
    ignored = 0
    for event in events:
        name = event["query"]
        if any(in_zone(name, suffix) for suffix in allowlist):
            ignored += 1
            continue
        labels = name.split(".")
        # Grouping hint, NOT a public-suffix/registrable-domain determination.
        group_domain = ".".join(labels[-2:])
        payload_labels = labels[:-2]
        matching = [label for label in payload_labels if len(label) >= min_label and entropy(label) >= min_entropy]
        observation = {**event, "group_domain_hint": group_domain, "ownership": correlate_owner(event, leases),
                       "candidate": bool(matching)}
        if matching:
            label = matching[0]
            observation["label_sha256"] = hashlib.sha256(label.encode()).hexdigest()
            observation["label_length"] = len(label)
            observation["label_entropy"] = round(entropy(label), 3)
            if reveal_payload:
                try:
                    decoded = base64.b32decode(label.upper() + "=" * (-len(label) % 8))
                    observation["base32_preview"] = repr(decoded[:64])
                except ValueError:
                    observation["base32_preview"] = "not valid base32"
            key = event["src_ip"], group_domain
            current = timestamp(event["timestamp"])
            queue = windows[key]
            queue.append(event)
            while (current - timestamp(queue[0]["timestamp"])).total_seconds() > window_seconds:
                queue.popleft()
            candidates[key].append(event)
            if len(queue) > peaks.get(key, (0, None))[0]:
                peaks[key] = len(queue), current
        # Do not expose full query payload by default in reports.
        if not reveal_payload:
            observation["query"] = "[label-redacted]." + group_domain if len(labels) > 2 else group_domain
        timeline.append(observation)
    for (address, hint), candidate_events in sorted(candidates.items()):
        count, end = peaks[address, hint]
        if count >= threshold:
            evidence = [e for e in candidate_events if 0 <= (end - timestamp(e["timestamp"])).total_seconds() <= window_seconds]
            alerts.append({"rule": "DNS_ENCODED_LABEL_BURST", "severity": "medium",
                           "src_ip": address, "group_domain_hint": hint,
                           "count_in_window": count, "window_seconds": window_seconds,
                           "evidence_rows": [e["evidence_row"] for e in evidence],
                           "ownership": correlate_owner(evidence[-1], leases),
                           "assessment": "Suspicious encoded-label pattern; not proof of exfiltration or compromise.",
                           "next_steps": ["Check endpoint process and resolver logs.",
                                          "Validate telemetry/CDN/AV false positives and collection gaps.",
                                          "Confirm lease validity; preserve original evidence before escalation."]})
    return {"schema_version": 1, "scope": "Offline DNS triage; no live traffic captured or external systems queried.",
            "rules": {"window_seconds": window_seconds, "threshold": threshold, "min_label": min_label,
                      "min_entropy": min_entropy, "allowlist": allowlist},
            "summary": {"query_events": len(events), "allowlisted_events": ignored, "alerts": len(alerts)},
            "limitations": ["Grouping uses the last two labels, not a public suffix list.",
                            "Entropy and repetition are heuristics; legitimate software can match.",
                            "DHCP attribution is interval-based evidence, not authenticated user identity.",
                            "Capture coverage, NAT, retries, encrypted DNS and clock quality affect results."],
            "alerts": alerts, "timeline": timeline}
