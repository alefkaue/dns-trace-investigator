from argparse import ArgumentParser
from html import escape
from pathlib import Path
import json
import sys
from .core import read_rows, investigate


def main(argv=None):
    parser = ArgumentParser(description="Offline DNS query triage with timed DHCP ownership and evidence provenance")
    parser.add_argument("--queries", type=Path, required=True)
    parser.add_argument("--leases", type=Path)
    parser.add_argument("--allow", action="append", default=[], help="exact domain or subdomain suffix; repeatable")
    parser.add_argument("--window", type=int, default=60)
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--reveal-payload", action="store_true", help="include query labels and bounded base32 previews in LOCAL output")
    parser.add_argument("--out", type=Path, default=Path("reports"))
    args = parser.parse_args(argv)
    try:
        rows, query_hash = read_rows(args.queries)
        leases, lease_hash = read_rows(args.leases) if args.leases else ([], None)
        report = investigate(rows, leases, args.allow, args.window, args.threshold, reveal_payload=args.reveal_payload)
        report["provenance"] = {"queries_sha256": query_hash, "leases_sha256": lease_hash,
                                "row_numbering": "one-based data record, excluding CSV header"}
        args.out.mkdir(parents=True, exist_ok=True)
        content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        (args.out / "investigation.json").write_text(content, encoding="utf-8")
        md = "# DNS evidence triage\n\n" + report["scope"] + "\n\n```json\n" + content.replace("```", "\\u0060\\u0060\\u0060") + "```\n"
        (args.out / "investigation.md").write_text(md, encoding="utf-8")
        html = '<!doctype html><html lang="en"><meta charset="utf-8"><title>DNS triage</title><h1>DNS evidence triage</h1><pre>' + escape(content) + '</pre></html>'
        (args.out / "investigation.html").write_text(html, encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    print(f"Queries: {report['summary']['query_events']} | Alerts for review: {report['summary']['alerts']}")
    print("No finding is proof of compromise. Reports:", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
