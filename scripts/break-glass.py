#!/usr/bin/env python3
"""Break-glass for security on-call. Every action is written to the audit log.

  issue   --subject team:<id>|user:<name> --relax a,b --minutes N --ticket T --reason "..." --by NAME
          Prints the override token once (send it as header x-ctrl-ai-break-glass). Needs CTRL_AI_BREAKGLASS_SECRET.
  revoke  --id bg_xxxxxxxx --by NAME
  list
  outage  --mode degrade|fail_closed|normal --minutes N --reason "..." [--ticket T] --by NAME
  outage  --end --by NAME

Files: --register (default $CTRL_AI_BREAKGLASS_FILE or state/break_glass.json), --audit (default
$CTRL_AI_AUDIT_LOG or logs/audit.jsonl), --policy (default $CTRL_AI_POLICY_FILE or config/policy.yaml).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ctrl_ai.core.audit import AuditLog
from ctrl_ai.core.policy import parse_policy
from ctrl_ai.core.rows import break_glass_row
from ctrl_ai.core.schema import validate
from ctrl_ai.governance import breakglass
from ctrl_ai.semantic.outage import incident_row

REPO = Path(__file__).resolve().parents[1]


def _iso(when: datetime) -> str:
    return when.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def load(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        doc = {"overrides": []}
    doc.setdefault("overrides", [])
    return doc


def save(path: Path, doc: dict) -> None:
    """Validate, then write atomically (temporary file, fsync, os.replace)."""
    validate(doc, "break_glass")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".break_glass.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def policy_settings(path: Path):
    try:
        return parse_policy(path.read_bytes())
    except Exception as exc:
        sys.exit(f"cannot read the policy ({exc})")


def cmd_issue(args, register: Path, audit: AuditLog) -> int:
    secret = os.environ.get("CTRL_AI_BREAKGLASS_SECRET", "")
    if not secret:
        print("CTRL_AI_BREAKGLASS_SECRET is not set; refusing to issue an override.", file=sys.stderr)
        return 2
    policy = policy_settings(Path(args.policy))
    relax = [r.strip() for r in args.relax.split(",") if r.strip()]
    problem = breakglass.validate_request(
        policy.break_glass, args.subject, relax, args.minutes, args.ticket, args.reason
    )
    if problem:
        print(f"refused: {problem}", file=sys.stderr)
        return 2
    now = datetime.now(UTC)
    record = {
        "id": "bg_" + secrets.token_hex(4),
        "subject": args.subject,
        "relax": relax,
        "reason": args.reason,
        "issued_by": args.by,
        "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(minutes=args.minutes)),
        "revoked": False,
    }
    if args.ticket:
        record["ticket"] = args.ticket
    doc = load(register)
    doc["overrides"].append(record)
    save(register, doc)
    audit.write(break_glass_row("issue", record))
    token = breakglass.make_token(record, secret)
    print(
        f"Override {record['id']} for {args.subject}, relaxing {', '.join(relax)}, until {record['expires_at']}.",
        file=sys.stderr,
    )
    print("Token (shown once; send it as header x-ctrl-ai-break-glass):", file=sys.stderr)
    print(token)
    return 0


def cmd_revoke(args, register: Path, audit: AuditLog) -> int:
    doc = load(register)
    for record in doc["overrides"]:
        if record["id"] == args.id:
            record["revoked"] = True
            save(register, doc)
            audit.write({**break_glass_row("revoke", record), "by": args.by})
            print(f"revoked {args.id}")
            return 0
    print(f"no override {args.id}", file=sys.stderr)
    return 1


def cmd_list(args, register: Path, audit: AuditLog) -> int:
    doc = load(register)
    now = _iso(datetime.now(UTC))
    for r in doc["overrides"]:
        state = "revoked" if r["revoked"] else ("expired" if r["expires_at"] <= now else "ACTIVE")
        print(
            f"{r['id']}  {state:8}  {r['subject']:24}  relax={','.join(r['relax'])}  until {r['expires_at']}  "
            f"ticket={r.get('ticket', '-')}  by={r['issued_by']}"
        )
    outage = doc.get("semantic_outage")
    if outage:
        print(
            f"semantic_outage: active={outage['active']} mode={outage['mode']} until {outage['expires_at']} "
            f"by={outage['issued_by']}"
        )
    return 0


def cmd_outage(args, register: Path, audit: AuditLog) -> int:
    doc = load(register)
    if args.end:
        current = doc.get("semantic_outage")
        if not current or not current.get("active"):
            print("no manual semantic-outage switch is active")
            return 0
        current["active"] = False
        save(register, doc)
        audit.write(
            incident_row(
                "manual_off", "semantic", current.get("mode"), args.reason or "ended by hand", args.by
            )
        )
        print("manual semantic-outage switch ended")
        return 0
    if not args.mode or not args.minutes or not args.reason:
        print("outage needs --mode, --minutes and --reason (or --end)", file=sys.stderr)
        return 2
    policy = policy_settings(Path(args.policy))
    limit = int(policy.semantic_outage.get("max_manual_minutes", 120))
    if args.minutes > limit:
        print(
            f"refused: at most {limit} minutes (policy semantic_outage.max_manual_minutes)", file=sys.stderr
        )
        return 2
    if len(args.reason) < 3:
        print("refused: give a reason", file=sys.stderr)
        return 2
    now = datetime.now(UTC)
    entry = {
        "active": True,
        "mode": args.mode,
        "reason": args.reason,
        "issued_by": args.by,
        "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(minutes=args.minutes)),
    }
    if args.ticket:
        entry["ticket"] = args.ticket
    doc["semantic_outage"] = entry
    save(register, doc)
    audit.write(
        incident_row(
            "manual_on",
            "semantic",
            args.mode,
            args.reason,
            args.by,
            ticket=args.ticket,
            expires_at=entry["expires_at"],
        )
    )
    print(f"semantic outage switch: {args.mode} until {entry['expires_at']}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--register",
        default=os.environ.get("CTRL_AI_BREAKGLASS_FILE_HOST") or str(REPO / "state" / "break_glass.json"),
    )
    p.add_argument(
        "--audit", default=os.environ.get("CTRL_AI_AUDIT_LOG_HOST") or str(REPO / "logs" / "audit.jsonl")
    )
    p.add_argument(
        "--policy", default=os.environ.get("CTRL_AI_POLICY_FILE_HOST") or str(REPO / "config" / "policy.yaml")
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("issue")
    i.add_argument("--subject", required=True)
    i.add_argument("--relax", required=True)
    i.add_argument("--minutes", type=int, required=True)
    i.add_argument("--ticket", default="")
    i.add_argument("--reason", required=True)
    i.add_argument("--by", required=True)
    r = sub.add_parser("revoke")
    r.add_argument("--id", required=True)
    r.add_argument("--by", default="cli")
    sub.add_parser("list")
    o = sub.add_parser("outage")
    o.add_argument("--mode", choices=["degrade", "fail_closed", "normal"])
    o.add_argument("--minutes", type=int)
    o.add_argument("--reason", default="")
    o.add_argument("--ticket", default=None)
    o.add_argument("--by", required=True)
    o.add_argument("--end", action="store_true")
    args = p.parse_args(argv)
    register, audit = Path(args.register), AuditLog(args.audit)
    return {"issue": cmd_issue, "revoke": cmd_revoke, "list": cmd_list, "outage": cmd_outage}[args.cmd](
        args, register, audit
    )


if __name__ == "__main__":
    sys.exit(main())
