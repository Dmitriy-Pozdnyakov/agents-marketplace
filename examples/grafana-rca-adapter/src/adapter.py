"""Build RCA investigation request bodies from a Grafana webhook on stdin."""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


LABELS = ("api_name", "api_method", "api_endpoint", "app_name", "code")
TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)")


def obj(value, field):
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def string(record, field):
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value


def canonical_utc(value):
    match = TIMESTAMP.fullmatch(value)
    if not match:
        raise ValueError("startsAt must be an RFC 3339 timestamp with timezone")
    seconds, fraction, offset = match.groups()
    instant = datetime.fromisoformat(seconds + ("+00:00" if offset == "Z" else offset))
    utc = instant.astimezone(timezone.utc).replace(tzinfo=None).isoformat()
    fraction = (fraction or "").rstrip("0").rstrip(".")
    return utc + fraction + "Z"


def selected_rules(connection, profile):
    for field in ("projectId", "grafanaConnectionId"):
        if string(connection, field) != string(profile, field):
            raise ValueError(f"connection and profile differ on {field}")
    string(connection, "connectionId")
    if type(profile.get("orgId")) is not int or profile["orgId"] < 1:
        raise ValueError("profile.orgId must be a positive integer")
    uids = connection.get("ruleUids")
    if not isinstance(uids, list) or not uids or not all(isinstance(uid, str) and uid.strip() for uid in uids):
        raise ValueError("ruleUids must be a nonempty list of rule IDs")
    if len(uids) != len(set(uids)):
        raise ValueError("ruleUids must contain unique rule IDs")
    rules = obj(profile.get("rules"), "rules")
    selected = {}
    for uid in uids:
        rule = obj(rules.get(uid), f"rules[{uid}]")
        for field in ("service", "logsUid", "tracesUid", "metricsUid", "logsUrl"):
            string(rule, field)
        selected[uid] = rule
    return selected


def prepare(alert, connection, org_id, rules):
    alert = obj(alert, "alert")
    status = string(alert, "status")
    if status == "resolved":
        return None
    if status != "firing":
        raise ValueError("unknown alert status")
    uid = string(obj(alert.get("annotations"), "annotations"), "rule_uid")
    if uid not in rules:
        return None
    labels = obj(alert.get("labels"), "labels")
    required = {field: string(labels, field) for field in LABELS}
    if not re.fullmatch(r"5[0-9]{2}", required["code"]):
        raise ValueError("code must be an HTTP 5xx status")
    name = string(labels, "alertname")
    fingerprint = string(alert, "fingerprint")
    starts_at = canonical_utc(string(alert, "startsAt"))
    key = [connection["projectId"], connection["connectionId"], uid, fingerprint, starts_at]
    request_id = hashlib.sha256(json.dumps(key, separators=(",", ":")).encode("utf-8")).hexdigest()
    rule = rules[uid]
    return {
        "schema_version": 1, "request_id": request_id, "grafana": {"org_id": org_id},
        "alert": {"rule_uid": uid, "fingerprint": fingerprint, "name": name,
                  "status": status, "starts_at": starts_at, "labels": required},
        "target": {"service": rule["service"]},
        "sources": {"logs_uid": rule["logsUid"], "traces_uid": rule["tracesUid"],
                    "metrics_uid": rule["metricsUid"]},
        "references": {"logs_url": rule["logsUrl"]},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connection", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    args = parser.parse_args()
    output = {"investigations": [], "rejected": []}
    try:
        connection = obj(json.loads(args.connection.read_text(encoding="utf-8")), "connection")
        profile = obj(json.loads(args.profile.read_text(encoding="utf-8")), "profile")
        rules = selected_rules(connection, profile)
        webhook = obj(json.load(sys.stdin), "webhook")
        if type(webhook.get("orgId")) is not int or webhook["orgId"] != profile["orgId"]:
            raise ValueError("unexpected Grafana organization")
        if not isinstance(webhook.get("alerts"), list) or not webhook["alerts"]:
            raise ValueError("alerts must be a nonempty array")
        for index, alert in enumerate(webhook["alerts"]):
            try:
                body = prepare(alert, connection, profile["orgId"], rules)
                if body is not None:
                    output["investigations"].append(body)
            except (ValueError, OverflowError) as error:
                output["rejected"].append({"index": index, "reason": str(error)})
    except (OSError, ValueError) as error:
        output["rejected"].append({"reason": str(error)})
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return int(bool(output["rejected"]))


if __name__ == "__main__":
    sys.exit(main())
