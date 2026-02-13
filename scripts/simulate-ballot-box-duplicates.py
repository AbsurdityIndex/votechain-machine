#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import random
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "deployments" / "compose" / "reports"
MACHINE_TOKEN = os.getenv("MACHINE_API_TOKEN", "compose-machine-api-token-change-me")


def http_json(method, url, payload=None, headers=None, timeout=15):
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    body = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url=url, method=method, data=body, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw else None
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") if exc.fp else ""
        parsed = None
        if raw:
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {"raw": raw}
        return exc.code, parsed
    except Exception as exc:
        return 599, {"error": str(exc)}


def wait_for(url, timeout_seconds=120):
    started = time.time()
    while time.time() - started < timeout_seconds:
        status, _ = http_json("GET", url, headers={"Authorization": f"Bearer {MACHINE_TOKEN}"})
        if 200 <= status < 300:
            return
        time.sleep(1)
    raise RuntimeError(f"timeout waiting for service: {url}")


def reset_machine_db(db_name):
    sql = (
        "TRUNCATE TABLE challenges, idempotency, bb_leaves, bb_sth, ballots, exports, "
        "election_manifest, state_meta RESTART IDENTITY CASCADE;"
    )
    subprocess.run(
        [
            "docker",
            "exec",
            "votechain-postgres-airgap",
            "psql",
            "-U",
            "votechain",
            "-d",
            db_name,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def ensure_compose_env():
    env_file = ROOT / ".env"
    if not env_file.exists():
        subprocess.run(
            [str(ROOT / "scripts" / "generate-compose-env.sh"), str(env_file)],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    for line in env_file.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        k, v = raw.split("=", 1)
        if k and k not in os.environ:
            os.environ[k] = v

    global MACHINE_TOKEN
    MACHINE_TOKEN = os.getenv("MACHINE_API_TOKEN", MACHINE_TOKEN)


def key_id_from_public_pem(path):
    data = Path(path).read_text(encoding="utf-8")
    b64 = "".join(line.strip() for line in data.splitlines() if not line.startswith("-----"))
    der = base64.b64decode(b64)
    if len(der) < 32:
        raise RuntimeError(f"invalid ed25519 public key der length at {path}")
    raw = der[-32:]
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def load_manifest(machine_url, receipt_key_id):
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "manifest": {
            "election_id": "duplicate-attempt-demo-2026",
            "jurisdiction_id": "pa-philadelphia",
            "manifest_id": "duplicate-attempt-demo-v1",
            "not_before": (now - dt.timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
            "not_after": (now + dt.timedelta(hours=6)).isoformat().replace("+00:00", "Z"),
            "receipt_key_id": receipt_key_id,
            "source_bundle_sha256": "duplicate-demo-source",
            "contests": [
                {
                    "contest_id": "president",
                    "type": "candidate",
                    "title": "President",
                    "options": [
                        {"id": "cand_a", "label": "Candidate A"},
                        {"id": "cand_b", "label": "Candidate B"},
                    ],
                }
            ],
        }
    }
    status, body = http_json(
        "POST",
        machine_url + "/v1/election/load",
        payload=payload,
        headers={"Authorization": f"Bearer {MACHINE_TOKEN}"},
    )
    if status != 200:
        raise RuntimeError(f"load manifest failed: status={status} body={body}")
    return payload["manifest"]["election_id"], payload["manifest"]["manifest_id"]


def compute_nullifier(credential_pub, election_id):
    seed = f"votechain:nullifier:v1:{credential_pub}:{election_id}".encode("utf-8")
    return "0x" + hashlib.sha256(seed).hexdigest()


def build_cast_payload(attempt, challenge, election_id, manifest_id):
    credential_pub = attempt["credential_pub"]
    nullifier = compute_nullifier(credential_pub, election_id)
    cipher_blob = (
        f"attempt={attempt['attempt_id']}|voter={attempt['voter_id']}|selection={attempt['selection']}"
    ).encode("utf-8")
    ciphertext = base64.urlsafe_b64encode(cipher_blob).decode("utf-8").rstrip("=")
    ballot_hash = base64.urlsafe_b64encode(hashlib.sha256(cipher_blob).digest()).decode("utf-8").rstrip("=")
    return {
        "idempotency_key": f"idem-{attempt['attempt_id']}",
        "election_id": election_id,
        "manifest_id": manifest_id,
        "challenge_id": challenge["challenge_id"],
        "challenge": challenge["challenge"],
        "nullifier": nullifier,
        "eligibility_proof": {
            "credential_pub": credential_pub,
            "proof_blob": f"mock-proof-{attempt['attempt_id']}",
        },
        "encrypted_ballot": {
            "ballot_id": f"ballot-{attempt['attempt_id']}",
            "ciphertext": ciphertext,
            "ballot_hash": ballot_hash,
            "wrapped_ballot_key": f"wrapped-key-{attempt['attempt_id']}",
            "wrapped_ballot_key_epk": f"wrapped-epk-{attempt['attempt_id']}",
        },
    }


def cast_attempt(machine_url, attempt, election_id, manifest_id):
    status, challenge = http_json(
        "POST",
        machine_url + "/v1/election/challenge",
        payload={},
        headers={"Authorization": f"Bearer {MACHINE_TOKEN}"},
    )
    if status != 200:
        return {"cast_status": "challenge_failed", "http_status": status, "error": challenge}

    cast_payload = build_cast_payload(attempt, challenge, election_id, manifest_id)
    status, cast = http_json(
        "POST",
        machine_url + "/v1/election/cast",
        payload=cast_payload,
        headers={"Authorization": f"Bearer {MACHINE_TOKEN}"},
    )
    if status != 200:
        code = ""
        if cast and isinstance(cast, dict):
            code = cast.get("error", {}).get("code", "")
        return {"cast_status": "rejected", "http_status": status, "error_code": code, "error": cast}

    receipt = cast["cast_receipt"]
    verify_status, verify = http_json(
        "POST",
        machine_url + "/v1/election/verify",
        payload={"receipt": receipt},
        headers={"Authorization": f"Bearer {MACHINE_TOKEN}"},
    )
    if verify_status != 200:
        return {
            "cast_status": "cast_ok_verify_failed",
            "http_status": verify_status,
            "receipt_id": receipt["receipt_id"],
            "verify_error": verify,
        }
    return {
        "cast_status": "accepted",
        "http_status": 200,
        "receipt_id": receipt["receipt_id"],
        "verify_status": verify.get("status"),
        "tx_id": receipt["votechain_anchor"]["tx_id"],
    }


def build_attempts(registered_count, initial_casts, duplicate_attempts, unregistered_attempts, seed):
    rng = random.Random(seed)
    registered = []
    for i in range(1, registered_count + 1):
        voter_id = f"registered-{i:03d}"
        registered.append({"voter_id": voter_id, "credential_pub": f"{voter_id}-credential"})

    initial = registered[:initial_casts]
    dup_sources = rng.choices(initial, k=duplicate_attempts)

    attempts = []
    seq = 1
    for v in initial:
        attempts.append(
            {
                "attempt_id": f"a{seq:04d}",
                "voter_id": v["voter_id"],
                "credential_pub": v["credential_pub"],
                "selection": "cand_a" if rng.random() < 0.5 else "cand_b",
                "attempt_type": "initial",
            }
        )
        seq += 1

    for v in dup_sources:
        attempts.append(
            {
                "attempt_id": f"a{seq:04d}",
                "voter_id": v["voter_id"],
                "credential_pub": v["credential_pub"],
                "selection": "cand_a" if rng.random() < 0.5 else "cand_b",
                "attempt_type": "duplicate",
            }
        )
        seq += 1

    for i in range(1, unregistered_attempts + 1):
        voter_id = f"unregistered-{i:03d}"
        attempts.append(
            {
                "attempt_id": f"a{seq:04d}",
                "voter_id": voter_id,
                "credential_pub": f"{voter_id}-credential",
                "selection": "cand_a" if rng.random() < 0.5 else "cand_b",
                "attempt_type": "unregistered",
            }
        )
        seq += 1

    return registered, attempts


def main():
    global MACHINE_TOKEN
    ensure_compose_env()
    parser = argparse.ArgumentParser(description="Simulate duplicate-vote attempts with ballot-box verification.")
    parser.add_argument("--machine-url", default="http://127.0.0.1:8080")
    parser.add_argument("--machine-token", default=MACHINE_TOKEN)
    parser.add_argument("--machine-db", default="votechain_machine")
    parser.add_argument("--receipt-key-id", default="")
    parser.add_argument("--registered-voters", type=int, default=20)
    parser.add_argument("--initial-casts", type=int, default=12)
    parser.add_argument("--duplicate-attempts", type=int, default=6)
    parser.add_argument("--unregistered-attempts", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20260211)
    parser.add_argument(
        "--force-machine-bypass-on-duplicate",
        action="store_true",
        help="attempt cast even when ballot-box rejects duplicate check-in",
    )
    args = parser.parse_args()
    MACHINE_TOKEN = args.machine_token
    if not args.receipt_key_id:
        args.receipt_key_id = key_id_from_public_pem(ROOT / "deployments" / "compose" / "keys" / "machine-signing-public.pem")

    if args.initial_casts > args.registered_voters:
        raise SystemExit("--initial-casts cannot exceed --registered-voters")

    wait_for(args.machine_url + "/healthz")
    reset_machine_db(args.machine_db)

    election_id, manifest_id = load_manifest(args.machine_url, args.receipt_key_id)
    registered, attempts = build_attempts(
        registered_count=args.registered_voters,
        initial_casts=args.initial_casts,
        duplicate_attempts=args.duplicate_attempts,
        unregistered_attempts=args.unregistered_attempts,
        seed=args.seed,
    )

    pollbook = {v["voter_id"]: v for v in registered}
    checked_in = set()

    rows = []
    for attempt in attempts:
        voter_id = attempt["voter_id"]
        ballot_box_status = "allowed"
        if voter_id not in pollbook:
            ballot_box_status = "denied_not_registered"
        elif voter_id in checked_in:
            ballot_box_status = "denied_duplicate_checkin"
        else:
            checked_in.add(voter_id)

        machine_result = {"cast_status": "not_attempted"}
        if ballot_box_status == "allowed":
            machine_result = cast_attempt(args.machine_url, attempt, election_id, manifest_id)
        elif ballot_box_status == "denied_duplicate_checkin" and args.force_machine_bypass_on_duplicate:
            machine_result = cast_attempt(args.machine_url, attempt, election_id, manifest_id)

        row = {
            "attempt_id": attempt["attempt_id"],
            "attempt_type": attempt["attempt_type"],
            "voter_id": voter_id,
            "ballot_box_status": ballot_box_status,
            "machine_result": machine_result,
        }
        rows.append(row)

    status, close_body = http_json(
        "POST",
        args.machine_url + "/v1/election/close",
        payload={},
        headers={"Authorization": f"Bearer {MACHINE_TOKEN}"},
    )
    if status != 200:
        raise RuntimeError(f"close polls failed: status={status} body={close_body}")

    summary = {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "machine_url": args.machine_url,
        "machine_db": args.machine_db,
        "force_machine_bypass_on_duplicate": args.force_machine_bypass_on_duplicate,
        "attempts_total": len(rows),
        "ballot_box_allowed": sum(1 for r in rows if r["ballot_box_status"] == "allowed"),
        "ballot_box_denied_not_registered": sum(1 for r in rows if r["ballot_box_status"] == "denied_not_registered"),
        "ballot_box_denied_duplicate_checkin": sum(1 for r in rows if r["ballot_box_status"] == "denied_duplicate_checkin"),
        "machine_cast_accepted": sum(1 for r in rows if r["machine_result"]["cast_status"] == "accepted"),
        "machine_verify_ok": sum(
            1
            for r in rows
            if r["machine_result"]["cast_status"] == "accepted"
            and r["machine_result"].get("verify_status") == "ok"
        ),
        "machine_rejected_nullifier_used": sum(
            1
            for r in rows
            if r["machine_result"]["cast_status"] == "rejected"
            and r["machine_result"].get("error_code") == "EWP_NULLIFIER_USED"
        ),
        "machine_rejected_other": sum(
            1
            for r in rows
            if r["machine_result"]["cast_status"] == "rejected"
            and r["machine_result"].get("error_code") != "EWP_NULLIFIER_USED"
        ),
        "close_polls_status": close_body.get("status", ""),
        "close_polls_ballot_count": close_body.get("ballot_count", 0),
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_json = REPORT_DIR / f"duplicate-attempts-report-{stamp}.json"
    report_md = REPORT_DIR / f"duplicate-attempts-report-{stamp}.md"
    with open(report_json, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "attempts": rows}, fh, indent=2)
        fh.write("\n")
    with open(report_md, "w", encoding="utf-8") as fh:
        fh.write("# Duplicate Attempt Simulation Report\n\n")
        for k, v in summary.items():
            fh.write(f"- {k}: `{v}`\n")
        fh.write("\n## Notable machine rejections\n\n")
        for row in rows:
            mr = row["machine_result"]
            if mr.get("cast_status") == "rejected":
                fh.write(
                    f"- attempt `{row['attempt_id']}` voter `{row['voter_id']}` "
                    f"error_code=`{mr.get('error_code','')}` http_status=`{mr.get('http_status','')}`\n"
                )

    print(f"report_json:{report_json}")
    print(f"report_md:{report_md}")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
