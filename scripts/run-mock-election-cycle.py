#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import csv
import datetime as dt
import hashlib
import json
import os
import random
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "deployments" / "compose" / "reports"
EXPORT_ROOT = ROOT / "deployments" / "compose" / "exports"

MACHINE_DEFS = [
    {
        "name": "machine-1",
        "machine_id": "machine-pa-001",
        "key_id": "ed25519:9ff90b83db2cee4a",
        "key_public_path": ROOT / "deployments" / "compose" / "keys" / "machine-signing-public.pem",
        "url": "http://127.0.0.1:8080",
        "db": "votechain_machine",
        "export_dir": EXPORT_ROOT,
    },
    {
        "name": "machine-2",
        "machine_id": "machine-pa-002",
        "key_id": "ed25519:b4d50b693f42ba9e",
        "key_public_path": ROOT / "deployments" / "compose" / "keys" / "machine-2-signing-public.pem",
        "url": "http://127.0.0.1:8081",
        "db": "votechain_machine_2",
        "export_dir": EXPORT_ROOT / "machine-2",
    },
    {
        "name": "machine-3",
        "machine_id": "machine-pa-003",
        "key_id": "ed25519:11e6e6e08701085a",
        "key_public_path": ROOT / "deployments" / "compose" / "keys" / "machine-3-signing-public.pem",
        "url": "http://127.0.0.1:8082",
        "db": "votechain_machine_3",
        "export_dir": EXPORT_ROOT / "machine-3",
    },
    {
        "name": "machine-4",
        "machine_id": "machine-pa-004",
        "key_id": "ed25519:788cadc7b67e1553",
        "key_public_path": ROOT / "deployments" / "compose" / "keys" / "machine-4-signing-public.pem",
        "url": "http://127.0.0.1:8083",
        "db": "votechain_machine_4",
        "export_dir": EXPORT_ROOT / "machine-4",
    },
    {
        "name": "machine-5",
        "machine_id": "machine-pa-005",
        "key_id": "ed25519:2b48b9da62cff635",
        "key_public_path": ROOT / "deployments" / "compose" / "keys" / "machine-5-signing-public.pem",
        "url": "http://127.0.0.1:8084",
        "db": "votechain_machine_5",
        "export_dir": EXPORT_ROOT / "machine-5",
    },
]

INGEST_URL = "http://127.0.0.1:8181"
OBSERVER_URL = "http://127.0.0.1:8282"
LEDGER_URLS = {
    "federal": "http://127.0.0.1:8301",
    "state": "http://127.0.0.1:8302",
    "oversight": "http://127.0.0.1:8303",
}
AIRGAP_INGEST_URL = "http://127.0.0.1:8182"
AIRGAP_OBSERVER_URL = "http://127.0.0.1:8382"
AIRGAP_LEDGER_URLS = {
    "federal": "http://127.0.0.1:8401",
    "state": "http://127.0.0.1:8402",
    "oversight": "http://127.0.0.1:8403",
}
INGEST_TOKEN = "compose-dev-token-change-me"
AIRGAP_INGEST_TOKEN = "compose-airgap-token-change-me"
MACHINE_TOKEN = "compose-machine-api-token-change-me"
MACHINE_AUTH = {"Authorization": f"Bearer {MACHINE_TOKEN}"}


def sh(cmd, timeout=600):
    subprocess.run(
        cmd,
        cwd=ROOT,
        check=True,
        timeout=timeout,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def key_id_from_public_pem(path):
    data = Path(path).read_text(encoding="utf-8")
    b64 = "".join(line.strip() for line in data.splitlines() if not line.startswith("-----"))
    der = base64.b64decode(b64)
    if len(der) < 32:
        raise RuntimeError(f"invalid ed25519 public key der length at {path}")
    raw = der[-32:]
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


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

    global INGEST_TOKEN, AIRGAP_INGEST_TOKEN, MACHINE_TOKEN, MACHINE_AUTH
    INGEST_TOKEN = os.getenv("INGEST_TOKEN", INGEST_TOKEN)
    AIRGAP_INGEST_TOKEN = os.getenv("AIRGAP_INGEST_TOKEN", AIRGAP_INGEST_TOKEN)
    MACHINE_TOKEN = os.getenv("MACHINE_API_TOKEN", MACHINE_TOKEN)
    MACHINE_AUTH = {"Authorization": f"Bearer {MACHINE_TOKEN}"}
    for machine in MACHINE_DEFS:
        machine["key_id"] = key_id_from_public_pem(machine["key_public_path"])


def http_json(method, url, payload=None, headers=None, timeout=15):
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url=url, method=method, data=data, headers=req_headers)
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


def wait_health(name, url, headers=None, timeout_seconds=180):
    start = time.time()
    while time.time() - start < timeout_seconds:
        status, _ = http_json("GET", url, headers=headers)
        if 200 <= status < 300:
            print(f"ready:{name}")
            return
        time.sleep(1)
    raise RuntimeError(f"timeout waiting for {name}: {url}")


def retry_json(method, url, payload=None, headers=None, retries=6, base_sleep=0.2):
    last = None
    for attempt in range(1, retries + 1):
        status, body = http_json(method, url, payload=payload, headers=headers)
        if 200 <= status < 300:
            return status, body
        last = (status, body)
        if status >= 500:
            time.sleep(base_sleep * attempt)
            continue
        return status, body
    return last


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


def session_manifest(not_before, not_after, receipt_key_id):
    return {
        "manifest": {
            "election_id": "mock-general-2026",
            "jurisdiction_id": "pa-philadelphia",
            "manifest_id": "mock-general-2026-v1",
            "not_before": not_before,
            "not_after": not_after,
            "receipt_key_id": receipt_key_id,
            "source_bundle_sha256": "mock-election-source-2026-v1",
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


def build_cast_payload(machine_id, voter_id, session_uid, challenge, selection):
    credential_pub = f"{machine_id}:{voter_id}"
    election_id = "mock-general-2026"
    manifest_id = "mock-general-2026-v1"
    nullifier_seed = f"votechain:nullifier:v1:{credential_pub}:{election_id}".encode("utf-8")
    nullifier = "0x" + hashlib.sha256(nullifier_seed).hexdigest()
    cipher_blob = f"session={session_uid}|machine={machine_id}|voter={voter_id}|selection={selection}".encode("utf-8")
    ciphertext = base64.urlsafe_b64encode(cipher_blob).decode("utf-8").rstrip("=")
    ballot_hash = base64.urlsafe_b64encode(hashlib.sha256(cipher_blob).digest()).decode("utf-8").rstrip("=")
    return {
        "idempotency_key": f"idem-{session_uid}",
        "election_id": election_id,
        "manifest_id": manifest_id,
        "challenge_id": challenge["challenge_id"],
        "challenge": challenge["challenge"],
        "nullifier": nullifier,
        "eligibility_proof": {
            "credential_pub": credential_pub,
            "proof_blob": f"mock-proof-{session_uid}",
        },
        "encrypted_ballot": {
            "ballot_id": f"ballot-{session_uid}-{selection}",
            "ciphertext": ciphertext,
            "ballot_hash": ballot_hash,
            "wrapped_ballot_key": f"wrapped-key-{session_uid}",
            "wrapped_ballot_key_epk": f"wrapped-epk-{session_uid}",
        },
    }


def run_session(machine, record, manifest_not_before, manifest_not_after, bundle_archive_dir):
    base = machine["url"]
    machine_id = machine["machine_id"]
    manifest_payload = session_manifest(
        not_before=manifest_not_before,
        not_after=manifest_not_after,
        receipt_key_id=machine["key_id"],
    )

    status, body = retry_json("POST", base + "/v1/election/load", payload=manifest_payload, headers=MACHINE_AUTH)
    if status != 200:
        raise RuntimeError(f"{machine_id} load failed: status={status} body={body}")

    cast_ok = False
    receipt_ok = False
    receipt_id = ""
    spoiled = bool(record["spoiled"])

    if spoiled:
        status, body = retry_json("POST", base + "/v1/election/challenge", payload={}, headers=MACHINE_AUTH)
        if status != 200:
            raise RuntimeError(f"{machine_id} spoil challenge failed: status={status} body={body}")
    else:
        status, challenge = retry_json("POST", base + "/v1/election/challenge", payload={}, headers=MACHINE_AUTH)
        if status != 200:
            raise RuntimeError(f"{machine_id} challenge failed: status={status} body={challenge}")
        cast_payload = build_cast_payload(
            machine_id=machine_id,
            voter_id=record["voter_id"],
            session_uid=record["session_uid"],
            challenge=challenge,
            selection=record["selection"],
        )
        status, cast = retry_json("POST", base + "/v1/election/cast", payload=cast_payload, headers=MACHINE_AUTH)
        if status != 200:
            raise RuntimeError(f"{machine_id} cast failed: status={status} body={cast}")
        cast_ok = True
        receipt = cast["cast_receipt"]
        receipt_id = receipt["receipt_id"]
        status, verify = retry_json("POST", base + "/v1/election/verify", payload={"receipt": receipt}, headers=MACHINE_AUTH)
        if status != 200:
            raise RuntimeError(f"{machine_id} verify failed: status={status} body={verify}")
        receipt_ok = verify.get("status") == "ok"
        if not receipt_ok:
            raise RuntimeError(f"{machine_id} verify status not ok: {verify}")

    status, close = retry_json("POST", base + "/v1/election/close", payload={}, headers=MACHINE_AUTH)
    if status != 200:
        raise RuntimeError(f"{machine_id} close failed: status={status} body={close}")

    bundle_file = os.path.basename(close["bundle_path"])
    host_bundle = machine["export_dir"] / bundle_file
    for _ in range(60):
        if host_bundle.exists():
            break
        time.sleep(0.2)
    if not host_bundle.exists():
        raise RuntimeError(f"{machine_id} bundle missing: {host_bundle}")

    with open(host_bundle, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)

    status, airgap_ingest = retry_json(
        "POST",
        AIRGAP_INGEST_URL + "/v1/ingest/bundle",
        payload={"bundle": bundle},
        headers={"Authorization": f"Bearer {AIRGAP_INGEST_TOKEN}"},
    )
    if status != 200:
        raise RuntimeError(f"{machine_id} airgap ingest failed: status={status} body={airgap_ingest}")

    status, ingest = retry_json(
        "POST",
        INGEST_URL + "/v1/ingest/bundle",
        payload={"bundle": bundle},
        headers={"Authorization": f"Bearer {INGEST_TOKEN}"},
    )
    if status != 200:
        raise RuntimeError(f"{machine_id} ingest failed: status={status} body={ingest}")

    archived_bundle = bundle_archive_dir / f"{bundle['bundle_id']}.json"
    if not archived_bundle.exists():
        shutil.copy2(host_bundle, archived_bundle)

    reset_machine_db(machine["db"])
    try:
        host_bundle.unlink(missing_ok=True)
    except Exception:
        pass

    return {
        "session_uid": record["session_uid"],
        "machine_id": machine_id,
        "session_index": record["session_index"],
        "voter_id": record["voter_id"],
        "spoiled": spoiled,
        "selection": record["selection"],
        "cast_ok": cast_ok,
        "receipt_ok": receipt_ok,
        "receipt_id": receipt_id,
        "bundle_id": bundle["bundle_id"],
        "bundle_archive_path": str(archived_bundle),
        "airgap_ingest_status": airgap_ingest.get("status"),
        "ingest_status": ingest.get("status"),
    }


def run_machine(machine, machine_records, manifest_not_before, manifest_not_after, bundle_archive_dir, result_sink, lock):
    for idx, rec in enumerate(machine_records, start=1):
        out = run_session(machine, rec, manifest_not_before, manifest_not_after, bundle_archive_dir)
        with lock:
            result_sink.append(out)
        if idx % 10 == 0:
            print(f"{machine['machine_id']}: completed {idx}/{len(machine_records)} sessions")


def fetch_json_ok(url, headers=None):
    status, body = http_json("GET", url, headers=headers)
    if status != 200:
        raise RuntimeError(f"request failed: {url} status={status} body={body}")
    return body


def poll_relay_drained(observer_url, expected_bundles, timeout_seconds=900):
    start = time.time()
    while time.time() - start < timeout_seconds:
        status, body = http_json("GET", observer_url + "/v1/observer/status")
        if status == 200:
            pending = body.get("ingest_data", {}).get("outbox_pending", -1)
            sent = body.get("ingest_data", {}).get("outbox_sent", -1)
            if pending == 0 and sent >= expected_bundles:
                return body
        time.sleep(2)
    raise RuntimeError("timed out waiting for relay outbox to drain")


def write_dataset(dataset, stamp):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    dataset_json = REPORT_DIR / f"mock-election-data-{stamp}.json"
    dataset_csv = REPORT_DIR / f"mock-election-data-{stamp}.csv"

    with open(dataset_json, "w", encoding="utf-8") as fh:
        json.dump(dataset, fh, indent=2)
        fh.write("\n")

    with open(dataset_csv, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "session_uid",
                "machine_id",
                "session_index",
                "voter_id",
                "spoiled",
                "selection",
            ],
        )
        writer.writeheader()
        for row in dataset:
            writer.writerow(row)
    return dataset_json, dataset_csv


def write_report(summary, session_results, stamp):
    report_json = REPORT_DIR / f"mock-election-run-{stamp}.json"
    report_md = REPORT_DIR / f"mock-election-run-{stamp}.md"
    with open(report_json, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "sessions": session_results}, fh, indent=2)
        fh.write("\n")

    lines = [
        "# Mock Election Run Report",
        "",
        f"- Timestamp (UTC): `{summary['timestamp_utc']}`",
        f"- Total sessions: `{summary['expected_sessions']}`",
        f"- Spoiled sessions: `{summary['expected_spoiled']}`",
        f"- Expected cast sessions: `{summary['expected_cast']}`",
        f"- Observed bundles: `{summary['observed_bundle_count']}`",
        f"- Observed receipts: `{summary['observed_receipt_count']}`",
        f"- Receipt verify ok: `{summary['observed_receipt_verify_ok']}`",
        f"- Winner: `{summary['winner']}` ({summary['winner_votes']} votes)",
        f"- Observer overall: `{summary['observer_overall']}`",
        f"- Observer consistency: `{summary['observer_consistency']}`",
        f"- Outbox pending: `{summary['observer_outbox_pending']}`",
        f"- Outbox sent: `{summary['observer_outbox_sent']}`",
        f"- Airgap observer overall: `{summary['airgap_observer_overall']}`",
        f"- Airgap observer consistency: `{summary['airgap_observer_consistency']}`",
        f"- Airgap outbox pending: `{summary['airgap_observer_outbox_pending']}`",
        f"- Airgap outbox sent: `{summary['airgap_observer_outbox_sent']}`",
        f"- Bundle archive dir: `{summary['bundle_archive_dir']}`",
        "",
        "## Ledger",
        "",
        f"- Federal index/hash: `{summary['ledger_federal_index']}` / `{summary['ledger_federal_hash']}`",
        f"- State index/hash: `{summary['ledger_state_index']}` / `{summary['ledger_state_hash']}`",
        f"- Oversight index/hash: `{summary['ledger_oversight_index']}` / `{summary['ledger_oversight_hash']}`",
        f"- Airgap federal index/hash: `{summary['airgap_ledger_federal_index']}` / `{summary['airgap_ledger_federal_hash']}`",
        f"- Airgap state index/hash: `{summary['airgap_ledger_state_index']}` / `{summary['airgap_ledger_state_hash']}`",
        f"- Airgap oversight index/hash: `{summary['airgap_ledger_oversight_index']}` / `{summary['airgap_ledger_oversight_hash']}`",
        "",
        f"- Verification passed: `{summary['verification_passed']}`",
    ]
    with open(report_md, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    return report_json, report_md


def main():
    parser = argparse.ArgumentParser(description="Run 5-machine mock election session cycle.")
    parser.add_argument("--machines", type=int, default=5, help="number of machine services to use (max 5)")
    parser.add_argument("--sessions-per-machine", type=int, default=100, help="sessions per machine")
    parser.add_argument("--spoil-rate", type=float, default=0.12, help="probability of spoiled voter session")
    parser.add_argument("--seed", type=int, default=20260211, help="random seed")
    parser.add_argument("--skip-stack-reset", action="store_true", help="do not run compose down/up at start")
    args = parser.parse_args()

    if args.machines < 1 or args.machines > len(MACHINE_DEFS):
        raise SystemExit("machines must be between 1 and 5")
    if args.sessions_per_machine < 1:
        raise SystemExit("sessions-per-machine must be >= 1")
    if args.spoil_rate < 0 or args.spoil_rate > 1:
        raise SystemExit("spoil-rate must be between 0 and 1")

    ensure_compose_env()

    selected = MACHINE_DEFS[: args.machines]
    for machine in selected:
        machine["export_dir"].mkdir(parents=True, exist_ok=True)

    if not args.skip_stack_reset:
        print("resetting compose stack...")
        sh(["docker", "compose", "down", "-v", "--remove-orphans"], timeout=600)
        sh(["docker", "compose", "up", "-d", "--build"], timeout=1200)

    wait_health("ingest", INGEST_URL + "/healthz", headers={"Authorization": f"Bearer {INGEST_TOKEN}"})
    wait_health("airgap-ingest", AIRGAP_INGEST_URL + "/healthz", headers={"Authorization": f"Bearer {AIRGAP_INGEST_TOKEN}"})
    wait_health("observer", OBSERVER_URL + "/healthz")
    wait_health("airgap-observer", AIRGAP_OBSERVER_URL + "/healthz")
    for role, url in LEDGER_URLS.items():
        wait_health(role, url + "/healthz")
    for role, url in AIRGAP_LEDGER_URLS.items():
        wait_health(f"airgap-{role}", url + "/healthz")
    for machine in selected:
        wait_health(machine["machine_id"], machine["url"] + "/healthz", headers=MACHINE_AUTH)

    now = dt.datetime.now(dt.timezone.utc)
    manifest_not_before = (now - dt.timedelta(minutes=20)).isoformat().replace("+00:00", "Z")
    manifest_not_after = (now + dt.timedelta(days=2)).isoformat().replace("+00:00", "Z")

    rng = random.Random(args.seed)
    dataset = []
    for machine in selected:
        for s in range(1, args.sessions_per_machine + 1):
            spoiled = rng.random() < args.spoil_rate
            selection = "" if spoiled else ("cand_a" if rng.random() < 0.5 else "cand_b")
            dataset.append(
                {
                    "session_uid": f"{machine['machine_id']}-s{s:03d}",
                    "machine_id": machine["machine_id"],
                    "session_index": s,
                    "voter_id": f"{machine['machine_id']}-voter-{s:03d}",
                    "spoiled": spoiled,
                    "selection": selection,
                }
            )

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle_archive_dir = REPORT_DIR / f"bundle-archive-{stamp}"
    bundle_archive_dir.mkdir(parents=True, exist_ok=True)
    dataset_json, dataset_csv = write_dataset(dataset, stamp)
    print(f"mock_data_json:{dataset_json}")
    print(f"mock_data_csv:{dataset_csv}")
    print(f"bundle_archive_dir:{bundle_archive_dir}")

    by_machine = {m["machine_id"]: [] for m in selected}
    for row in dataset:
        by_machine[row["machine_id"]].append(row)

    results = []
    lock = threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(selected)) as ex:
        futs = [
            ex.submit(
                run_machine,
                machine,
                by_machine[machine["machine_id"]],
                manifest_not_before,
                manifest_not_after,
                bundle_archive_dir,
                results,
                lock,
            )
            for machine in selected
        ]
        for fut in futs:
            fut.result()

    expected_sessions = len(dataset)
    expected_spoiled = sum(1 for d in dataset if d["spoiled"])
    expected_cast = expected_sessions - expected_spoiled
    tally = {"cand_a": 0, "cand_b": 0}
    for row in dataset:
        if row["spoiled"]:
            continue
        tally[row["selection"]] = tally.get(row["selection"], 0) + 1
    winner = "tie"
    winner_votes = 0
    if tally["cand_a"] > tally["cand_b"]:
        winner = "cand_a"
        winner_votes = tally["cand_a"]
    elif tally["cand_b"] > tally["cand_a"]:
        winner = "cand_b"
        winner_votes = tally["cand_b"]
    else:
        winner_votes = tally["cand_a"]
    observed_cast = sum(1 for r in results if r["cast_ok"])
    observed_verify_ok = sum(1 for r in results if r["receipt_ok"])

    observer_status = poll_relay_drained(OBSERVER_URL, expected_bundles=expected_sessions, timeout_seconds=1200)
    airgap_observer_status = poll_relay_drained(AIRGAP_OBSERVER_URL, expected_bundles=expected_sessions, timeout_seconds=1200)
    fed = fetch_json_ok(LEDGER_URLS["federal"] + "/healthz")
    state = fetch_json_ok(LEDGER_URLS["state"] + "/healthz")
    oversight = fetch_json_ok(LEDGER_URLS["oversight"] + "/healthz")
    airgap_fed = fetch_json_ok(AIRGAP_LEDGER_URLS["federal"] + "/healthz")
    airgap_state = fetch_json_ok(AIRGAP_LEDGER_URLS["state"] + "/healthz")
    airgap_oversight = fetch_json_ok(AIRGAP_LEDGER_URLS["oversight"] + "/healthz")

    observed_bundle_count = observer_status.get("ingest_data", {}).get("bundle_count", -1)
    observed_receipt_count = observer_status.get("ingest_data", {}).get("receipt_count", -1)
    outbox_pending = observer_status.get("ingest_data", {}).get("outbox_pending", -1)
    outbox_sent = observer_status.get("ingest_data", {}).get("outbox_sent", -1)
    consistency = observer_status.get("consistency", {}).get("status", "")
    overall = observer_status.get("overall", "")
    airgap_outbox_pending = airgap_observer_status.get("ingest_data", {}).get("outbox_pending", -1)
    airgap_outbox_sent = airgap_observer_status.get("ingest_data", {}).get("outbox_sent", -1)
    airgap_consistency = airgap_observer_status.get("consistency", {}).get("status", "")
    airgap_overall = airgap_observer_status.get("overall", "")

    fed_idx = int(fed.get("latest_index", 0))
    state_idx = int(state.get("latest_index", 0))
    over_idx = int(oversight.get("latest_index", 0))
    fed_hash = fed.get("latest_hash", "")
    state_hash = state.get("latest_hash", "")
    over_hash = oversight.get("latest_hash", "")
    airgap_fed_idx = int(airgap_fed.get("latest_index", 0))
    airgap_state_idx = int(airgap_state.get("latest_index", 0))
    airgap_over_idx = int(airgap_oversight.get("latest_index", 0))
    airgap_fed_hash = airgap_fed.get("latest_hash", "")
    airgap_state_hash = airgap_state.get("latest_hash", "")
    airgap_over_hash = airgap_oversight.get("latest_hash", "")

    verification_passed = all(
        [
            observed_bundle_count == expected_sessions,
            observed_receipt_count == expected_cast,
            observed_cast == expected_cast,
            observed_verify_ok == expected_cast,
            outbox_pending == 0,
            outbox_sent >= expected_sessions,
            consistency == "ok",
            overall in {"ok", "degraded"},
            airgap_outbox_pending == 0,
            airgap_outbox_sent >= expected_sessions,
            airgap_consistency == "ok",
            airgap_overall in {"ok", "degraded"},
            fed_idx >= expected_sessions,
            state_idx >= expected_sessions,
            over_idx >= expected_sessions,
            fed_idx == state_idx == over_idx,
            fed_hash != "",
            fed_hash == state_hash == over_hash,
            airgap_fed_idx >= expected_sessions,
            airgap_state_idx >= expected_sessions,
            airgap_over_idx >= expected_sessions,
            airgap_fed_idx == airgap_state_idx == airgap_over_idx,
            airgap_fed_hash != "",
            airgap_fed_hash == airgap_state_hash == airgap_over_hash,
        ]
    )

    summary = {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "seed": args.seed,
        "machines": args.machines,
        "sessions_per_machine": args.sessions_per_machine,
        "spoil_rate": args.spoil_rate,
        "expected_sessions": expected_sessions,
        "expected_spoiled": expected_spoiled,
        "expected_cast": expected_cast,
        "candidate_tally": tally,
        "winner": winner,
        "winner_votes": winner_votes,
        "observed_cast_success": observed_cast,
        "observed_receipt_verify_ok": observed_verify_ok,
        "observed_bundle_count": observed_bundle_count,
        "observed_receipt_count": observed_receipt_count,
        "observer_overall": overall,
        "observer_consistency": consistency,
        "observer_outbox_pending": outbox_pending,
        "observer_outbox_sent": outbox_sent,
        "airgap_observer_overall": airgap_overall,
        "airgap_observer_consistency": airgap_consistency,
        "airgap_observer_outbox_pending": airgap_outbox_pending,
        "airgap_observer_outbox_sent": airgap_outbox_sent,
        "bundle_archive_dir": str(bundle_archive_dir),
        "ledger_federal_index": fed_idx,
        "ledger_state_index": state_idx,
        "ledger_oversight_index": over_idx,
        "ledger_federal_hash": fed_hash,
        "ledger_state_hash": state_hash,
        "ledger_oversight_hash": over_hash,
        "airgap_ledger_federal_index": airgap_fed_idx,
        "airgap_ledger_state_index": airgap_state_idx,
        "airgap_ledger_oversight_index": airgap_over_idx,
        "airgap_ledger_federal_hash": airgap_fed_hash,
        "airgap_ledger_state_hash": airgap_state_hash,
        "airgap_ledger_oversight_hash": airgap_over_hash,
        "verification_passed": verification_passed,
    }

    report_json, report_md = write_report(summary, sorted(results, key=lambda r: r["session_uid"]), stamp)
    print(f"run_report_json:{report_json}")
    print(f"run_report_md:{report_md}")
    print(json.dumps(summary))

    if not verification_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
