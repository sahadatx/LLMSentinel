"""Persistent local control-plane records for policies, incidents, labels, and API keys.

SQLite is intended for local and single-host deployments. Production replicas should
use a shared database adapter with equivalent transactions and durability semantics.
The database file is created with mode 0600. Restrict its parent directory and storage
volume as well; this application does not encrypt SQLite contents at rest.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sentinel.gateway.auth import AuthContext


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ControlPlaneStore:
    """Small transactional repository with tenant-scoped security records."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or os.getenv("SENTINEL_CONTROL_DB", ".sentinel/control-plane.sqlite3"))
        if str(self.path) == ":memory:":
            raise ValueError("Control-plane state must be durable; :memory: is not supported")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise ValueError("Control-plane database path and parent must not be symbolic links")
        if stat.S_IMODE(self.path.parent.stat().st_mode) & 0o077:
            raise ValueError("Control-plane database directory must be private (mode 0700 or stricter)")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS policy_versions (
                    id TEXT PRIMARY KEY,
                    revision TEXT NOT NULL,
                    digest TEXT NOT NULL UNIQUE,
                    body TEXT NOT NULL,
                    signature TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    activated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assignee TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    activity TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS incidents_tenant_updated ON incidents(tenant_id, updated_at DESC);
                CREATE TABLE IF NOT EXISTS evaluation_samples (
                    id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    expected_disposition TEXT NOT NULL,
                    attack_family TEXT NOT NULL,
                    technique TEXT NOT NULL,
                    language TEXT NOT NULL,
                    source TEXT NOT NULL,
                    review_status TEXT NOT NULL,
                    split TEXT NOT NULL,
                    label_version TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reviewer TEXT,
                    reviewed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS evaluation_runs (
                    id TEXT PRIMARY KEY,
                    dataset_digest TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metrics TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evaluation_reviews (
                    sample_id TEXT NOT NULL REFERENCES evaluation_samples(id) ON DELETE CASCADE,
                    reviewer TEXT NOT NULL,
                    category TEXT NOT NULL,
                    expected_disposition TEXT NOT NULL,
                    attack_family TEXT NOT NULL,
                    technique TEXT NOT NULL,
                    language TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(sample_id, reviewer)
                );
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    name TEXT NOT NULL,
                    token_digest TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                );
                CREATE INDEX IF NOT EXISTS api_keys_tenant ON api_keys(tenant_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS audit_export_state (
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    cursor TEXT NOT NULL
                );
                INSERT OR IGNORE INTO audit_export_state(id, cursor) VALUES(1, '0000000000000000000000000000000000000000000000000000000000000000');
                CREATE TABLE IF NOT EXISTS audit_outbox (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_hash TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT NOT NULL,
                    delivered_at TEXT,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS audit_outbox_pending ON audit_outbox(delivered_at, sequence);
                """
            )
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def check_health(self) -> bool:
        try:
            with self._connect() as db:
                return db.execute("SELECT 1").fetchone()[0] == 1
        except sqlite3.Error:
            return False

    def get_audit_export_cursor(self) -> str:
        with self._connect() as db:
            row = db.execute("SELECT cursor FROM audit_export_state WHERE id=1").fetchone()
        return str(row["cursor"])

    def enqueue_audit_export(self, events: list[dict[str, Any]], next_cursor: str) -> None:
        if len(next_cursor) != 64 or any(char not in "0123456789abcdef" for char in next_cursor.lower()):
            raise ValueError("Audit export cursor must be a SHA-256 hash")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for record in events:
                event_hash = record.get("hash")
                if not isinstance(event_hash, str) or len(event_hash) != 64:
                    raise ValueError("Audit export event has no valid record hash")
                db.execute(
                    "INSERT OR IGNORE INTO audit_outbox(event_hash, payload, created_at, next_attempt_at) VALUES(?,?,?,?)",
                    (event_hash, json.dumps(record, sort_keys=True, separators=(",", ":")), str(record.get("timestamp", now)), now),
                )
            db.execute("UPDATE audit_export_state SET cursor=? WHERE id=1", (next_cursor,))

    def pending_audit_export(self, limit: int = 100) -> tuple[list[dict[str, Any]], float]:
        now = datetime.now(timezone.utc)
        with self._connect() as db:
            rows = db.execute(
                "SELECT event_hash, payload, next_attempt_at FROM audit_outbox WHERE delivered_at IS NULL ORDER BY sequence LIMIT ?",
                (max(1, min(limit, 250)),),
            ).fetchall()
        if not rows:
            return [], 0.0
        events: list[dict[str, Any]] = []
        for row in rows:
            next_attempt = datetime.fromisoformat(row["next_attempt_at"])
            wait_seconds = max(0.0, (next_attempt - now).total_seconds())
            if wait_seconds:
                if events:
                    break
                return [], min(wait_seconds, 60.0)
            record = json.loads(row["payload"])
            if not isinstance(record, dict) or record.get("hash") != row["event_hash"]:
                raise RuntimeError("Audit outbox payload does not match its chained record hash")
            events.append(record)
        return events, 0.0

    def mark_audit_export_attempt(self, event_hashes: list[str], error: str | None = None) -> None:
        now = datetime.now(timezone.utc)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for event_hash in event_hashes:
                row = db.execute(
                    "SELECT attempts FROM audit_outbox WHERE event_hash=? AND delivered_at IS NULL",
                    (event_hash,),
                ).fetchone()
                if row is None:
                    continue
                attempts = int(row["attempts"]) + 1
                if error is None:
                    db.execute(
                        "UPDATE audit_outbox SET attempts=?, delivered_at=?, last_error=NULL WHERE event_hash=?",
                        (attempts, now.isoformat(), event_hash),
                    )
                else:
                    delay_seconds = min(3600, 2 ** min(attempts, 12))
                    db.execute(
                        "UPDATE audit_outbox SET attempts=?, next_attempt_at=?, last_error=? WHERE event_hash=?",
                        (attempts, (now + timedelta(seconds=delay_seconds)).isoformat(), error[:120], event_hash),
                    )

    def audit_export_status(self) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                "SELECT SUM(CASE WHEN delivered_at IS NULL THEN 1 ELSE 0 END) AS pending, SUM(CASE WHEN delivered_at IS NOT NULL THEN 1 ELSE 0 END) AS delivered, MIN(CASE WHEN delivered_at IS NULL THEN created_at END) AS oldest_pending, MAX(delivered_at) AS last_delivered, MAX(CASE WHEN delivered_at IS NULL THEN last_error END) AS last_error FROM audit_outbox"
            ).fetchone()
        return {
            "pending": int(row["pending"] or 0),
            "delivered": int(row["delivered"] or 0),
            "oldest_pending": row["oldest_pending"],
            "last_delivered": row["last_delivered"],
            "last_error": row["last_error"],
        }

    def prune_audit_outbox(self, retention_days: int) -> int:
        if not 1 <= retention_days <= 3650:
            raise ValueError("Audit outbox retention must be between 1 and 3650 days")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._connect() as db:
            cursor = db.execute(
                "DELETE FROM audit_outbox WHERE delivered_at IS NOT NULL AND delivered_at<?",
                (cutoff,),
            )
        return cursor.rowcount

    def stage_policy(self, policy: dict[str, Any], signature: dict[str, Any] | None, actor: str) -> dict[str, Any]:
        digest = canonical_digest(policy)
        record_id = uuid.uuid4().hex
        created_at = utc_now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO policy_versions(id, revision, digest, body, signature, created_by, created_at, status) VALUES(?,?,?,?,?,?,?,?)",
                (record_id, str(policy.get("revision", "1")), digest, json.dumps(policy, sort_keys=True), json.dumps(signature) if signature else None, actor, created_at, "staged"),
            )
        return self.get_policy(record_id) or {}

    def get_policy(self, record_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM policy_versions WHERE id=?", (record_id,)).fetchone()
        if row is None:
            return None
        return self._policy_row(row)

    def get_active_policy(self) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM policy_versions WHERE status='active' ORDER BY activated_at DESC LIMIT 1"
            ).fetchone()
        return self._policy_row(row) if row else None

    def ensure_active_policy(
        self, policy: dict[str, Any], signature: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Persist the deployed policy as the active baseline without losing history."""
        digest = canonical_digest(policy)
        now = utc_now()
        with self._connect() as db:
            active = db.execute(
                "SELECT digest FROM policy_versions WHERE status='active' LIMIT 1"
            ).fetchone()
            if active is not None and active["digest"] == digest:
                if signature is not None and signature.get("policy_sha256") == digest:
                    db.execute(
                        "UPDATE policy_versions SET signature=? WHERE digest=?",
                        (json.dumps(signature), digest),
                    )
                row = db.execute(
                    "SELECT * FROM policy_versions WHERE digest=?", (digest,)
                ).fetchone()
                return self._policy_row(row)
            db.execute("UPDATE policy_versions SET status='approved' WHERE status='active'")
            row = db.execute(
                "SELECT * FROM policy_versions WHERE digest=?", (digest,)
            ).fetchone()
            if row is None:
                record_id = uuid.uuid4().hex
                db.execute(
                    "INSERT INTO policy_versions(id, revision, digest, body, signature, created_by, created_at, status, activated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (record_id, str(policy.get("revision", "1")), digest, json.dumps(policy, sort_keys=True), json.dumps(signature) if signature else None, "deployment", now, "active", now),
                )
                row = db.execute(
                    "SELECT * FROM policy_versions WHERE id=?", (record_id,)
                ).fetchone()
            else:
                if signature is not None and signature.get("policy_sha256") == digest:
                    db.execute(
                        "UPDATE policy_versions SET signature=? WHERE digest=?",
                        (json.dumps(signature), digest),
                    )
                db.execute(
                    "UPDATE policy_versions SET status='active', activated_at=? WHERE id=?",
                    (now, row["id"]),
                )
                row = db.execute(
                    "SELECT * FROM policy_versions WHERE id=?", (row["id"],)
                ).fetchone()
        return self._policy_row(row)

    @staticmethod
    def _policy_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "revision": row["revision"], "sha256": row["digest"],
            "policy": json.loads(row["body"]), "signature": json.loads(row["signature"]) if row["signature"] else None,
            "created_by": row["created_by"], "created_at": row["created_at"], "status": row["status"],
            "approved_by": row["approved_by"], "approved_at": row["approved_at"], "activated_at": row["activated_at"],
        }

    def list_policies(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM policy_versions ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 200)),)).fetchall()
        return [self._policy_row(row) for row in rows]

    def policy_has_dry_run(self, policy_digest: str) -> bool:
        with self._connect() as db:
            rows = db.execute(
                "SELECT metrics FROM evaluation_runs WHERE policy_digest=?",
                (policy_digest,),
            ).fetchall()
        for row in rows:
            if self._qualifying_dry_run(row["metrics"]):
                return True
        return False

    @staticmethod
    def _qualifying_dry_run(raw_metrics: str) -> bool:
        try:
            metrics = json.loads(raw_metrics)
        except (TypeError, json.JSONDecodeError):
            return False
        if not isinstance(metrics, dict):
            return False
        overall = metrics.get("overall")
        samples = overall.get("samples") if isinstance(overall, dict) else None
        return (
            isinstance(samples, int)
            and not isinstance(samples, bool)
            and samples > 0
            and metrics.get("split") == "validation"
            and metrics.get("reviewed_only") is True
            and metrics.get("evidence_quality") == "human_reviewed"
        )

    def approve_policy(self, record_id: str, actor: str) -> dict[str, Any] | None:
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT created_by, status FROM policy_versions WHERE id=?", (record_id,)).fetchone()
            if row is None:
                return None
            if row["status"] != "staged":
                raise ValueError("Only staged policy versions can be approved")
            if row["created_by"] == actor:
                raise PermissionError("Policy author cannot approve their own policy")
            db.execute("UPDATE policy_versions SET status='approved', approved_by=?, approved_at=? WHERE id=?", (actor, now, record_id))
        return self.get_policy(record_id)

    def activate_policy(self, record_id: str) -> dict[str, Any] | None:
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status, digest, activated_at FROM policy_versions WHERE id=?", (record_id,)).fetchone()
            if row is None:
                return None
            if row["status"] != "approved":
                raise ValueError("Policy must be approved before activation or rollback")
            # A previously active revision is a known rollback target. A newly
            # staged candidate must have a completed, non-empty dry-run first.
            if row["activated_at"] is None:
                evidence_rows = db.execute(
                    "SELECT metrics FROM evaluation_runs WHERE policy_digest=?",
                    (row["digest"],),
                ).fetchall()
                has_dry_run = False
                for evidence_row in evidence_rows:
                    if self._qualifying_dry_run(evidence_row["metrics"]):
                        has_dry_run = True
                        break
                if not has_dry_run:
                    raise ValueError("A completed non-empty validation dry-run is required before activation")
            db.execute("UPDATE policy_versions SET status='approved' WHERE status='active'")
            db.execute("UPDATE policy_versions SET status='active', activated_at=? WHERE id=?", (now, record_id))
        return self.get_policy(record_id)

    def create_incident(self, tenant_id: str, title: str, summary: str, severity: str, actor: str) -> dict[str, Any]:
        record_id = uuid.uuid4().hex
        now = utc_now()
        activity = [{"at": now, "actor": actor, "action": "created", "status": "open"}]
        with self._connect() as db:
            db.execute(
                "INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (record_id, tenant_id, title, summary, severity, "open", None, actor, now, now, json.dumps(activity)),
            )
        return self.get_incident(record_id) or {}

    @staticmethod
    def _incident_row(row: sqlite3.Row) -> dict[str, Any]:
        return {"id": row["id"], "tenant_id": row["tenant_id"], "title": row["title"], "summary": row["summary"], "severity": row["severity"], "status": row["status"], "assignee": row["assignee"], "created_by": row["created_by"], "created_at": row["created_at"], "updated_at": row["updated_at"], "activity": json.loads(row["activity"])}

    def get_incident(self, record_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM incidents WHERE id=?", (record_id,)).fetchone()
        return self._incident_row(row) if row else None

    def list_incidents(self, tenant_id: str | None, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            if tenant_id is None:
                rows = db.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall()
            else:
                rows = db.execute("SELECT * FROM incidents WHERE tenant_id=? ORDER BY updated_at DESC LIMIT ?", (tenant_id, max(1, min(limit, 500)))).fetchall()
        return [self._incident_row(row) for row in rows]

    def update_incident(self, record_id: str, status: str, assignee: str | None, actor: str, comment: str | None) -> dict[str, Any] | None:
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT activity FROM incidents WHERE id=?", (record_id,)).fetchone()
            if row is None:
                return None
            activity = json.loads(row["activity"])
            activity.append({"at": now, "actor": actor, "action": "updated", "status": status, "assignee": assignee, **({"comment": comment} if comment else {})})
            db.execute("UPDATE incidents SET status=?, assignee=?, updated_at=?, activity=? WHERE id=?", (status, assignee, now, json.dumps(activity), record_id))
        return self.get_incident(record_id)

    def create_sample(self, sample: dict[str, Any], actor: str) -> dict[str, Any]:
        now = utc_now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO evaluation_samples VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sample["id"], sample["category"], sample["prompt"], sample["expected_disposition"], sample["attack_family"], sample["technique"], sample["language"], sample["source"], sample["review_status"], sample["split"], sample["label_version"], actor, now, None, None),
            )
        return self.get_sample(sample["id"]) or {}

    def seed_samples(self, samples: list[dict[str, Any]]) -> int:
        now = utc_now()
        with self._connect() as db:
            current = db.execute("SELECT COUNT(*) FROM evaluation_samples").fetchone()[0]
            if current:
                return 0
            db.executemany(
                "INSERT OR IGNORE INTO evaluation_samples VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(sample["id"], sample["category"], sample["prompt"], sample["expected_disposition"], sample["attack_family"], sample["technique"], sample["language"], sample["source"], sample["review_status"], sample["split"], sample["label_version"], "seed-corpus", now, None, None) for sample in samples],
            )
            return db.total_changes

    def sample_count(self) -> int:
        with self._connect() as db:
            row = db.execute("SELECT COUNT(*) FROM evaluation_samples").fetchone()
        return int(row[0])

    @staticmethod
    def _sample_row(row: sqlite3.Row) -> dict[str, Any]:
        return {"id": row["id"], "category": row["category"], "prompt": row["prompt"], "expected_disposition": row["expected_disposition"], "attack_family": row["attack_family"], "technique": row["technique"], "language": row["language"], "source": row["source"], "review_status": row["review_status"], "split": row["split"], "label_version": row["label_version"], "created_by": row["created_by"], "created_at": row["created_at"], "reviewer": row["reviewer"], "reviewed_at": row["reviewed_at"]}

    @staticmethod
    def _review_summary(sample: dict[str, Any], reviews: list[sqlite3.Row]) -> dict[str, Any]:
        sample["review_count"] = len(reviews)
        if len(reviews) < 2:
            sample["inter_reviewer_agreement"] = None
            return sample
        fields = ("category", "expected_disposition", "attack_family", "technique", "language")
        votes: dict[tuple[str, ...], int] = {}
        for review in reviews:
            label = tuple(str(review[field]) for field in fields)
            votes[label] = votes.get(label, 0) + 1
        matching_pairs = sum(count * (count - 1) // 2 for count in votes.values())
        total_pairs = len(reviews) * (len(reviews) - 1) // 2
        sample["inter_reviewer_agreement"] = round(matching_pairs / total_pairs, 4)
        return sample

    def get_sample(self, sample_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM evaluation_samples WHERE id=?", (sample_id,)).fetchone()
            if row is None:
                return None
            reviews = db.execute(
                "SELECT * FROM evaluation_reviews WHERE sample_id=? ORDER BY created_at, reviewer",
                (sample_id,),
            ).fetchall()
            return self._review_summary(self._sample_row(row), reviews)

    def list_samples(self, split: str | None, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as db:
            if split:
                rows = db.execute("SELECT * FROM evaluation_samples WHERE split=? ORDER BY id LIMIT ?", (split, max(1, min(limit, 1000)))).fetchall()
            else:
                rows = db.execute("SELECT * FROM evaluation_samples ORDER BY id LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
            sample_ids = [row["id"] for row in rows]
            reviews_by_sample: dict[str, list[sqlite3.Row]] = {sample_id: [] for sample_id in sample_ids}
            for offset in range(0, len(sample_ids), 900):
                batch = sample_ids[offset : offset + 900]
                placeholders = ",".join("?" for _ in batch)
                review_rows = db.execute(
                    f"SELECT * FROM evaluation_reviews WHERE sample_id IN ({placeholders}) ORDER BY created_at, reviewer",
                    batch,
                ).fetchall()
                for review in review_rows:
                    reviews_by_sample[review["sample_id"]].append(review)
            return [
                self._review_summary(self._sample_row(row), reviews_by_sample[row["id"]])
                for row in rows
            ]

    def review_sample(self, sample_id: str, labels: dict[str, str], actor: str) -> dict[str, Any] | None:
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT created_by, review_status FROM evaluation_samples WHERE id=?", (sample_id,)).fetchone()
            if row is None:
                return None
            if row["created_by"] == actor:
                raise PermissionError("A sample author cannot review their own sample")
            if row["review_status"] == "human_reviewed":
                raise ValueError("Human-reviewed labels are immutable; add a new sample version for corrections")
            prior_review = db.execute(
                "SELECT 1 FROM evaluation_reviews WHERE sample_id=? AND reviewer=?",
                (sample_id, actor),
            ).fetchone()
            if prior_review is not None:
                raise PermissionError("Each reviewer may submit only one independent vote per sample")
            db.execute(
                "INSERT INTO evaluation_reviews(sample_id, reviewer, category, expected_disposition, attack_family, technique, language, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (sample_id, actor, labels["category"], labels["expected_disposition"], labels["attack_family"], labels["technique"], labels["language"], now),
            )
            votes = db.execute(
                "SELECT * FROM evaluation_reviews WHERE sample_id=? ORDER BY created_at, reviewer",
                (sample_id,),
            ).fetchall()
            label_fields = ("category", "expected_disposition", "attack_family", "technique", "language")
            counts: dict[tuple[str, ...], int] = {}
            representative: dict[tuple[str, ...], sqlite3.Row] = {}
            for vote in votes:
                signature = tuple(str(vote[field]) for field in label_fields)
                counts[signature] = counts.get(signature, 0) + 1
                representative[signature] = vote
            winning_signature, winning_count = max(counts.items(), key=lambda item: item[1])
            if len(votes) >= 2 and winning_count > len(votes) / 2:
                winning = representative[winning_signature]
                reviewers = ",".join(str(vote["reviewer"]) for vote in votes)
                db.execute(
                    "UPDATE evaluation_samples SET category=?, expected_disposition=?, attack_family=?, technique=?, language=?, review_status='human_reviewed', reviewer=?, reviewed_at=? WHERE id=?",
                    (*winning_signature, reviewers, now, sample_id),
                )
            else:
                status = "adjudication_required" if len(votes) >= 2 else "in_review"
                db.execute(
                    "UPDATE evaluation_samples SET review_status=? WHERE id=?",
                    (status, sample_id),
                )
        return self.get_sample(sample_id)

    def save_evaluation_run(self, dataset_digest: str, policy_digest: str, actor: str, metrics: dict[str, Any]) -> dict[str, Any]:
        record_id = uuid.uuid4().hex
        created_at = utc_now()
        with self._connect() as db:
            db.execute("INSERT INTO evaluation_runs VALUES(?,?,?,?,?,?)", (record_id, dataset_digest, policy_digest, actor, created_at, json.dumps(metrics, sort_keys=True)))
        return {"id": record_id, "dataset_sha256": dataset_digest, "policy_sha256": policy_digest, "created_by": actor, "created_at": created_at, "metrics": metrics}

    def list_evaluation_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM evaluation_runs ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 100)),)).fetchall()
        return [{"id": row["id"], "dataset_sha256": row["dataset_digest"], "policy_sha256": row["policy_digest"], "created_by": row["created_by"], "created_at": row["created_at"], "metrics": json.loads(row["metrics"])} for row in rows]

    def issue_api_key(self, tenant_id: str, role: str, name: str, actor: str, expires_at: str) -> tuple[dict[str, Any], str]:
        key_id = uuid.uuid4().hex[:16]
        token_secret = secrets.token_urlsafe(32)
        token = f"ls_{key_id}.{token_secret}"
        digest = hashlib.sha256(token.encode()).hexdigest()
        created_at = utc_now()
        with self._connect() as db:
            db.execute("INSERT INTO api_keys VALUES(?,?,?,?,?,?,?,?,?)", (key_id, tenant_id, role, name, digest, actor, created_at, expires_at, None))
        return ({"id": key_id, "tenant_id": tenant_id, "role": role, "name": name, "created_by": actor, "created_at": created_at, "expires_at": expires_at, "revoked_at": None}, token)

    def authenticate_api_key(self, token: str) -> AuthContext | None:
        try:
            prefix, secret = token.split(".", 1)
        except ValueError:
            return None
        if not prefix.startswith("ls_") or len(prefix) != 19 or not secret:
            return None
        key_id = prefix[3:]
        with self._connect() as db:
            row = db.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
        if row is None or row["revoked_at"] is not None or row["expires_at"] <= utc_now():
            return None
        if not secrets.compare_digest(row["token_digest"], hashlib.sha256(token.encode()).hexdigest()):
            return None
        return AuthContext(
            tenant_id=row["tenant_id"],
            role=row["role"],
            subject=f"api-key:{key_id}",
            authenticated=True,
            principal=row["created_by"],
        )

    def list_api_keys(self, tenant_id: str | None, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            if tenant_id is None:
                rows = db.execute("SELECT * FROM api_keys ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 200)),)).fetchall()
            else:
                rows = db.execute("SELECT * FROM api_keys WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?", (tenant_id, max(1, min(limit, 200)))).fetchall()
        return [{"id": row["id"], "tenant_id": row["tenant_id"], "role": row["role"], "name": row["name"], "created_by": row["created_by"], "created_at": row["created_at"], "expires_at": row["expires_at"], "revoked_at": row["revoked_at"]} for row in rows]

    def revoke_api_key(self, key_id: str, tenant_id: str | None) -> bool:
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if tenant_id is None:
                cursor = db.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now, key_id))
            else:
                cursor = db.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND tenant_id=? AND revoked_at IS NULL", (now, key_id, tenant_id))
        return cursor.rowcount == 1

    def rotate_api_key(self, key_id: str, tenant_id: str | None) -> tuple[dict[str, Any], str] | None:
        """Atomically revoke one active key and replace it without extending expiry."""
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if tenant_id is None:
                row = db.execute("SELECT * FROM api_keys WHERE id=? AND revoked_at IS NULL", (key_id,)).fetchone()
            else:
                row = db.execute("SELECT * FROM api_keys WHERE id=? AND tenant_id=? AND revoked_at IS NULL", (key_id, tenant_id)).fetchone()
            if row is None or row["expires_at"] <= now:
                return None
            new_id = uuid.uuid4().hex[:16]
            token = f"ls_{new_id}.{secrets.token_urlsafe(32)}"
            digest = hashlib.sha256(token.encode()).hexdigest()
            db.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now, key_id))
            db.execute(
                "INSERT INTO api_keys VALUES(?,?,?,?,?,?,?,?,?)",
                (new_id, row["tenant_id"], row["role"], row["name"], digest, row["created_by"], now, row["expires_at"], None),
            )
        return (
            {"id": new_id, "tenant_id": row["tenant_id"], "role": row["role"], "name": row["name"], "created_by": row["created_by"], "created_at": now, "expires_at": row["expires_at"], "revoked_at": None, "rotated_from": key_id},
            token,
        )
