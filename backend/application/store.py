"""Durable metadata store for local application-research projects."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def default_data_root() -> Path:
    configured = os.environ.get("AEGIS_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().absolute() / "application-research"
    return Path.home() / ".aegis" / "application-research"


class ApplicationStore:
    """SQLite index plus private content directories.

    Filesystem locations are intentionally kept out of public project
    dictionaries so a renderer or report cannot accidentally disclose the
    operator's original path.
    """

    def __init__(self, root: Path | None = None):
        self.root = (root or default_data_root()).absolute()
        self.projects_root = self.root / "projects"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.projects_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.root.chmod(0o700)
            self.projects_root.chmod(0o700)
        except OSError:
            pass
        self.database = self.root / "projects.sqlite3"
        self._initialize()
        try:
            self.database.chmod(0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA busy_timeout = 15000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    artifact_kind TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    artifact_relpath TEXT NOT NULL,
                    snapshot_relpath TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    summary_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    progress_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    file_path TEXT,
                    line INTEGER,
                    evidence TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS private_evidence (
                    finding_id TEXT PRIMARY KEY
                        REFERENCES findings(id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL
                        REFERENCES projects(id) ON DELETE CASCADE,
                    raw_evidence TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS staged_findings (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    file_path TEXT,
                    line INTEGER,
                    evidence TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS staged_private_evidence (
                    finding_id TEXT PRIMARY KEY REFERENCES staged_findings(id) ON DELETE CASCADE,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    raw_evidence TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_project
                    ON findings(project_id);
                CREATE INDEX IF NOT EXISTS idx_staged_findings_job
                    ON staged_findings(job_id);
                CREATE INDEX IF NOT EXISTS idx_private_evidence_project
                    ON private_evidence(project_id);
                CREATE INDEX IF NOT EXISTS idx_jobs_project
                    ON jobs(project_id);
                """
            )
            columns = {
                str(row["name"]) for row in connection.execute("PRAGMA table_info(jobs)")
            }
            if "progress_json" not in columns:
                connection.execute(
                    "ALTER TABLE jobs ADD COLUMN progress_json TEXT NOT NULL DEFAULT '{}'"
                )

    def project_directory(self, project_id: str) -> Path:
        return self.projects_root / project_id

    def create_project(self, record: dict[str, Any]) -> dict[str, Any]:
        timestamp = _now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO projects (
                    id, name, source_type, artifact_kind, sha256, size_bytes,
                    status, artifact_relpath, snapshot_relpath, metadata_json,
                    summary_json, error, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', NULL, ?, ?)
                """,
                (
                    record["id"],
                    record["name"],
                    record["source_type"],
                    record["artifact_kind"],
                    record["sha256"],
                    record["size_bytes"],
                    "imported",
                    record["artifact_relpath"],
                    record["snapshot_relpath"],
                    json.dumps(record.get("metadata", {}), sort_keys=True),
                    timestamp,
                    timestamp,
                ),
            )
        return self.get_project(record["id"])

    def list_projects(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 500))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM projects ORDER BY created_at DESC LIMIT ?", (bounded,)
            ).fetchall()
            return [self._public_project(row, include_findings=False) for row in rows]

    def get_project(self, project_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if row is None:
                raise KeyError(project_id)
            project = self._public_project(row, include_findings=False)
            page = self._findings_page(connection, project_id, 0, 100)
            project["findings"] = page["findings"]
            project["findings_total"] = page["total"]
            project["findings_page"] = {
                "offset": 0,
                "limit": 100,
                "has_more": page["has_more"],
                "analysis_job_id": project["summary"].get("analysis_job_id"),
            }
            return project

    @staticmethod
    def _findings_page(
        connection: sqlite3.Connection, project_id: str, offset: int, limit: int
    ) -> dict[str, Any]:
        total = int(connection.execute(
            "SELECT COUNT(*) FROM findings WHERE project_id = ?", (project_id,)
        ).fetchone()[0])
        rows = connection.execute(
            """SELECT findings.id, rule_id, severity, confidence, status, title,
                      description, file_path, line, evidence, remediation,
                      EXISTS(SELECT 1 FROM private_evidence
                             WHERE private_evidence.finding_id = findings.id)
                      AS has_private_evidence
               FROM findings WHERE findings.project_id = ?
               ORDER BY CASE severity
                   WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                   file_path, line, title, findings.id
               LIMIT ? OFFSET ?""",
            (project_id, limit, offset),
        ).fetchall()
        findings = [
            {**dict(row), "has_private_evidence": bool(row["has_private_evidence"])}
            for row in rows
        ]
        return {
            "findings": findings,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(findings) < total,
        }

    def list_findings_page(
        self, project_id: str, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        if offset < 0 or not 1 <= limit <= 500:
            raise ValueError("Finding page must use nonnegative offset and limit 1–500")
        with self._connect() as connection:
            connection.execute("BEGIN")
            project = connection.execute(
                "SELECT summary_json FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if project is None:
                raise KeyError(project_id)
            page = self._findings_page(connection, project_id, offset, limit)
            page["analysis_job_id"] = json.loads(project["summary_json"] or "{}").get(
                "analysis_job_id"
            )
            return page

    def get_private_finding(
        self, project_id: str, finding_id: str
    ) -> dict[str, Any]:
        """Return exact evidence only to a privileged desktop caller."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT findings.id, findings.rule_id, findings.severity,
                       findings.title, findings.file_path, findings.line,
                       private_evidence.raw_evidence
                FROM findings
                JOIN private_evidence
                  ON private_evidence.finding_id = findings.id
                WHERE findings.project_id = ? AND findings.id = ?
                """,
                (project_id, finding_id),
            ).fetchone()
            if row is None:
                raise KeyError(finding_id)
            return dict(row)

    def list_private_evidence(self, project_id: str) -> list[dict[str, Any]]:
        """Build the operator-only evidence ledger for export or local LLM use."""
        with self._connect() as connection:
            project = connection.execute(
                "SELECT id FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if project is None:
                raise KeyError(project_id)
            rows = connection.execute(
                """
                SELECT findings.id, findings.rule_id, findings.severity,
                       findings.title, findings.file_path, findings.line,
                       private_evidence.raw_evidence
                FROM findings
                JOIN private_evidence
                  ON private_evidence.finding_id = findings.id
                WHERE findings.project_id = ?
                ORDER BY CASE findings.severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                    findings.file_path, findings.line, findings.title
                """,
                (project_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def list_private_evidence_page(
        self, project_id: str, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        if offset < 0 or not 1 <= limit <= 500:
            raise ValueError("Private evidence page must use nonnegative offset and limit 1–500")
        with self._connect() as connection:
            connection.execute("BEGIN")
            project = connection.execute(
                "SELECT summary_json FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if project is None:
                raise KeyError(project_id)
            total = int(connection.execute(
                "SELECT COUNT(*) FROM private_evidence WHERE project_id = ?",
                (project_id,),
            ).fetchone()[0])
            rows = connection.execute(
                """SELECT findings.id, findings.rule_id, findings.severity,
                          findings.title, findings.file_path, findings.line,
                          private_evidence.raw_evidence
                   FROM findings JOIN private_evidence
                     ON private_evidence.finding_id = findings.id
                   WHERE findings.project_id = ?
                   ORDER BY CASE findings.severity
                       WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                       WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                       findings.file_path, findings.line, findings.title, findings.id
                   LIMIT ? OFFSET ?""",
                (project_id, limit, offset),
            ).fetchall()
            evidence = [dict(row) for row in rows]
            return {
                "evidence": evidence,
                "total": total,
                "offset": offset,
                "limit": limit,
                "has_more": offset + len(evidence) < total,
                "analysis_job_id": json.loads(project["summary_json"] or "{}").get(
                    "analysis_job_id"
                ),
            }

    def list_private_evidence_for_model(
        self, project_id: str, question: str, limit: int = 500
    ) -> dict[str, Any]:
        """Bound private chat retrieval and rank requested categories first.

        The raw question only selects fixed Boolean priorities; it is never
        interpolated into SQL. This keeps late flags or accounts from being
        displaced by hundreds of higher-severity, unrelated secrets.
        """
        if not 1 <= limit <= 500:
            raise ValueError("Private model context limit must be 1–500")
        priorities = (
            int(bool(re.search(r"\bflags?\b", question, re.I))),
            int(bool(re.search(r"\b(?:accounts?|usernames?|users?)\b", question, re.I))),
            int(bool(re.search(r"\b(?:endpoints?|addresses?|urls?)\b", question, re.I))),
            int(bool(re.search(r"\b(?:projects?|codenames?|acquisition|company)\b", question, re.I))),
            int(bool(re.search(r"\b(?:passwords?|credentials?|secrets?|tokens?|keys?|recovery)\b", question, re.I))),
        )
        with self._connect() as connection:
            connection.execute("BEGIN")
            project = connection.execute(
                "SELECT summary_json FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if project is None:
                raise KeyError(project_id)
            total = int(connection.execute(
                "SELECT COUNT(*) FROM private_evidence WHERE project_id = ?",
                (project_id,),
            ).fetchone()[0])
            rows = connection.execute(
                """SELECT findings.id, findings.rule_id, findings.severity,
                          findings.title, findings.file_path, findings.line,
                          private_evidence.raw_evidence
                   FROM findings JOIN private_evidence
                     ON private_evidence.finding_id = findings.id
                   WHERE findings.project_id = ?
                   ORDER BY CASE WHEN
                       (? = 1 AND findings.rule_id = 'evidence.scoring-flag') OR
                       (? = 1 AND findings.rule_id = 'identity.account-identifier') OR
                       (? = 1 AND findings.rule_id = 'network.internal-endpoint') OR
                       (? = 1 AND findings.rule_id = 'intelligence.context-identifier') OR
                       (? = 1 AND findings.rule_id LIKE 'secret.%')
                     THEN 0 ELSE 1 END,
                     CASE findings.severity
                       WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                       WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                     findings.file_path, findings.line, findings.title, findings.id
                   LIMIT ?""",
                (project_id, *priorities, limit),
            ).fetchall()
            return {
                "evidence": [dict(row) for row in rows],
                "total": total,
                "limit": limit,
                "has_more": len(rows) < total,
                "analysis_job_id": json.loads(project["summary_json"] or "{}").get(
                    "analysis_job_id"
                ),
            }

    def get_internal_project(self, project_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if row is None:
                raise KeyError(project_id)
            result = dict(row)
            result["metadata"] = json.loads(result.pop("metadata_json") or "{}")
            result["summary"] = json.loads(result.pop("summary_json") or "{}")
            return result

    def delete_project_record(self, project_id: str) -> None:
        """Delete project metadata and all cascading jobs/evidence records."""
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM projects WHERE id = ?", (project_id,)
            )
            if cursor.rowcount != 1:
                raise KeyError(project_id)
        # Private evidence may have lived in the WAL. Truncate it after the
        # committed secure deletion when no other connection is holding it.
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass

    def start_job(self, job_id: str, project_id: str, kind: str) -> None:
        timestamp = _now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    id, project_id, kind, status, created_at, started_at
                ) VALUES (?, ?, ?, 'running', ?, ?)
                """,
                (job_id, project_id, kind, timestamp, timestamp),
            )
            connection.execute(
                "UPDATE projects SET status = 'analyzing', error = NULL, updated_at = ? WHERE id = ?",
                (timestamp, project_id),
            )

    def append_job_findings(
        self,
        job_id: str,
        project_id: str,
        findings: list[dict[str, Any]],
        private_evidence: list[dict[str, str]],
    ) -> None:
        """Stage one file's results without replacing the last completed run."""
        if not findings:
            return
        timestamp = _now()
        finding_ids = {str(item["id"]) for item in findings}
        with self._connect() as connection:
            connection.executemany(
                """INSERT INTO staged_findings (
                    id, job_id, project_id, rule_id, severity, confidence,
                    status, title, description, file_path, line, evidence,
                    remediation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(
                    item["id"], job_id, project_id, item["rule_id"],
                    item["severity"], item["confidence"], item["status"],
                    item["title"], item["description"], item.get("file_path"),
                    item.get("line"), item["evidence"], item["remediation"],
                    timestamp,
                ) for item in findings],
            )
            connection.executemany(
                """INSERT INTO staged_private_evidence (
                    finding_id, job_id, project_id, raw_evidence, created_at
                ) VALUES (?, ?, ?, ?, ?)""",
                [(
                    item["finding_id"], job_id, project_id,
                    item["raw_evidence"], timestamp,
                ) for item in private_evidence if item.get("finding_id") in finding_ids],
            )

    def list_staged_findings(
        self, job_id: str, *, limit: int = 5000, secret_only: bool = False
    ) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 100_000))
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, rule_id, severity, confidence, status, title,
                           description, file_path, line, evidence, remediation
                    FROM staged_findings
                    WHERE job_id = ? AND (? = 0 OR rule_id LIKE 'secret.%')
                    ORDER BY rowid LIMIT ?""",
                (job_id, int(secret_only), bounded),
            ).fetchall()
            return [dict(row) for row in rows]

    def update_job_progress(
        self, job_id: str, project_id: str, progress: dict[str, Any]
    ) -> None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT progress_json FROM jobs WHERE id = ? AND project_id = ? AND status = 'running'",
                (job_id, project_id),
            ).fetchone()
            if row is None:
                return
            previous = json.loads(row["progress_json"] or "{}")
            if previous.get("cancel_requested"):
                progress = {**progress, "cancel_requested": True}
            connection.execute(
                "UPDATE jobs SET progress_json = ? WHERE id = ? AND project_id = ? AND status = 'running'",
                (json.dumps(progress, sort_keys=True), job_id, project_id),
            )

    def get_latest_job(self, project_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            project = connection.execute(
                "SELECT id FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if project is None:
                raise KeyError(project_id)
            row = connection.execute(
                """SELECT id, kind, status, error, created_at, started_at,
                          completed_at, progress_json
                   FROM jobs WHERE project_id = ?
                   ORDER BY rowid DESC LIMIT 1""",
                (project_id,),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["progress"] = json.loads(result.pop("progress_json") or "{}")
            return result

    def request_job_cancel(self, job_id: str, project_id: str) -> None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT progress_json FROM jobs WHERE id = ? AND project_id = ? AND status = 'running'",
                (job_id, project_id),
            ).fetchone()
            if row is None:
                return
            progress = json.loads(row["progress_json"] or "{}")
            progress["cancel_requested"] = True
            connection.execute(
                "UPDATE jobs SET progress_json = ? WHERE id = ? AND project_id = ?",
                (json.dumps(progress, sort_keys=True), job_id, project_id),
            )

    def cancel_job(self, job_id: str, project_id: str) -> None:
        timestamp = _now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT summary_json FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if row is None:
                raise KeyError(project_id)
            previous_summary = json.loads(row["summary_json"] or "{}")
            previous_status = "complete" if previous_summary.get("completed_at") else "imported"
            connection.execute(
                "UPDATE projects SET status = ?, error = NULL, updated_at = ? WHERE id = ?",
                (previous_status, timestamp, project_id),
            )
            connection.execute(
                "UPDATE jobs SET status = 'cancelled', completed_at = ? WHERE id = ? AND project_id = ?",
                (timestamp, job_id, project_id),
            )
            connection.execute("DELETE FROM staged_private_evidence WHERE job_id = ?", (job_id,))
            connection.execute("DELETE FROM staged_findings WHERE job_id = ?", (job_id,))

    def complete_job(
        self,
        job_id: str,
        project_id: str,
        summary: dict[str, Any],
        findings: list[dict[str, Any]],
        private_evidence: list[dict[str, str]],
    ) -> dict[str, Any]:
        timestamp = _now()
        finding_ids = {str(finding["id"]) for finding in findings}
        private_rows = [
            item for item in private_evidence
            if str(item.get("finding_id", "")) in finding_ids
        ]
        with self._connect() as connection:
            connection.execute("DELETE FROM findings WHERE project_id = ?", (project_id,))
            connection.execute(
                """INSERT INTO findings (
                    id, project_id, rule_id, severity, confidence, status,
                    title, description, file_path, line, evidence, remediation, created_at
                ) SELECT id, project_id, rule_id, severity, confidence, status,
                         title, description, file_path, line, evidence,
                         remediation, created_at
                  FROM staged_findings WHERE job_id = ? AND project_id = ?""",
                (job_id, project_id),
            )
            connection.executemany(
                """
                INSERT INTO findings (
                    id, project_id, rule_id, severity, confidence, status,
                    title, description, file_path, line, evidence,
                    remediation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        finding["id"], project_id, finding["rule_id"],
                        finding["severity"], finding["confidence"],
                        finding["status"], finding["title"],
                        finding["description"], finding.get("file_path"),
                        finding.get("line"), finding["evidence"],
                        finding["remediation"], timestamp,
                    )
                    for finding in findings
                ],
            )
            connection.execute(
                """INSERT INTO private_evidence (
                    finding_id, project_id, raw_evidence, created_at
                ) SELECT finding_id, project_id, raw_evidence, created_at
                  FROM staged_private_evidence WHERE job_id = ? AND project_id = ?""",
                (job_id, project_id),
            )
            connection.executemany(
                """
                INSERT INTO private_evidence (
                    finding_id, project_id, raw_evidence, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        item["finding_id"], project_id,
                        item["raw_evidence"], timestamp,
                    )
                    for item in private_rows
                ],
            )
            connection.execute(
                """
                UPDATE projects SET status = 'complete', summary_json = ?,
                    error = NULL, updated_at = ? WHERE id = ?
                """,
                (json.dumps(summary, sort_keys=True), timestamp, project_id),
            )
            connection.execute(
                """
                UPDATE jobs SET status = 'complete', completed_at = ?
                WHERE id = ? AND project_id = ?
                """,
                (timestamp, job_id, project_id),
            )
            connection.execute(
                "DELETE FROM staged_private_evidence WHERE job_id = ?", (job_id,)
            )
            connection.execute(
                "DELETE FROM staged_findings WHERE job_id = ?", (job_id,)
            )
        return self.get_project(project_id)

    def record_firmware_advisory_lookup(
        self,
        project_id: str,
        lookup: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist only sanitized advisory metadata in an analyzed project."""
        timestamp = _now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT summary_json FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if row is None:
                raise KeyError(project_id)
            summary = json.loads(row["summary_json"] or "{}")
            firmware = summary.get("firmware")
            if not isinstance(firmware, dict) or not firmware.get("recognized"):
                raise ValueError("Analyze recognized Cisco firmware before advisory lookup")
            version = str(lookup.get("version") or "")
            versions = {str(item) for item in firmware.get("versions", [])}
            if not version or version not in versions:
                raise ValueError(
                    "Firmware version changed while the advisory lookup was running"
                )
            firmware["advisory_lookup_performed"] = True
            firmware["advisory_lookup"] = lookup
            cursor = connection.execute(
                """
                UPDATE projects SET summary_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (json.dumps(summary, sort_keys=True), timestamp, project_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(project_id)
        return self.get_project(project_id)

    def fail_job(self, job_id: str, project_id: str, error: str) -> None:
        timestamp = _now()
        safe_error = str(error)[:500]
        with self._connect() as connection:
            row = connection.execute(
                "SELECT summary_json FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            previous_summary = json.loads(row["summary_json"] or "{}") if row else {}
            status = "complete" if previous_summary.get("completed_at") else "error"
            connection.execute(
                """
                UPDATE projects SET status = ?, error = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, safe_error, timestamp, project_id),
            )
            connection.execute(
                """
                UPDATE jobs SET status = 'error', error = ?, completed_at = ?
                WHERE id = ? AND project_id = ?
                """,
                (safe_error, timestamp, job_id, project_id),
            )
            connection.execute("DELETE FROM staged_private_evidence WHERE job_id = ?", (job_id,))
            connection.execute("DELETE FROM staged_findings WHERE job_id = ?", (job_id,))

    @staticmethod
    def _public_project(
        row: sqlite3.Row, *, include_findings: bool = False
    ) -> dict[str, Any]:
        project = {
            "id": row["id"],
            "name": row["name"],
            "source_type": row["source_type"],
            "artifact_kind": row["artifact_kind"],
            "sha256": row["sha256"],
            "size_bytes": row["size_bytes"],
            "status": row["status"],
            "intake": json.loads(row["metadata_json"] or "{}"),
            "summary": json.loads(row["summary_json"] or "{}"),
            "error": row["error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        if include_findings:
            project["findings"] = []
        return project
