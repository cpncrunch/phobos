from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import json
import re
import sqlite3
import uuid


SCHEMA_VERSION = 4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class StoredJob:
    id: int
    name: str
    schedule: str
    prompt: str
    next_run_at: str
    enabled: bool
    last_run_at: str | None = None


@dataclass(slots=True)
class StoredProcess:
    id: int
    session_id: str
    command: str
    target: str
    action_type: str
    purpose: str
    pid: int | None
    status: str
    started_at: str
    stdout_path: str
    stderr_path: str
    rc_path: str
    exit_code: int | None = None
    ended_at: str | None = None


@dataclass(slots=True)
class StoredTask:
    id: int
    session_id: str
    content: str
    status: str
    created_at: str
    updated_at: str
    metadata: dict[str, Any]


class AgentStore:
    """SQLite-backed local state for the standalone Phobos Agent runtime."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.fts_available = False
        self.init_schema()

    def close(self) -> None:
        self.conn.close()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                engagement_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_name_engagement ON sessions(name, engagement_path);
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_session_id ON messages(session_id, id);
            CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_key ON memories(key);
            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                args_json TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at TEXT NOT NULL,
                resolved_at TEXT,
                resolved_by TEXT,
                result_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_approvals_session_status ON approvals(session_id, status);
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                name TEXT NOT NULL,
                schedule TEXT NOT NULL,
                prompt TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                next_run_at TEXT NOT NULL,
                last_run_at TEXT,
                last_result TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_jobs_session_next_run ON jobs(session_id, enabled, next_run_at);
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                event TEXT NOT NULL,
                data_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id, id);
            CREATE TABLE IF NOT EXISTS context_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                source_from INTEGER,
                source_to INTEGER,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_context_summaries_session ON context_summaries(session_id, id);
            CREATE TABLE IF NOT EXISTS processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                command TEXT NOT NULL,
                target TEXT NOT NULL,
                action_type TEXT NOT NULL,
                purpose TEXT NOT NULL,
                pid INTEGER,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                exit_code INTEGER,
                stdout_path TEXT NOT NULL,
                stderr_path TEXT NOT NULL,
                rc_path TEXT NOT NULL,
                decision_json TEXT NOT NULL DEFAULT '{}',
                approval_id INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_processes_session ON processes(session_id, id);
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                content TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tasks_session_status ON tasks(session_id, status, id);
            CREATE TABLE IF NOT EXISTS context_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                parent_id INTEGER,
                depth INTEGER NOT NULL DEFAULT 0,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                source_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_context_nodes_session ON context_nodes(session_id, id);
            CREATE INDEX IF NOT EXISTS idx_context_nodes_parent ON context_nodes(parent_id);
            CREATE TABLE IF NOT EXISTS delegations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                status TEXT NOT NULL,
                prompt TEXT NOT NULL,
                tasks_json TEXT NOT NULL DEFAULT '[]',
                results_json TEXT NOT NULL DEFAULT '[]',
                artifacts_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_delegations_session ON delegations(session_id, id);
            CREATE TABLE IF NOT EXISTS media_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                source_path TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_media_session ON media_artifacts(session_id, id);
            """
        )
        self._init_meta()
        self.fts_available = self._init_fts()
        self.conn.commit()

    def _init_meta(self) -> None:
        self.conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")
        now = utc_now()
        self.conn.execute("INSERT OR IGNORE INTO meta(key, value, updated_at) VALUES ('schema_version', ?, ?)", (str(SCHEMA_VERSION), now))
        self.conn.execute("UPDATE meta SET value=?, updated_at=? WHERE key='schema_version'", (str(SCHEMA_VERSION), now))

    def _init_fts(self) -> bool:
        """Initialize FTS5 indexes when the bundled SQLite build supports them.

        LIKE search remains as a fallback. FTS5 gives the local runtime a more
        Hermes-like session/memory recall path without adding non-stdlib deps.
        """

        try:
            self.conn.executescript(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                    session_id UNINDEXED,
                    role UNINDEXED,
                    content,
                    created_at UNINDEXED,
                    content='messages',
                    content_rowid='id'
                );
                CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
                    INSERT INTO messages_fts(rowid, session_id, role, content, created_at)
                    VALUES (new.id, new.session_id, new.role, new.content, new.created_at);
                END;
                CREATE TRIGGER IF NOT EXISTS messages_ad BEFORE DELETE ON messages BEGIN
                    INSERT INTO messages_fts(messages_fts, rowid, session_id, role, content, created_at)
                    VALUES('delete', old.id, old.session_id, old.role, old.content, old.created_at);
                END;
                CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
                    INSERT INTO messages_fts(messages_fts, rowid, session_id, role, content, created_at)
                    VALUES('delete', old.id, old.session_id, old.role, old.content, old.created_at);
                    INSERT INTO messages_fts(rowid, session_id, role, content, created_at)
                    VALUES (new.id, new.session_id, new.role, new.content, new.created_at);
                END;

                CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                    key,
                    value,
                    tags,
                    content='memories',
                    content_rowid='id'
                );
                CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
                    INSERT INTO memories_fts(rowid, key, value, tags)
                    VALUES (new.id, new.key, new.value, new.tags);
                END;
                CREATE TRIGGER IF NOT EXISTS memories_ad BEFORE DELETE ON memories BEGIN
                    INSERT INTO memories_fts(memories_fts, rowid, key, value, tags)
                    VALUES('delete', old.id, old.key, old.value, old.tags);
                END;
                CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
                    INSERT INTO memories_fts(memories_fts, rowid, key, value, tags)
                    VALUES('delete', old.id, old.key, old.value, old.tags);
                    INSERT INTO memories_fts(rowid, key, value, tags)
                    VALUES (new.id, new.key, new.value, new.tags);
                END;
                """
            )
            self.conn.execute("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')")
            self.conn.execute("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')")
            return True
        except sqlite3.OperationalError:
            return False

    def schema_info(self) -> dict[str, Any]:
        row = self.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        return {
            "schema_version": int(row["value"]) if row else SCHEMA_VERSION,
            "latest_supported_schema_version": SCHEMA_VERSION,
            "fts_available": bool(self.fts_available),
            "path": str(self.path),
        }

    def get_or_create_session(self, name: str, engagement_path: str | Path) -> str:
        engagement = str(Path(engagement_path))
        row = self.conn.execute("SELECT id FROM sessions WHERE name=? AND engagement_path=?", (name, engagement)).fetchone()
        if row:
            session_id = str(row["id"])
            self.conn.execute("UPDATE sessions SET updated_at=? WHERE id=?", (utc_now(), session_id))
            self.conn.commit()
            return session_id
        session_id = str(uuid.uuid4())
        now = utc_now()
        self.conn.execute(
            "INSERT INTO sessions(id, name, engagement_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, name, engagement, now, now),
        )
        self.conn.commit()
        return session_id

    def list_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    def append_message(self, session_id: str, role: str, content: str, metadata: dict[str, Any] | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO messages(session_id, role, content, metadata_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, role, content, json.dumps(metadata or {}, sort_keys=True), utc_now()),
        )
        self.conn.execute("UPDATE sessions SET updated_at=? WHERE id=?", (utc_now(), session_id))
        self.conn.commit()
        return int(cur.lastrowid)

    def recent_messages(self, session_id: str, limit: int = 12) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM messages WHERE session_id=? ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
        out = []
        for row in reversed(rows):
            out.append({
                "id": row["id"], "role": row["role"], "content": row["content"],
                "metadata": json.loads(row["metadata_json"] or "{}"), "created_at": row["created_at"],
            })
        return out

    def all_messages(self, session_id: str, limit: int = 1000) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM messages WHERE session_id=? ORDER BY id LIMIT ?",
            (session_id, limit),
        ).fetchall()
        return [_message_row(row) for row in rows]

    def get_message(self, message_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
        return _message_row(row) if row else None

    def search_messages(self, session_id: str, query: str, limit: int = 10) -> list[dict[str, Any]]:
        if query.strip() and self.fts_available:
            for match_query in _fts_query_candidates(query):
                try:
                    rows = self.conn.execute(
                        """
                        SELECT messages.*
                        FROM messages_fts
                        JOIN messages ON messages_fts.rowid = messages.id
                        WHERE messages_fts MATCH ? AND messages.session_id=?
                        ORDER BY bm25(messages_fts), messages.id DESC
                        LIMIT ?
                        """,
                        (match_query, session_id, limit),
                    ).fetchall()
                    if rows:
                        return [_message_row(row) for row in rows]
                except sqlite3.OperationalError:
                    continue
        like = f"%{query}%"
        rows = self.conn.execute(
            "SELECT * FROM messages WHERE session_id=? AND content LIKE ? ORDER BY id DESC LIMIT ?",
            (session_id, like, limit),
        ).fetchall()
        return [_message_row(row) for row in rows]

    def remember(self, key: str, value: str, tags: str = "") -> int:
        now = utc_now()
        existing = self.conn.execute("SELECT id FROM memories WHERE key=?", (key,)).fetchone()
        if existing:
            self.conn.execute("UPDATE memories SET value=?, tags=?, updated_at=? WHERE key=?", (value, tags, now, key))
            self.conn.commit()
            return int(existing["id"])
        cur = self.conn.execute(
            "INSERT INTO memories(key, value, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (key, value, tags, now, now),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def recall(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        if query.strip() and self.fts_available:
            for match_query in _fts_query_candidates(query):
                try:
                    rows = self.conn.execute(
                        """
                        SELECT memories.*
                        FROM memories_fts
                        JOIN memories ON memories_fts.rowid = memories.id
                        WHERE memories_fts MATCH ?
                        ORDER BY bm25(memories_fts), memories.updated_at DESC
                        LIMIT ?
                        """,
                        (match_query, limit),
                    ).fetchall()
                    if rows:
                        return [dict(row) for row in rows]
                except sqlite3.OperationalError:
                    continue
        like = f"%{query}%"
        rows = self.conn.execute(
            "SELECT * FROM memories WHERE key LIKE ? OR value LIKE ? OR tags LIKE ? ORDER BY updated_at DESC LIMIT ?",
            (like, like, like, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def create_context_summary(self, session_id: str, source_from: int | None, source_to: int | None, summary: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO context_summaries(session_id, source_from, source_to, summary, created_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, source_from, source_to, summary, utc_now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def latest_context_summary(self, session_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM context_summaries WHERE session_id=? ORDER BY id DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_context_summaries(self, session_id: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM context_summaries WHERE session_id=? ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def create_context_node(
        self,
        session_id: str,
        title: str,
        summary: str,
        sources: list[dict[str, Any]] | None = None,
        *,
        parent_id: int | None = None,
        depth: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO context_nodes(session_id, parent_id, depth, title, summary, source_json, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, parent_id, depth, title, summary, json.dumps(sources or [], sort_keys=True), json.dumps(metadata or {}, sort_keys=True), utc_now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_context_node(self, node_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM context_nodes WHERE id=?", (node_id,)).fetchone()
        return _context_node_row(row) if row else None

    def list_context_nodes(self, session_id: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM context_nodes WHERE session_id=? ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
        return [_context_node_row(row) for row in rows]

    def child_context_nodes(self, parent_id: int) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM context_nodes WHERE parent_id=? ORDER BY id", (parent_id,)).fetchall()
        return [_context_node_row(row) for row in rows]

    def search_context_nodes(self, session_id: str, query: str, limit: int = 10) -> list[dict[str, Any]]:
        like = f"%{query}%"
        rows = self.conn.execute(
            """
            SELECT * FROM context_nodes
            WHERE session_id=? AND (title LIKE ? OR summary LIKE ? OR metadata_json LIKE ?)
            ORDER BY id DESC LIMIT ?
            """,
            (session_id, like, like, like, limit),
        ).fetchall()
        return [_context_node_row(row) for row in rows]

    def search_all_messages(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        if query.strip() and self.fts_available:
            for match_query in _fts_query_candidates(query):
                try:
                    rows = self.conn.execute(
                        """
                        SELECT messages.*, sessions.name AS session_name
                        FROM messages_fts
                        JOIN messages ON messages_fts.rowid = messages.id
                        LEFT JOIN sessions ON messages.session_id = sessions.id
                        WHERE messages_fts MATCH ?
                        ORDER BY bm25(messages_fts), messages.id DESC
                        LIMIT ?
                        """,
                        (match_query, limit),
                    ).fetchall()
                    if rows:
                        return [_message_row(row) | {"session_name": row["session_name"]} for row in rows]
                except sqlite3.OperationalError:
                    continue
        like = f"%{query}%"
        rows = self.conn.execute(
            """
            SELECT messages.*, sessions.name AS session_name
            FROM messages
            LEFT JOIN sessions ON messages.session_id = sessions.id
            WHERE content LIKE ?
            ORDER BY messages.id DESC LIMIT ?
            """,
            (like, limit),
        ).fetchall()
        return [_message_row(row) | {"session_name": row["session_name"]} for row in rows]

    def create_task(self, session_id: str, content: str, status: str = "pending", metadata: dict[str, Any] | None = None) -> int:
        now = utc_now()
        cur = self.conn.execute(
            "INSERT INTO tasks(session_id, content, status, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, content, status, json.dumps(metadata or {}, sort_keys=True), now, now),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def update_task(self, task_id: int, *, content: str | None = None, status: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any] | None:
        fields: list[str] = []
        values: list[Any] = []
        if content is not None:
            fields.append("content=?")
            values.append(content)
        if status is not None:
            fields.append("status=?")
            values.append(status)
        if metadata is not None:
            fields.append("metadata_json=?")
            values.append(json.dumps(metadata, sort_keys=True))
        if not fields:
            return self.get_task(task_id)
        fields.append("updated_at=?")
        values.append(utc_now())
        values.append(task_id)
        self.conn.execute(f"UPDATE tasks SET {', '.join(fields)} WHERE id=?", values)
        self.conn.commit()
        return self.get_task(task_id)

    def get_task(self, task_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        return _task_row(row) if row else None

    def list_tasks(self, session_id: str, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if status and status != "all":
            rows = self.conn.execute(
                "SELECT * FROM tasks WHERE session_id=? AND status=? ORDER BY id LIMIT ?",
                (session_id, status, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM tasks WHERE session_id=? ORDER BY CASE status WHEN 'in_progress' THEN 0 WHEN 'pending' THEN 1 WHEN 'completed' THEN 2 ELSE 3 END, id LIMIT ?",
                (session_id, limit),
            ).fetchall()
        return [_task_row(row) for row in rows]

    def create_delegation(self, session_id: str, prompt: str, tasks: list[dict[str, Any]]) -> int:
        now = utc_now()
        cur = self.conn.execute(
            """
            INSERT INTO delegations(session_id, status, prompt, tasks_json, results_json, artifacts_json, created_at, updated_at)
            VALUES (?, 'running', ?, ?, '[]', '{}', ?, ?)
            """,
            (session_id, prompt, json.dumps(tasks, sort_keys=True), now, now),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def complete_delegation(self, delegation_id: int, status: str, results: list[dict[str, Any]], artifacts: dict[str, Any] | None = None) -> dict[str, Any] | None:
        self.conn.execute(
            "UPDATE delegations SET status=?, results_json=?, artifacts_json=?, updated_at=? WHERE id=?",
            (status, json.dumps(results, sort_keys=True), json.dumps(artifacts or {}, sort_keys=True), utc_now(), delegation_id),
        )
        self.conn.commit()
        return self.get_delegation(delegation_id)

    def get_delegation(self, delegation_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM delegations WHERE id=?", (delegation_id,)).fetchone()
        return _delegation_row(row) if row else None

    def list_delegations(self, session_id: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM delegations WHERE session_id=? ORDER BY id DESC LIMIT ?", (session_id, limit)).fetchall()
        return [_delegation_row(row) for row in rows]

    def create_media_artifact(
        self,
        session_id: str,
        kind: str,
        source_path: str,
        artifact_path: str,
        mime_type: str,
        sha256: str,
        size: int,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO media_artifacts(session_id, kind, source_path, artifact_path, mime_type, sha256, size, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, kind, source_path, artifact_path, mime_type, sha256, size, json.dumps(metadata or {}, sort_keys=True), utc_now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_media_artifacts(self, session_id: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM media_artifacts WHERE session_id=? ORDER BY id DESC LIMIT ?", (session_id, limit)).fetchall()
        return [_media_artifact_row(row) for row in rows]

    def create_approval(self, session_id: str, tool_name: str, args: dict[str, Any], decision: dict[str, Any]) -> int:
        cur = self.conn.execute(
            "INSERT INTO approvals(session_id, tool_name, args_json, decision_json, status, requested_at) VALUES (?, ?, ?, ?, 'pending', ?)",
            (session_id, tool_name, json.dumps(args, sort_keys=True), json.dumps(decision, sort_keys=True), utc_now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_approval(self, approval_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["args"] = json.loads(data.pop("args_json") or "{}")
        data["decision"] = json.loads(data.pop("decision_json") or "{}")
        data["result"] = json.loads(data.pop("result_json") or "null")
        return data

    def list_approvals(self, session_id: str, status: str = "pending") -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM approvals WHERE session_id=? AND status=? ORDER BY id DESC",
            (session_id, status),
        ).fetchall()
        out = []
        for row in rows:
            data = dict(row)
            data["args"] = json.loads(data.pop("args_json") or "{}")
            data["decision"] = json.loads(data.pop("decision_json") or "{}")
            data["result"] = json.loads(data.pop("result_json") or "null")
            out.append(data)
        return out

    def resolve_approval(self, approval_id: int, status: str, resolved_by: str, result: dict[str, Any] | None = None) -> None:
        self.conn.execute(
            "UPDATE approvals SET status=?, resolved_at=?, resolved_by=?, result_json=? WHERE id=?",
            (status, utc_now(), resolved_by, json.dumps(result or {}, sort_keys=True), approval_id),
        )
        self.conn.commit()

    def create_job(self, session_id: str, name: str, schedule: str, prompt: str) -> int:
        next_run = next_run_for_schedule(schedule)
        cur = self.conn.execute(
            "INSERT INTO jobs(session_id, name, schedule, prompt, enabled, created_at, next_run_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (session_id, name, schedule, prompt, utc_now(), next_run),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_jobs(self, session_id: str) -> list[StoredJob]:
        rows = self.conn.execute("SELECT * FROM jobs WHERE session_id=? ORDER BY id", (session_id,)).fetchall()
        return [StoredJob(int(r["id"]), r["name"], r["schedule"], r["prompt"], r["next_run_at"], bool(r["enabled"]), r["last_run_at"]) for r in rows]

    def due_jobs(self, session_id: str, now: str | None = None) -> list[StoredJob]:
        now = now or utc_now()
        rows = self.conn.execute(
            "SELECT * FROM jobs WHERE session_id=? AND enabled=1 AND next_run_at<=? ORDER BY next_run_at, id",
            (session_id, now),
        ).fetchall()
        return [StoredJob(int(r["id"]), r["name"], r["schedule"], r["prompt"], r["next_run_at"], bool(r["enabled"]), r["last_run_at"]) for r in rows]

    def mark_job_run(self, job_id: int, result: str) -> None:
        row = self.conn.execute("SELECT schedule FROM jobs WHERE id=?", (job_id,)).fetchone()
        schedule = row["schedule"] if row else "manual"
        self.conn.execute(
            "UPDATE jobs SET last_run_at=?, next_run_at=?, last_result=? WHERE id=?",
            (utc_now(), next_run_for_schedule(schedule), result[-4000:], job_id),
        )
        self.conn.commit()

    def create_process(
        self,
        session_id: str,
        command: str,
        target: str,
        action_type: str,
        purpose: str,
        stdout_path: str,
        stderr_path: str,
        rc_path: str,
        decision: dict[str, Any],
        approval_id: int | None = None,
    ) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO processes(session_id, command, target, action_type, purpose, pid, status, started_at, stdout_path, stderr_path, rc_path, decision_json, approval_id)
            VALUES (?, ?, ?, ?, ?, NULL, 'starting', ?, ?, ?, ?, ?, ?)
            """,
            (session_id, command, target, action_type, purpose, utc_now(), stdout_path, stderr_path, rc_path, json.dumps(decision, sort_keys=True), approval_id),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def update_process(self, process_id: int, **fields: Any) -> None:
        allowed = {"pid", "status", "ended_at", "exit_code", "stdout_path", "stderr_path", "rc_path"}
        assignments = []
        values = []
        for key, value in fields.items():
            if key in allowed:
                assignments.append(f"{key}=?")
                values.append(value)
        if not assignments:
            return
        values.append(process_id)
        self.conn.execute(f"UPDATE processes SET {', '.join(assignments)} WHERE id=?", values)
        self.conn.commit()

    def get_process(self, process_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM processes WHERE id=?", (process_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["decision"] = json.loads(data.pop("decision_json") or "{}")
        return data

    def list_processes(self, session_id: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM processes WHERE session_id=? ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
        out = []
        for row in rows:
            data = dict(row)
            data["decision"] = json.loads(data.pop("decision_json") or "{}")
            out.append(data)
        return out

    def audit(self, session_id: str | None, event: str, data: dict[str, Any] | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO audit_log(session_id, event, data_json, created_at) VALUES (?, ?, ?, ?)",
            (session_id, event, json.dumps(data or {}, sort_keys=True), utc_now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_audit(self, session_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        if session_id is None:
            rows = self.conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM audit_log WHERE session_id=? ORDER BY id DESC LIMIT ?", (session_id, limit)).fetchall()
        out = []
        for row in rows:
            data = dict(row)
            data["data"] = json.loads(data.pop("data_json") or "{}")
            out.append(data)
        return out


def next_run_for_schedule(schedule: str) -> str:
    schedule = (schedule or "manual").strip().lower()
    now = datetime.now(timezone.utc)
    if schedule in {"manual", "once", "now"}:
        return now.isoformat()
    parts = schedule.replace("every", "").replace(":", " ").split()
    if len(parts) >= 2:
        try:
            amount = int(parts[0])
            unit = parts[1]
            if unit.startswith("s"):
                return (now + timedelta(seconds=amount)).isoformat()
            if unit.startswith("m"):
                return (now + timedelta(minutes=amount)).isoformat()
            if unit.startswith("h"):
                return (now + timedelta(hours=amount)).isoformat()
            if unit.startswith("d"):
                return (now + timedelta(days=amount)).isoformat()
        except ValueError:
            pass
    return (now + timedelta(days=1)).isoformat()


def _message_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "role": row["role"],
        "content": row["content"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "created_at": row["created_at"],
    }


def _task_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "content": row["content"],
        "status": row["status"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _context_node_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "parent_id": row["parent_id"],
        "depth": row["depth"],
        "title": row["title"],
        "summary": row["summary"],
        "sources": json.loads(row["source_json"] or "[]"),
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "created_at": row["created_at"],
    }


def _delegation_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "status": row["status"],
        "prompt": row["prompt"],
        "tasks": json.loads(row["tasks_json"] or "[]"),
        "results": json.loads(row["results_json"] or "[]"),
        "artifacts": json.loads(row["artifacts_json"] or "{}"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _media_artifact_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "kind": row["kind"],
        "source_path": row["source_path"],
        "artifact_path": row["artifact_path"],
        "mime_type": row["mime_type"],
        "sha256": row["sha256"],
        "size": row["size"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "created_at": row["created_at"],
    }


def _fts_query_candidates(query: str) -> list[str]:
    query = query.strip()
    if not query:
        return []
    tokens = re.findall(r"[A-Za-z0-9_./:@-]+", query)
    quoted = " AND ".join(_quote_fts_token(token) for token in tokens) if tokens else _quote_fts_token(query)
    candidates = [query]
    if quoted and quoted != query:
        candidates.append(quoted)
    return candidates


def _quote_fts_token(token: str) -> str:
    return '"' + token.replace('"', '""') + '"'
