from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'normal',
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS notices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    direction TEXT NOT NULL CHECK(direction IN ('restrict','close')),
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','revoked')),
                    effective_from TEXT NOT NULL,
                    expires_at TEXT,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked_at TEXT,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    alert_version INTEGER NOT NULL,
                    disposition TEXT NOT NULL
                        CHECK(disposition IN ('observe','restrict','close')),
                    basis TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','superseded','invalid','confirmed')),
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
            """)
            self._migrate()

    def _migrate(self) -> None:
        cols = [r["name"] for r in self.conn.execute("PRAGMA table_info(records)")]
        if "severity" not in cols:
            self.conn.execute(
                "ALTER TABLE records ADD COLUMN severity TEXT NOT NULL DEFAULT 'normal'")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, severity: str,
                   status: str, external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, severity, status,
                       external_ref, created_by, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, severity, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
                # 异常记录变化推进告警版本，使按旧读数作出的处置建议失效
                self.conn.execute(
                    "UPDATE items SET version=version+1, updated_at=? WHERE id=?",
                    (now, item_id))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def close_record(self, item_id: int, record_id: int, actor: str) -> Optional[Dict[str, Any]]:
        now = utc_now()
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT * FROM records WHERE id=? AND item_id=?", (record_id, item_id)
            ).fetchone()
            if row is None:
                return None
            record = dict(row)
            if record["status"] != "closed":
                self.conn.execute(
                    "UPDATE records SET status='closed' WHERE id=?", (record_id,))
                record["status"] = "closed"
                # 关闭异常同样改变告警状态，推进版本
                self.conn.execute(
                    "UPDATE items SET version=version+1, updated_at=? WHERE id=?",
                    (now, item_id))
        return record

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_counts(self, item_id: int) -> Dict[str, int]:
        with self._lock:
            row = self.conn.execute(
                """SELECT
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open_n,
                   SUM(CASE WHEN status='open' AND severity='critical' THEN 1 ELSE 0 END)
                       AS critical_n
                   FROM records WHERE item_id=?""",
                (item_id,),
            ).fetchone()
        return {"open": int(row["open_n"] or 0),
                "critical_open": int(row["critical_n"] or 0)}

    def create_notice(self, item_id: int, direction: str, title: str, detail: str,
                      effective_from: str, expires_at: Optional[str],
                      external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO notices(item_id, direction, title, detail, status,
                       effective_from, expires_at, external_ref, created_by, created_at)
                       VALUES(?,?,?,?, 'active',?,?,?,?,?)""",
                    (item_id, direction, title, detail, effective_from, expires_at,
                     external_ref, actor, now),
                )
                notice_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("通告唯一标识已存在") from exc
        return self.get_notice(item_id, notice_id)

    def get_notice(self, item_id: int, notice_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM notices WHERE id=? AND item_id=?", (notice_id, item_id)
            ).fetchone()
        if row is None:
            raise NotFoundError("交通通告不存在")
        return dict(row)

    def list_notices(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM notices WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def find_active_notice(self, item_id: int, direction: str, at: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                """SELECT * FROM notices
                   WHERE item_id=? AND direction=? AND status='active'
                     AND effective_from<=? AND (expires_at IS NULL OR expires_at>?)
                   ORDER BY id DESC LIMIT 1""",
                (item_id, direction, at, at),
            ).fetchone()
        return dict(row) if row else None

    def revoke_active_notices(self, item_id: int, actor: str, at: str) -> List[Dict[str, Any]]:
        with self._lock, self.conn:
            rows = self.conn.execute(
                "SELECT * FROM notices WHERE item_id=? AND status='active' ORDER BY id",
                (item_id,),
            ).fetchall()
            notices = [dict(row) for row in rows]
            if notices:
                self.conn.execute(
                    "UPDATE notices SET status='revoked', revoked_at=? WHERE item_id=? AND status='active'",
                    (at, item_id))
                for notice in notices:
                    notice["status"] = "revoked"
                    notice["revoked_at"] = at
        return notices

    def create_assessment(self, item_id: int, alert_version: int, disposition: str,
                          basis: dict, actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE assessments SET status='superseded' WHERE item_id=? AND status='active'",
                (item_id,))
            cur = self.conn.execute(
                """INSERT INTO assessments(item_id, alert_version, disposition, basis,
                   status, created_by, created_at) VALUES(?,?,?,?,'active',?,?)""",
                (item_id, alert_version, disposition,
                 json.dumps(basis, ensure_ascii=False, sort_keys=True), actor, now),
            )
            assessment_id = int(cur.lastrowid)
        return self.get_assessment(item_id, assessment_id)

    def get_assessment(self, item_id: int, assessment_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM assessments WHERE id=? AND item_id=?",
                (assessment_id, item_id),
            ).fetchone()
        if row is None:
            raise NotFoundError("处置评估不存在")
        result = dict(row)
        result["basis"] = json.loads(result["basis"])
        return result

    def list_assessments(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM assessments WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["basis"] = json.loads(item["basis"])
            result.append(item)
        return result

    def mark_assessment(self, item_id: int, assessment_id: int, status: str) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE assessments SET status=? WHERE id=? AND item_id=?",
                (status, assessment_id, item_id))

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()
