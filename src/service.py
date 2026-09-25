from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, ValidationError, ensure_role,
                     normalize_severity, require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CONFIRM_ROLES, CREATE_ROLES, ENTITY,
                    NOTICE_DIRECTIONS, NOTICE_ROLES, RECORD_ROLES, RESTORE_ROLES,
                    TERMINAL_STATES, TITLE, VIEW_ROLES, assess_disposition,
                    completion_blockers, escalation_required, priority_score,
                    response_deadline_hours, role_for_transition, validate_confirm,
                    validate_restore, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        revoked = []
        if target in TERMINAL_STATES:
            revoked = self._revoke_active_notices(item_id, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
            "revoked_notices": revoked,
        })
        return self.enrich(updated)

    def assess(self, item_id: int, actor: str, role: str) -> Dict[str, Any]:
        self._view(role)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        open_records = self.repository.open_record_count(item_id)
        critical_open = self.repository.open_critical_record_count(item_id)
        result = assess_disposition(item["quantity"], item["threshold"],
                                    open_records, critical_open)
        basis = {"alert_version": item["version"], "quantity": item["quantity"],
                 "threshold": item["threshold"], "ratio": result["ratio"],
                 "open_records": open_records, "critical_open_records": critical_open,
                 "recommendation": result["recommendation"], "reasons": result["reasons"]}
        self.repository.append_audit("assess", ENTITY, item_id, actor, basis)
        return dict(basis, item_id=item_id, status=item["status"])

    def create_notice(self, item_id: int, payload: Dict[str, Any], actor: str,
                      role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_ROLES)
        actor = require_text(actor, "actor", 100)
        direction = payload.get("direction")
        if direction not in NOTICE_DIRECTIONS:
            raise ValidationError("direction必须是restricted或closed")
        detail = require_text(payload.get("detail"), "detail")
        item = self.repository.get_item(item_id)
        if item["status"] in TERMINAL_STATES:
            raise ConflictError("告警已恢复，不能新建通告")
        notice = self.repository.create_notice(item_id, direction, detail, actor)
        self.repository.append_audit("notice_create", ENTITY, item_id, actor, {
            "notice_id": notice["id"], "direction": direction,
        })
        return notice

    def confirm(self, item_id: int, payload: Dict[str, Any], actor: str,
                role: str) -> Dict[str, Any]:
        ensure_role(role, CONFIRM_ROLES)
        actor = require_text(actor, "actor", 100)
        action = payload.get("action")
        if action not in NOTICE_DIRECTIONS:
            raise ValidationError("action必须是restricted或closed")
        notice_id = payload.get("notice_id")
        if not isinstance(notice_id, int) or notice_id < 1:
            raise ValueError("notice_id必须是正整数")
        expected_version = payload.get("expected_version")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        item = self.repository.get_item(item_id)
        validate_confirm(item["status"], action)
        notice = self.repository.get_notice(notice_id)
        if notice["item_id"] != item_id:
            raise ValidationError("通告不属于该告警")
        if notice["direction"] != action:
            raise ConflictError("通告方向与确认动作不一致")
        if notice["status"] != "active":
            raise ConflictError("通告已撤销，需重新发布")
        if item["version"] != expected_version:
            self.repository.append_audit("invalidate", ENTITY, item_id, actor, {
                "action": action, "expected_version": expected_version,
                "current_version": item["version"],
                "reason": "告警版本已变化，原建议失效",
            })
            raise ConflictError("告警版本已变化，原建议失效，请重新评估")
        updated = self.repository.transition_item(item_id, action, expected_version, actor)
        self.repository.append_audit("confirm", ENTITY, item_id, actor, {
            "from": item["status"], "to": action, "notice_id": notice_id,
            "alert_version": expected_version,
        })
        return self.enrich(updated)

    def restore(self, item_id: int, payload: Dict[str, Any], actor: str,
                role: str) -> Dict[str, Any]:
        ensure_role(role, RESTORE_ROLES)
        actor = require_text(actor, "actor", 100)
        expected_version = payload.get("expected_version")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        item = self.repository.get_item(item_id)
        validate_restore(item["status"])
        blockers = completion_blockers("restored", self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, "restored", expected_version, actor)
        revoked = self._revoke_active_notices(item_id, actor)
        self.repository.append_audit("restore", ENTITY, item_id, actor, {
            "from": item["status"], "to": "restored", "revoked_notices": revoked,
        })
        return self.enrich(updated)

    def _revoke_active_notices(self, item_id: int, actor: str) -> list:
        revoked = []
        for notice in self.repository.list_active_notices(item_id):
            self.repository.revoke_notice(notice["id"], actor)
            self.repository.append_audit("notice_revoke", ENTITY, item_id, actor, {
                "notice_id": notice["id"], "direction": notice["direction"],
            })
            revoked.append(notice["id"])
        return revoked

    def close_record(self, item_id: int, record_id: int, actor: str,
                     role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        record = self.repository.close_record(item_id, record_id, actor)
        self.repository.append_audit("record_close", ENTITY, item_id, actor, {
            "record_id": record["id"],
        })
        return record

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def list_notices(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_notices(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
