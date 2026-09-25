from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .audit import utc_now
from .domain import (ConflictError, NotFoundError, ValidationError, ensure_role,
                     normalize_severity, require_number, require_text)
from .repository import Repository
from .rules import (ASSESS_ROLES, AUDIT_ROLES, CREATE_ROLES, ENTITY,
                    NOTICE_DIRECTION, NOTICE_ROLES, RECORD_ROLES, SEVERITIES,
                    VIEW_ROLES, DISPOSITION_LABELS, completion_blockers,
                    disposition_supports_target, escalation_required,
                    evaluate_disposition, priority_score, response_deadline_hours,
                    role_for_transition, validate_transition)


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
        severity = payload.get("severity", "normal")
        if severity not in SEVERITIES:
            raise ValidationError("severity不在允许范围内")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValidationError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, severity, status,
                                            external_ref, actor)
        item = self.repository.get_item(item_id)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "severity": severity,
            "status": status, "alert_version": item["version"],
        })
        return record

    def close_record(self, item_id: int, record_id: int, actor: str,
                     role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        record = self.repository.close_record(item_id, record_id, actor)
        if record is None:
            raise NotFoundError("异常记录不存在")
        item = self.repository.get_item(item_id)
        self.repository.append_audit("record_close", ENTITY, item_id, actor, {
            "record_id": record_id, "alert_version": item["version"],
        })
        return record

    def assess(self, item_id: int, actor: str, role: str) -> Dict[str, Any]:
        """处置评估：基于当前读数、阈值与未关闭异常生成限行/封闭/观察建议，
        结果绑定告警版本。"""
        ensure_role(role, ASSESS_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        counts = self.repository.open_record_counts(item_id)
        result = evaluate_disposition(item["quantity"], item["threshold"],
                                      counts["open"], counts["critical_open"])
        basis = dict(result["basis"])
        basis.update({"quantity": item["quantity"], "threshold": item["threshold"],
                      "item_status": item["status"]})
        assessment = self.repository.create_assessment(
            item_id, item["version"], result["disposition"], basis, actor)
        self.repository.append_audit("assess", ENTITY, item_id, actor, {
            "assessment_id": assessment["id"], "alert_version": item["version"],
            "disposition": result["disposition"],
            "recommendation": result["recommendation"],
            "reasons": result["reasons"], "basis": basis,
        })
        return {"assessment": assessment, "alert_version": item["version"],
                "disposition": result["disposition"],
                "recommendation": result["recommendation"],
                "reasons": result["reasons"], "basis": basis}

    def list_assessments(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_assessments(item_id)

    def create_notice(self, item_id: int, payload: Dict[str, Any], actor: str,
                      role: str) -> Dict[str, Any]:
        """新建方向为restrict（限行）或close（封闭）且当前有效的交通通告。"""
        ensure_role(role, NOTICE_ROLES)
        actor = require_text(actor, "actor", 100)
        self.repository.get_item(item_id)
        direction = payload.get("direction")
        if direction not in ("restrict", "close"):
            raise ValidationError("direction必须是restrict或close")
        title = require_text(payload.get("title"), "title", 200)
        detail = require_text(payload.get("detail"), "detail")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        effective_from_dt = self._parse_dt(
            payload.get("effective_from", now.isoformat()), "effective_from")
        expires_at_dt = None
        if payload.get("expires_at") is not None:
            expires_at_dt = self._parse_dt(payload["expires_at"], "expires_at")
            if expires_at_dt <= effective_from_dt:
                raise ValidationError("expires_at必须晚于effective_from")
        if expires_at_dt is not None and expires_at_dt <= now:
            raise ValidationError("通告截止时间必须晚于当前时间")
        if effective_from_dt > now:
            raise ValidationError("通告必须当前有效，effective_from不能晚于当前时间")
        effective_from = self._fmt_dt(effective_from_dt)
        expires_at = self._fmt_dt(expires_at_dt) if expires_at_dt else None
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        notice = self.repository.create_notice(
            item_id, direction, title, detail, effective_from, expires_at,
            external_ref, actor)
        self.repository.append_audit("notice_create", ENTITY, item_id, actor, {
            "notice_id": notice["id"], "direction": direction, "title": title,
            "effective_from": effective_from, "expires_at": expires_at,
        })
        return notice

    def list_notices(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_notices(item_id)

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str,
                   assessment_id: Optional[int] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or isinstance(expected_version, bool) \
                or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")
        direction = NOTICE_DIRECTION.get(target)
        if direction is not None:
            # 路政确认限行/封闭：评估版本校验 + 方向一致且当前有效的交通通告
            self._check_confirmation(item_id, item, assessment_id, target, actor)
        blockers = completion_blockers(
            target, self.repository.open_record_counts(item_id)["open"])
        if blockers:
            raise ConflictError("恢复前必须关闭全部异常记录：" + "；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        if direction is not None:
            self.repository.mark_assessment(item_id, assessment_id, "confirmed")
        revoked = []
        if target == "restored":
            # 恢复：撤销原限行或封闭通告
            revoked = self.repository.revoke_active_notices(item_id, actor, utc_now())
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        if direction is not None:
            self.repository.append_audit("confirm", ENTITY, item_id, actor, {
                "assessment_id": assessment_id, "alert_version": item["version"],
                "direction": direction, "target": target,
                "recommendation": DISPOSITION_LABELS[direction],
            })
        for notice in revoked:
            self.repository.append_audit("notice_revoke", ENTITY, item_id, actor, {
                "notice_id": notice["id"], "direction": notice["direction"],
                "reason": "告警恢复，撤销原限行或封闭通告",
            })
        return self.enrich(updated)

    def _check_confirmation(self, item_id: int, item: Dict[str, Any],
                            assessment_id: Optional[int], target: str,
                            actor: str) -> None:
        if assessment_id is None:
            raise ValidationError("确认限行或封闭必须提交assessment_id")
        if not isinstance(assessment_id, int) or isinstance(assessment_id, bool) \
                or assessment_id < 1:
            raise ValidationError("assessment_id必须是正整数")
        assessment = self.repository.get_assessment(item_id, assessment_id)
        direction = NOTICE_DIRECTION[target]
        if assessment["alert_version"] != item["version"]:
            # 告警版本已变化：原建议失效，不能按旧读数放行
            self.repository.mark_assessment(item_id, assessment_id, "invalid")
            self.repository.append_audit("assess_invalid", ENTITY, item_id, actor, {
                "assessment_id": assessment_id,
                "assessment_version": assessment["alert_version"],
                "current_version": item["version"],
                "target": target, "reason": "告警版本已变化，原处置建议失效",
            })
            raise ConflictError(
                f"告警版本已变化（评估基于版本{assessment['alert_version']}，"
                f"当前版本{item['version']}），原建议失效，请重新评估")
        if assessment["status"] != "active":
            raise ConflictError(f"处置评估已{assessment['status']}，请重新评估")
        if not disposition_supports_target(assessment["disposition"], target):
            raise ConflictError(
                f"评估建议为{DISPOSITION_LABELS[assessment['disposition']]}，"
                f"不足以确认{DISPOSITION_LABELS[direction]}，请重新评估")
        notice = self.repository.find_active_notice(item_id, direction, utc_now())
        if notice is None:
            raise ConflictError(
                f"确认前必须先新建方向为{direction}且当前有效的交通通告")

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def _parse_dt(value: Any, field: str) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        else:
            text = require_text(value, field, 50)
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValidationError(f"{field}必须是ISO时间") from exc
        if parsed.tzinfo is None:
            raise ValidationError(f"{field}必须带时区")
        return parsed.astimezone(timezone.utc).replace(microsecond=0)

    @staticmethod
    def _fmt_dt(parsed: datetime) -> str:
        return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()

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
