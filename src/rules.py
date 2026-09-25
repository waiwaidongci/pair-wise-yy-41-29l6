from __future__ import annotations
from .domain import ConflictError, ValidationError
TITLE='桥梁结构监测与限行决策'; ENTITY='桥梁告警'; ID_PREFIX='BM'
SEVERITIES=['normal', 'watch', 'warning', 'critical']; STATES=['normal', 'warning', 'restricted', 'closed', 'restored']; TRANSITIONS={'normal': ['warning'], 'warning': ['restricted'], 'restricted': ['closed'], 'closed': ['restored'], 'restored': []}; TRANSITION_ROLES={'warning': ['sensor_operator'], 'restricted': ['traffic_authority'], 'closed': ['traffic_authority'], 'restored': ['bridge_engineer']}
CREATE_ROLES=set(['sensor_operator']); RECORD_ROLES=set(['sensor_operator', 'bridge_engineer']); ASSESS_ROLES=set(['sensor_operator', 'bridge_engineer', 'traffic_authority']); NOTICE_ROLES=set(['traffic_authority']); AUDIT_ROLES=set(['bridge_engineer', 'viewer']); VIEW_ROLES=set(['sensor_operator', 'bridge_engineer', 'traffic_authority', 'viewer'])
SEVERITY_WEIGHT={'normal': 1.0, 'watch': 3.0, 'warning': 6.0, 'critical': 9.0}; DEADLINE_HOURS={'normal': 72, 'watch': 24, 'warning': 8, 'critical': 4}; TERMINAL_STATES=set(['restored'])
# 处置评估：封闭 > 限行 > 观察
CRITICAL_SEVERITY='critical'; RESTRICT_RATIO=0.75
DISPOSITIONS=['observe', 'restrict', 'close']; DISPOSITION_LABELS={'observe': '继续观察', 'restrict': '限行', 'close': '封闭'}
DISPOSITION_RANK={'observe': 0, 'restrict': 1, 'close': 2}
NOTICE_DIRECTION={'restricted': 'restrict', 'closed': 'close'}; DIRECTION_TARGET={'restrict': 'restricted', 'close': 'closed'}
def priority_score(severity,quantity=0.0,threshold=1.0,open_records=0):
    if severity not in SEVERITY_WEIGHT: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(0,min(10,int(round(SEVERITY_WEIGHT[severity]+min(4.0,ratio*4.0)+min(3.0,float(open_records))))))
def response_deadline_hours(severity,quantity=0.0,threshold=1.0):
    if severity not in DEADLINE_HOURS: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(1,int(DEADLINE_HOURS[severity]/max(1.0,ratio)))
def escalation_required(severity,quantity=0.0,threshold=1.0):
    return severity==SEVERITIES[-1] or (threshold>0 and quantity>=threshold)
def can_transition(current,target): return target in TRANSITIONS.get(current,[])
def validate_transition(current,target):
    if current not in STATES or target not in STATES: raise ValidationError("未知状态")
    if not can_transition(current,target): raise ConflictError(f"不能从{current}转换到{target}")
def completion_blockers(target,open_records): return ["仍有未关闭事项"] if target in TERMINAL_STATES and open_records>0 else []
def role_for_transition(target): return set(TRANSITION_ROLES.get(target,[]))
def threshold_ratio(quantity,threshold):
    return quantity/threshold if threshold and threshold>0 else (1.0 if quantity>0 else 0.0)
def evaluate_disposition(quantity,threshold,open_records,critical_open):
    """处置评估纯函数：返回建议等级与评估依据。读数达到阈值或存在严重级未关闭记录建议封闭；
    读数超过阈值四分之三或有两项未关闭异常建议限行；其余继续观察。"""
    ratio=threshold_ratio(quantity,threshold)
    reasons=[]; facts={"ratio": round(ratio,4), "threshold_reached": ratio>=1.0,
        "restrict_ratio_reached": ratio>=RESTRICT_RATIO,
        "open_records": int(open_records), "critical_open": int(critical_open)}
    if facts["threshold_reached"]:
        reasons.append(f"监测读数{quantity:g}达到阈值{threshold:g}（比值{facts['ratio']:g}），建议封闭")
    if critical_open>0:
        reasons.append(f"存在{critical_open}项严重级（{CRITICAL_SEVERITY}）未关闭异常记录，建议封闭")
    if facts["threshold_reached"] or critical_open>0:
        disposition='close'
    else:
        if facts["restrict_ratio_reached"]:
            reasons.append(f"监测读数{quantity:g}达到阈值四分之三（比值{facts['ratio']:g}≥{RESTRICT_RATIO:g}），建议限行")
        if open_records>=2:
            reasons.append(f"存在{open_records}项未关闭异常记录（≥2），建议限行")
        disposition='restrict' if (facts["restrict_ratio_reached"] or open_records>=2) else 'observe'
    if disposition=='observe':
        reasons.append("监测读数未达到限行线且未关闭异常少于两项，继续观察")
    return {"disposition": disposition, "recommendation": DISPOSITION_LABELS[disposition],
            "reasons": reasons, "basis": facts}
def disposition_supports_target(disposition,target):
    """评估建议强度是否足以支撑确认目标（封闭建议可用于限行确认，反之不可）。"""
    direction=NOTICE_DIRECTION.get(target)
    if direction is None or disposition not in DISPOSITION_RANK: return False
    return DISPOSITION_RANK[disposition]>=DISPOSITION_RANK[direction]
