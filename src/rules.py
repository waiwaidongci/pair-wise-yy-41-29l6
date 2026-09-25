from __future__ import annotations
from .domain import ConflictError, ValidationError
TITLE='桥梁结构监测与限行决策'; ENTITY='桥梁告警'; ID_PREFIX='BM'
SEVERITIES=['normal', 'watch', 'warning', 'critical']; STATES=['normal', 'warning', 'restricted', 'closed', 'restored']; TRANSITIONS={'normal': ['warning'], 'warning': ['restricted'], 'restricted': ['closed'], 'closed': ['restored'], 'restored': []}; TRANSITION_ROLES={'warning': ['sensor_operator'], 'restricted': ['bridge_engineer'], 'closed': ['traffic_authority'], 'restored': ['bridge_engineer']}
CREATE_ROLES=set(['sensor_operator']); RECORD_ROLES=set(['sensor_operator', 'bridge_engineer']); AUDIT_ROLES=set(['bridge_engineer', 'viewer']); VIEW_ROLES=set(['sensor_operator', 'bridge_engineer', 'traffic_authority', 'viewer'])
SEVERITY_WEIGHT={'normal': 1.0, 'watch': 3.0, 'warning': 6.0, 'critical': 9.0}; DEADLINE_HOURS={'normal': 72, 'watch': 24, 'warning': 8, 'critical': 4}; TERMINAL_STATES=set(['restored'])
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
NOTICE_DIRECTIONS=['restricted', 'closed']; CRITICAL_RECORD_KIND=SEVERITIES[-1]; RESTRICT_RATIO=0.75
NOTICE_ROLES=set(['traffic_authority']); CONFIRM_ROLES=set(['traffic_authority']); RESTORE_ROLES=set(['bridge_engineer'])
CONFIRM_SOURCES={'restricted': set(['normal', 'warning']), 'closed': set(['normal', 'warning', 'restricted'])}; RESTORE_SOURCES=set(['restricted', 'closed'])
def assess_disposition(quantity,threshold,open_records=0,critical_open_records=0):
    ratio=quantity/threshold if threshold>0 else 1.0
    reasons=[]
    if ratio>=1.0: reasons.append('读数达到阈值')
    if critical_open_records>0: reasons.append('存在严重级未关闭记录')
    if reasons: return {'recommendation': 'closed', 'reasons': reasons, 'ratio': round(ratio,4)}
    if ratio>RESTRICT_RATIO: reasons.append('读数超过阈值四分之三')
    if open_records>=2: reasons.append('存在两项及以上未关闭异常')
    if reasons: return {'recommendation': 'restricted', 'reasons': reasons, 'ratio': round(ratio,4)}
    return {'recommendation': 'observe', 'reasons': ['继续观察'], 'ratio': round(ratio,4)}
def validate_confirm(current,target):
    if target not in NOTICE_DIRECTIONS: raise ValidationError("未知处置方向")
    if current not in CONFIRM_SOURCES[target]: raise ConflictError(f"不能从{current}确认{target}")
def validate_restore(current):
    if current not in RESTORE_SOURCES: raise ConflictError(f"不能从{current}恢复")
