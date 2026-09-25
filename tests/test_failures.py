import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES
class FailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.repo=Repository(str(Path(self.tmp.name)/"test.db")); self.service=Service(self.repo)
        self.item=self.service.create_item({"title":"failure item","description":"failure scenarios","severity":'warning',"quantity":5,"threshold":10,"external_ref":"FAIL-1"},"creator",'sensor_operator')
        self.item=self.service.transition(self.item["id"],STATES[1],self.item["version"],"sensor",'sensor_operator')
    def tearDown(self): self.repo.close(); self.tmp.cleanup()
    def _restrict_prereq(self,item=None,direction='restrict'):
        item=item or self.item
        result=self.service.assess(item["id"],"duty",'bridge_engineer')
        self.service.create_notice(item["id"],{"direction":direction,"title":direction,"detail":"d"},"ta",'traffic_authority')
        return result["assessment"]["id"]
    def _make_restrict_situation(self):
        # 两项未关闭异常 => 限行
        self.service.add_record(self.item["id"],{"kind":"anomaly","detail":"open one","status":"open","external_ref":"A-1"},"recorder",'sensor_operator')
        self.service.add_record(self.item["id"],{"kind":"anomaly","detail":"open two","status":"open","external_ref":"A-2"},"recorder",'sensor_operator')
    def test_permission_version_duplicate_and_invariant(self):
        with self.assertRaises(PermissionDenied): self.service.transition(self.item["id"],'restricted',self.item["version"],"attacker","viewer",1)
        self._make_restrict_situation()
        result=self.service.assess(self.item["id"],"duty",'bridge_engineer')
        self.assertEqual(result["disposition"],'restrict')
        current=self.service.get_item(self.item["id"],"viewer")
        with self.assertRaises(ConflictError): self.service.transition(current["id"],'restricted',99,"ta",'traffic_authority',result["assessment"]["id"])
        payload={"kind":"action","detail":"same reference","status":"open","external_ref":"DUP-1"}
        self.service.add_record(current["id"],payload,"recorder",'sensor_operator')
        with self.assertRaises(ConflictError): self.service.add_record(current["id"],payload,"recorder",'sensor_operator')
        self._restrict_prereq(current)
        current=self.service.get_item(current["id"],"viewer")
        restricted=self.service.transition(current["id"],'restricted',current["version"],"ta",'traffic_authority',self._latest_assessment(current))
        # 封闭前：严重级异常使读数建议升级为封闭
        self.service.add_record(restricted["id"],{"kind":"anomaly","detail":"critical crack","severity":"critical","status":"open","external_ref":"C-1"},"recorder",'bridge_engineer')
        restricted=self.service.get_item(restricted["id"],"viewer")
        aid=self._restrict_prereq(restricted,'close')
        closed=self.service.transition(restricted["id"],'closed',restricted["version"],"ta",'traffic_authority',aid)
        # 仍有未关闭异常，不能恢复
        with self.assertRaises(ConflictError): self.service.transition(closed["id"],'restored',closed["version"],"reviewer",'bridge_engineer')
    def _latest_assessment(self,item):
        return self.service.list_assessments(item["id"],"viewer")[-1]["id"]
    def test_confirmation_requires_notice(self):
        self._make_restrict_situation()
        current=self.service.get_item(self.item["id"],"viewer")
        result=self.service.assess(current["id"],"duty",'bridge_engineer')
        self.assertEqual(result["disposition"],'restrict')
        # 没有限行通告不能确认
        with self.assertRaises(ConflictError):
            self.service.transition(current["id"],'restricted',current["version"],"ta",'traffic_authority',result["assessment"]["id"])
        # 方向不一致（只有封闭通告）不能确认限行
        self.service.create_notice(current["id"],{"direction":'close',"title":"c","detail":"d"},"ta",'traffic_authority')
        with self.assertRaises(ConflictError):
            self.service.transition(current["id"],'restricted',current["version"],"ta",'traffic_authority',result["assessment"]["id"])
        # 缺少assessment_id也不能确认
        with self.assertRaises(ValidationError):
            self.service.transition(current["id"],'restricted',current["version"],"ta",'traffic_authority')
    def test_stale_assessment_invalid_after_version_change(self):
        self._make_restrict_situation()
        current=self.service.get_item(self.item["id"],"viewer")
        result=self.service.assess(current["id"],"duty",'bridge_engineer')
        old_version=result["alert_version"]
        self.service.create_notice(current["id"],{"direction":'restrict',"title":"r","detail":"d"},"ta",'traffic_authority')
        # 新增异常推进告警版本，旧建议失效
        self.service.add_record(current["id"],{"kind":"anomaly","detail":"new reading after assessment","status":"open","external_ref":"A-3"},"recorder",'sensor_operator')
        current=self.service.get_item(current["id"],"viewer")
        self.assertGreater(current["version"],old_version)
        with self.assertRaises(ConflictError):
            self.service.transition(current["id"],'restricted',current["version"],"ta",'traffic_authority',result["assessment"]["id"])
        assessment=self.service.list_assessments(self.item["id"],"viewer")[0]
        self.assertEqual(assessment["status"],'invalid')
        events=[e for e in self.service.audit("viewer",self.item["id"]) if e["action"]=="assess_invalid"]
        self.assertEqual(len(events),1)
    def test_observe_assessment_cannot_restrict(self):
        # 读数低、无未关闭异常 => 观察，不能用于限行确认
        result=self.service.assess(self.item["id"],"duty",'bridge_engineer')
        self.assertEqual(result["disposition"],'observe')
        self.service.create_notice(self.item["id"],{"direction":'restrict',"title":"r","detail":"d"},"ta",'traffic_authority')
        with self.assertRaises(ConflictError):
            self.service.transition(self.item["id"],'restricted',self.item["version"],"ta",'traffic_authority',result["assessment"]["id"])
    def test_restrict_notice_does_not_support_close(self):
        self._make_restrict_situation()
        current=self.service.get_item(self.item["id"],"viewer")
        aid=self._restrict_prereq(current)  # 限行建议+限行通告
        current=self.service.get_item(current["id"],"viewer")
        restricted=self.service.transition(current["id"],'restricted',current["version"],"ta",'traffic_authority',aid)
        # 限行状态下没有新的封闭依据，限行建议不能用于封闭
        with self.assertRaises(ConflictError):
            self.service.transition(restricted["id"],'closed',restricted["version"],"ta",'traffic_authority',aid)
    def test_only_traffic_authority_creates_notice(self):
        with self.assertRaises(PermissionDenied):
            self.service.create_notice(self.item["id"],{"direction":'restrict',"title":"r","detail":"d"},"eng",'bridge_engineer')
if __name__=="__main__": unittest.main()
