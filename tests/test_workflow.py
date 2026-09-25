import tempfile, unittest
from pathlib import Path
from src.repository import Repository
from src.service import Service
from src.rules import STATES
class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.repo=Repository(str(Path(self.tmp.name)/"test.db")); self.service=Service(self.repo)
    def tearDown(self): self.repo.close(); self.tmp.cleanup()
    def _to_warning(self,item):
        return self.service.transition(item["id"],STATES[1],item["version"],"sensor",'sensor_operator')
    def _assess_and_notice(self,item,direction):
        result=self.service.assess(item["id"],"duty",'bridge_engineer')
        notice=self.service.create_notice(item["id"],{"direction":direction,"title":direction+" notice","detail":"traffic notice"},"ta",'traffic_authority')
        return result["assessment"]["id"],notice
    def test_complete_workflow_and_audit(self):
        item=self.service.create_item({"title":"workflow item","description":"complete business flow","severity":'warning',"quantity":12,"threshold":6,"external_ref":"WF-1"},"creator",'sensor_operator')
        self.assertEqual(item["status"],STATES[0])
        item=self._to_warning(item)
        self.service.add_record(item["id"],{"kind":"evidence","detail":"evidence registered","status":"closed","external_ref":"EV-1"},"recorder",'sensor_operator')
        item=self.service.get_item(item["id"],"viewer")
        aid,_=self._assess_and_notice(item,'restrict')
        item=self.service.transition(item["id"],'restricted',item["version"],"ta",'traffic_authority',aid)
        aid,_=self._assess_and_notice(item,'close')
        item=self.service.transition(item["id"],'closed',item["version"],"ta",'traffic_authority',aid)
        current=self.service.transition(item["id"],'restored',item["version"],"reviewer",'bridge_engineer')
        self.assertEqual(current["status"],STATES[-1])
        self.assertEqual(len(self.service.list_records(current["id"],"viewer")),1)
        notices=self.service.list_notices(current["id"],"viewer")
        self.assertEqual({n["status"] for n in notices},{'revoked'})
        events=self.service.audit("viewer",current["id"])
        actions={e["action"] for e in events}
        for action in ("assess","notice_create","confirm","notice_revoke"):
            self.assertIn(action,actions)
        self.assertGreaterEqual(len(events),len(STATES)+1); self.assertTrue(self.repo.verify_audit_chain())
if __name__=="__main__": unittest.main()
