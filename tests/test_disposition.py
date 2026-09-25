import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError, NotFoundError, PermissionDenied
from src.repository import Repository
from src.service import Service
class DispositionTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.repo=Repository(str(Path(self.tmp.name)/"test.db")); self.service=Service(self.repo)
    def tearDown(self): self.repo.close(); self.tmp.cleanup()
    def _item(self,quantity=5,threshold=10):
        return self.service.create_item({"title":"bridge alert","description":"disposition flow","severity":"warning","quantity":quantity,"threshold":threshold},"creator","sensor_operator")
    def test_assessment_recommendations_and_version(self):
        closed_item=self._item(quantity=10,threshold=10)
        a=self.service.assess(closed_item["id"],"duty","viewer")
        self.assertEqual(a["recommendation"],"closed"); self.assertEqual(a["alert_version"],closed_item["version"]); self.assertIn("读数达到阈值",a["reasons"])
        restricted_item=self._item(quantity=8,threshold=10)
        self.assertEqual(self.service.assess(restricted_item["id"],"duty","viewer")["recommendation"],"restricted")
        edge_item=self._item(quantity=7.5,threshold=10)
        self.assertEqual(self.service.assess(edge_item["id"],"duty","viewer")["recommendation"],"observe")
        observe_item=self._item(quantity=5,threshold=10)
        self.assertEqual(self.service.assess(observe_item["id"],"duty","viewer")["recommendation"],"observe")
        self.service.add_record(observe_item["id"],{"kind":"critical","detail":"severe crack","status":"open"},"rec","sensor_operator")
        critical=self.service.assess(observe_item["id"],"duty","viewer")
        self.assertEqual(critical["recommendation"],"closed"); self.assertEqual(critical["critical_open_records"],1)
        two_open=self._item(quantity=5,threshold=10)
        self.service.add_record(two_open["id"],{"kind":"crack","detail":"one","status":"open"},"rec","sensor_operator")
        self.service.add_record(two_open["id"],{"kind":"tilt","detail":"two","status":"open"},"rec","sensor_operator")
        self.assertEqual(self.service.assess(two_open["id"],"duty","viewer")["recommendation"],"restricted")
        events=self.service.audit("viewer",closed_item["id"])
        assess_events=[e for e in events if e["action"]=="assess"]
        self.assertTrue(assess_events); self.assertEqual(assess_events[0]["detail"]["alert_version"],closed_item["version"])
    def test_confirm_requires_matching_active_notice(self):
        item=self._item(quantity=12,threshold=10)
        item=self.service.transition(item["id"],"warning",item["version"],"op","sensor_operator")
        notice=self.service.create_notice(item["id"],{"direction":"closed","detail":"封闭通告"},"auth","traffic_authority")
        with self.assertRaises(PermissionDenied): self.service.create_notice(item["id"],{"direction":"closed","detail":"越权通告"},"op","sensor_operator")
        with self.assertRaises(NotFoundError): self.service.confirm(item["id"],{"action":"closed","notice_id":999,"expected_version":item["version"]},"auth","traffic_authority")
        with self.assertRaises(ConflictError): self.service.confirm(item["id"],{"action":"restricted","notice_id":notice["id"],"expected_version":item["version"]},"auth","traffic_authority")
        with self.assertRaises(PermissionDenied): self.service.confirm(item["id"],{"action":"closed","notice_id":notice["id"],"expected_version":item["version"]},"eng","bridge_engineer")
        updated=self.service.confirm(item["id"],{"action":"closed","notice_id":notice["id"],"expected_version":item["version"]},"auth","traffic_authority")
        self.assertEqual(updated["status"],"closed")
        actions=[e["action"] for e in self.service.audit("viewer",item["id"])]
        self.assertIn("notice_create",actions); self.assertIn("confirm",actions)
    def test_stale_version_invalidates_recommendation(self):
        item=self._item(quantity=12,threshold=10)
        notice=self.service.create_notice(item["id"],{"direction":"closed","detail":"封闭通告"},"auth","traffic_authority")
        assessment=self.service.assess(item["id"],"duty","viewer")
        self.service.add_record(item["id"],{"kind":"crack","detail":"new anomaly","status":"open"},"rec","sensor_operator")
        with self.assertRaises(ConflictError) as ctx:
            self.service.confirm(item["id"],{"action":"closed","notice_id":notice["id"],"expected_version":assessment["alert_version"]},"auth","traffic_authority")
        self.assertIn("重新评估",str(ctx.exception))
        self.assertEqual(self.service.get_item(item["id"],"viewer")["status"],"normal")
        events=self.service.audit("viewer",item["id"])
        invalidate=[e for e in events if e["action"]=="invalidate"]
        self.assertTrue(invalidate); self.assertEqual(invalidate[0]["detail"]["expected_version"],assessment["alert_version"])
        fresh=self.service.get_item(item["id"],"viewer")
        updated=self.service.confirm(item["id"],{"action":"closed","notice_id":notice["id"],"expected_version":fresh["version"]},"auth","traffic_authority")
        self.assertEqual(updated["status"],"closed")
    def test_restore_waits_for_records_and_revokes_notice(self):
        item=self._item(quantity=12,threshold=10)
        record=self.service.add_record(item["id"],{"kind":"crack","detail":"anomaly","status":"open"},"rec","sensor_operator")
        item=self.service.get_item(item["id"],"viewer")
        notice=self.service.create_notice(item["id"],{"direction":"closed","detail":"封闭通告"},"auth","traffic_authority")
        closed=self.service.confirm(item["id"],{"action":"closed","notice_id":notice["id"],"expected_version":item["version"]},"auth","traffic_authority")
        with self.assertRaises(ConflictError): self.service.restore(item["id"],{"expected_version":closed["version"]},"eng","bridge_engineer")
        with self.assertRaises(PermissionDenied): self.service.close_record(item["id"],record["id"],"auth","traffic_authority")
        self.service.close_record(item["id"],record["id"],"eng","bridge_engineer")
        with self.assertRaises(ConflictError): self.service.close_record(item["id"],record["id"],"eng","bridge_engineer")
        closed=self.service.get_item(item["id"],"viewer")
        restored=self.service.restore(item["id"],{"expected_version":closed["version"]},"eng","bridge_engineer")
        self.assertEqual(restored["status"],"restored")
        notices=self.service.list_notices(item["id"],"viewer")
        self.assertEqual(len(notices),1); self.assertEqual(notices[0]["status"],"revoked"); self.assertEqual(notices[0]["revoked_by"],"eng")
        actions=[e["action"] for e in self.service.audit("viewer",item["id"])]
        for expected in ("notice_create","confirm","record_close","notice_revoke","restore"): self.assertIn(expected,actions)
        self.assertTrue(self.repo.verify_audit_chain())
if __name__=="__main__": unittest.main()
