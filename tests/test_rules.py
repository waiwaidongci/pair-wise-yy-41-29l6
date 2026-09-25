import unittest
from src import rules
from src.domain import ConflictError, ValidationError
class RulesTest(unittest.TestCase):
    def test_priority_deadline_and_escalation(self):
        low=rules.priority_score(rules.SEVERITIES[0],1,10,0); high=rules.priority_score(rules.SEVERITIES[-1],30,10,3)
        self.assertGreater(high,low); self.assertLessEqual(rules.response_deadline_hours(rules.SEVERITIES[-1],30,10),rules.response_deadline_hours(rules.SEVERITIES[0],1,10))
        self.assertTrue(rules.escalation_required(rules.SEVERITIES[-1],1,10)); self.assertTrue(rules.escalation_required(rules.SEVERITIES[0],10,10))
    def test_transition_guards(self):
        self.assertTrue(rules.can_transition(rules.STATES[0],rules.STATES[1]))
        with self.assertRaises(ConflictError): rules.validate_transition(rules.STATES[0],rules.STATES[-1])
        with self.assertRaises(ValidationError): rules.priority_score("not-a-severity",1,1)
    def test_disposition_observe(self):
        r=rules.evaluate_disposition(5,10,0,0)
        self.assertEqual(r["disposition"],'observe'); self.assertEqual(r["recommendation"],'继续观察')
        self.assertFalse(r["basis"]["threshold_reached"]); self.assertFalse(r["basis"]["restrict_ratio_reached"])
    def test_disposition_restrict_on_ratio(self):
        r=rules.evaluate_disposition(7.5,10,0,0)
        self.assertEqual(r["disposition"],'restrict'); self.assertTrue(r["basis"]["restrict_ratio_reached"])
        self.assertFalse(r["basis"]["threshold_reached"])
    def test_disposition_restrict_on_two_open(self):
        r=rules.evaluate_disposition(1,10,2,0)
        self.assertEqual(r["disposition"],'restrict'); self.assertEqual(r["basis"]["open_records"],2)
    def test_disposition_close_on_threshold(self):
        r=rules.evaluate_disposition(10,10,0,0)
        self.assertEqual(r["disposition"],'close'); self.assertTrue(r["basis"]["threshold_reached"])
    def test_disposition_close_on_critical(self):
        r=rules.evaluate_disposition(1,10,1,1)
        self.assertEqual(r["disposition"],'close'); self.assertEqual(r["basis"]["critical_open"],1)
    def test_disposition_support_rank(self):
        self.assertTrue(rules.disposition_supports_target('close','restricted'))
        self.assertTrue(rules.disposition_supports_target('restrict','restricted'))
        self.assertTrue(rules.disposition_supports_target('close','closed'))
        self.assertFalse(rules.disposition_supports_target('restrict','closed'))
        self.assertFalse(rules.disposition_supports_target('observe','restricted'))
        self.assertFalse(rules.disposition_supports_target('restrict','warning'))
if __name__=="__main__": unittest.main()
