import unittest
from parry import scan_source

class TestApiSecurityIdor(unittest.TestCase):
    def test_idor_unscoped_db_query_flagged(self):
        vulnerable_code = """
        app.get('/api/invoices/:id', async (req, res) => {
            const invoice = await prisma.invoice.findUnique({
                where: { id: req.params.id }
            });
            res.json(invoice);
        });
        """
        findings = scan_source(vulnerable_code, "invoice_route.ts", "typescript")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-SEC-API001", rule_ids)
        idor_finding = next(f for f in findings if f.rule_id == "PARRY-SEC-API001")
        self.assertEqual(idor_finding.category, "security")
        self.assertEqual(idor_finding.severity, "error")
        self.assertIn("IDOR", idor_finding.message)

    def test_idor_scoped_db_query_passes(self):
        secure_code = """
        app.get('/api/invoices/:id', async (req, res) => {
            const invoice = await prisma.invoice.findFirst({
                where: { id: req.params.id, userId: req.user.id }
            });
            res.json(invoice);
        });
        """
        findings = scan_source(secure_code, "invoice_route.ts", "typescript")
        rule_ids = [f.rule_id for f in findings]
        self.assertNotIn("PARRY-SEC-API001", rule_ids)

    def test_idor_unscoped_find_by_pk_flagged(self):
        vulnerable_code = """
        router.get('/orders/:id', async (req, res) => {
            const order = await Order.findByPk(req.params.id);
            res.json(order);
        });
        """
        findings = scan_source(vulnerable_code, "order_route.js", "javascript")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-SEC-API001", rule_ids)

if __name__ == "__main__":
    unittest.main()
