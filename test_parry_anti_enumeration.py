import unittest
from parry import scan_source

class TestAntiEnumeration(unittest.TestCase):
    def test_flag_autoincrement_integer_pk_prisma(self):
        prisma_schema = """
        model Invoice {
            id Int @id @default(autoincrement())
            amount Float
        }
        """
        findings = scan_source(prisma_schema, "schema.prisma", "prisma")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-SEC-API002", rule_ids)
        finding = next(f for f in findings if f.rule_id == "PARRY-SEC-API002")
        self.assertIn("enumeration", finding.message.lower())

    def test_flag_serial_pk_sql(self):
        sql_schema = "CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(255));"
        findings = scan_source(sql_schema, "schema.sql", "sql")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-SEC-API002", rule_ids)

    def test_uuid_pk_passes(self):
        secure_prisma = """
        model Invoice {
            id String @id @default(uuid())
            amount Float
        }
        """
        findings = scan_source(secure_prisma, "schema.prisma", "prisma")
        rule_ids = [f.rule_id for f in findings]
        self.assertNotIn("PARRY-SEC-API002", rule_ids)

if __name__ == "__main__":
    unittest.main()
