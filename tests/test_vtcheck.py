import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vtcheck as V  # noqa: E402


class Extract(unittest.TestCase):
    def kinds(self, text):
        return V.indicators(text)[0]

    def test_defanged_url_from_phishfinder(self):
        self.assertEqual(self.kinds("hxxps://bakery-example[.]net/redirect.html"),
                         [("url", "https://bakery-example.net/redirect.html")])

    def test_domain_ip_hash(self):
        k = self.kinds("seen at amz-support-verify.example.net from 8.8.8.8, file "
                       "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        self.assertIn(("domain", "amz-support-verify.example.net"), k)
        self.assertIn(("ip", "8.8.8.8"), k)
        self.assertIn(("hash", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"), k)

    def test_filenames_and_private_ips_skipped(self):
        found, notes = V.indicators("open Invoice.pdf and report.docx on 192.168.1.1")
        self.assertEqual(found, [])
        self.assertTrue(any("private" in n for n in notes))

    def test_personal_link_looks_up_domain_only(self):
        found, notes = V.indicators("https://evil.example.com/login?email=user%40example.com")
        self.assertEqual(found, [("domain", "evil.example.com")])
        self.assertTrue(notes)

    def test_email_address_gives_domain_not_user(self):
        self.assertEqual(self.kinds("from sender@phishy-shop.example.org"), [("domain", "phishy-shop.example.org")])

    def test_url_host_not_repeated_as_domain(self):
        self.assertEqual(len(self.kinds("https://bad.example.org/x and again bad.example.org")), 2)

    def test_vt_links(self):
        self.assertEqual(V.vt_url("domain", "a.com"), "https://www.virustotal.com/gui/domain/a.com")
        self.assertTrue(V.vt_url("url", "https://a.com/x?y=1").startswith("https://www.virustotal.com/gui/search/https%3A"))


if __name__ == "__main__":
    unittest.main()
