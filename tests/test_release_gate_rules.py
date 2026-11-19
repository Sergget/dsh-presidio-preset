"""release_gate 扫描规则自身的回归测试。

门禁是「防作弊」资产：它必须既抓得住真问题，又不能因为豁免太宽而形同虚设。
本文件锁定两条规则的判定边界，改规则时先跑这里。

  - #7  密钥扫描：运行时生成的密钥/间接引用要抑制，硬编码凭据必须命中
  - 闭包  依赖漏洞：扫描对象是本包依赖闭包，不是构建机的整个 site-packages
"""
import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "release_gate_under_test", REPO / "tools" / "release_gate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SecretScanRulesTest(unittest.TestCase):
    """#7: 豁免只能覆盖「不是字面量」的值。"""

    @classmethod
    def setUpClass(cls):
        cls.gate = _load_gate()

    def _hits(self, line):
        hits, suppressed = self.gate._scan_text(line, "t")
        return hits, suppressed

    def test_runtime_generated_secret_is_suppressed(self):
        # hooks.py 里的真实形态：运行时生成随机密钥，不是硬编码
        hits, suppressed = self._hits('secret = secrets.token_bytes(32)')
        self.assertEqual(hits, [], "运行时生成的密钥不该被当成泄露凭据")
        self.assertEqual(suppressed, 1)

    def test_indirect_reference_is_suppressed(self):
        for line in ('token = os.environ.get("TOKEN")',
                     'token = cfg.credentials.token',
                     'secret = load_secret()',
                     'key = hashlib.sha256(data).digest()'):
            with self.subTest(line=line):
                hits, _ = self._hits(line)
                self.assertEqual(hits, [], f"间接引用被误判为硬编码: {line}")

    def test_placeholder_is_not_a_hit(self):
        hits, _ = self._hits('password = "***"')
        self.assertEqual(hits, [])

    def test_hardcoded_credentials_are_still_caught(self):
        """豁免放宽后，这四条必须仍然被抓出来——否则门禁就是摆设。"""
        for line in ('api_key = "abcd1234efgh5678"',
                     'secret = "topsecretvalue99"',
                     'password = "Hunter2Hunter2"',
                     'aws = "AKIAIOSFODNN7EXAMPLE"'):
            with self.subTest(line=line):
                hits, _ = self._hits(line)
                self.assertTrue(hits, f"硬编码凭据漏扫: {line}")

    def test_masked_output_does_not_leak_full_value(self):
        hits, _ = self._hits('api_key = "abcd1234efgh5678"')
        self.assertTrue(hits)
        masked = hits[0][2]
        self.assertIn("***", masked, "命中值必须打码，不能把凭据写进报告")
        self.assertNotIn("abcd1234efgh5678", masked)


class DependencyClosureTest(unittest.TestCase):
    """#6: 审计对象必须是本包闭包，不是宿主环境。"""

    @classmethod
    def setUpClass(cls):
        cls.gate = _load_gate()

    def test_requirements_come_from_pyproject(self):
        reqs = self.gate._project_requirements()
        self.assertTrue(reqs, "pyproject.toml 的 [project].dependencies 应能读出")
        joined = " ".join(reqs)
        for pkg in ("python-docx", "python-pptx", "openpyxl"):
            self.assertIn(pkg, joined)

    def test_host_only_package_is_outside_closure(self):
        """mcp 带进来的 opentelemetry-api 不属于本包闭包。

        这是 #6 曾经 FAIL 的根因：门禁按 `pip freeze` 审计整机，
        把构建机的额外安装算成了本包漏洞。
        """
        reqs = self.gate._project_requirements()
        self.assertFalse(any("opentelemetry" in r.lower() for r in reqs),
                         "本包不该直接依赖 opentelemetry")
        # 闭包解析结果（若环境允许联网/已缓存）也不应包含它
        import tempfile
        report = Path(tempfile.mkdtemp()) / "report.json"
        closure, why = self.gate._resolve_closure(reqs, report)
        if not closure:
            self.skipTest(f"闭包解析不可用（离线或无缓存）: {why}")
        self.assertTrue(any("python-docx" in c for c in closure))
        self.assertFalse(any("opentelemetry" in c for c in closure),
                         f"宿主环境包混进了本包闭包: {closure}")


if __name__ == "__main__":
    unittest.main()
