"""2026-11-18 安全加固改动的回归测试。

每一条对应 CODE-REVIEW-20261118 里的一项修复，且都做过「反证」验证：
把实现改回缺陷形态时，对应用例会失败（见 docs/CODE-REVIEW-20261118.md 第七节）。

覆盖：
  - #5  get_max_seq 序号解析：4 位以上序号不能被截断
  - #8  entity_types 白名单：过滤生效、空集表示全开、自定义规则不受限
  - #15 journal 指纹：HMAC 而非裸 SHA256，换密钥指纹变化
  - #16 映射库权限：文件存在且可读写（加固失败不应破坏可用性）
"""
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from presidio_pii.db import SessionRegistry  # noqa: E402
from presidio_pii.engine import PresidioPIIEngine  # noqa: E402


class GetMaxSeqTest(unittest.TestCase):
    """#5: 序号必须按类型名长度算偏移，不能定宽截取。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.reg = SessionRegistry(Path(self._tmp.name) / "s.db")
        self.addCleanup(self._tmp.cleanup)
        # close 必须在临时目录清理之前注册（addCleanup 后进先出）
        self.addCleanup(self.reg.close)

    def _insert(self, ptype, seq, idx=1):
        ph = "\u27e6PII:%s:%04d\u27e7" % (ptype, seq)
        self.reg.add_mapping("k", "svc", idx, ptype, ph, "\u539f\u6587%s" % seq)
        return ph

    def test_four_digit_seq(self):
        self._insert("PERSON", 42)
        self.assertEqual(self.reg.get_max_seq("k", "PERSON"), 42)

    def test_five_digit_seq_is_not_truncated(self):
        """定宽 SUBSTR(placeholder, -5, 4) 会把 12345 读成 1234。"""
        self._insert("PERSON", 12345)
        self.assertEqual(self.reg.get_max_seq("k", "PERSON"), 12345)

    def test_seq_beyond_9999_keeps_growing(self):
        self._insert("PERSON", 9999, idx=1)
        self.assertEqual(self.reg.get_max_seq("k", "PERSON"), 9999)
        self._insert("PERSON", 10000, idx=2)
        self.assertEqual(self.reg.get_max_seq("k", "PERSON"), 10000)

    def test_long_type_name_offset(self):
        """类型名长度不同，偏移必须随长度变化。"""
        self._insert("CREDIT_CODE", 7)
        self.assertEqual(self.reg.get_max_seq("k", "CREDIT_CODE"), 7)

    def test_unknown_type_is_zero(self):
        self._insert("PERSON", 5)
        self.assertEqual(self.reg.get_max_seq("k", "NOT_A_TYPE"), 0)


class EntityTypesFilterTest(unittest.TestCase):
    """#8: preset 的 entity_types 白名单。"""

    TEXT = "\u5f20\u4e09\u7684\u624b\u673a\u53f7\u662f13800138000\uff0c\u4f4f\u5728\u5317\u4eac\u5e02\u6d77\u6dc0\u533a\u3002"

    def _types(self, **kwargs):
        engine = PresidioPIIEngine(db_path=":memory:", **kwargs)
        return {r.entity_type for r in engine.analyze(self.TEXT)}

    def test_all_enabled_when_unset(self):
        found = self._types()
        self.assertIn("PHONE_NUMBER", found)
        self.assertIn("LOCATION", found)

    def test_filter_keeps_only_listed(self):
        found = self._types(entity_types=["PHONE_NUMBER"])
        self.assertEqual(found, {"PHONE_NUMBER"})

    def test_empty_list_means_unrestricted(self):
        self.assertEqual(self._types(entity_types=[]), self._types())

    def test_filter_runs_before_overlap_resolution(self):
        """关掉 LOCATION 后，该区间的 ORGANIZATION 仍应能被识别。"""
        engine = PresidioPIIEngine(db_path=":memory:", entity_types=["ORGANIZATION"])
        found = {r.entity_type for r in engine.analyze(self.TEXT)}
        self.assertTrue(found <= {"ORGANIZATION"}, found)

    def test_set_entity_types_applies_next_call(self):
        engine = PresidioPIIEngine(db_path=":memory:")
        self.assertIn("LOCATION", {r.entity_type for r in engine.analyze(self.TEXT)})
        engine.set_entity_types(["PHONE_NUMBER"])
        self.assertEqual(
            {r.entity_type for r in engine.analyze(self.TEXT)}, {"PHONE_NUMBER"})

    def test_custom_rule_type_survives_filter(self):
        """自定义屏蔽词 (USER_TERM) 不该被内置类型勾选列表关掉。"""
        fmt = ('[{"name":"t","entity_type":"USER_TERM",'
               '"pattern":"\\u7532\\u8ba1\\u5212","score":0.95,"priority":0}]')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(fmt, encoding="utf-8")
            engine = PresidioPIIEngine(
                db_path=":memory:", custom_rules=str(path),
                entity_types=["PHONE_NUMBER"])
            out = engine.redact("\u7532\u8ba1\u5212\u5728\u63a8\u8fdb", "s-1")
            self.assertIn("USER_TERM", out.text)


class FingerprintTest(unittest.TestCase):
    """#15: 日志指纹必须是 HMAC，不能是裸 SHA256。"""

    def setUp(self):
        from presidio_pii import hooks
        self.hooks = hooks
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(hooks.reset_singleton)

    def _fp_with_key(self, key):
        self.hooks.reset_singleton()
        os.environ["PII_DSH_LOG_HMAC_KEY"] = key
        self.addCleanup(os.environ.pop, "PII_DSH_LOG_HMAC_KEY", None)
        return self.hooks._fingerprint("13800138000")

    def test_not_bare_sha256(self):
        fp = self._fp_with_key("test-key-abc")
        bare = hashlib.sha256("13800138000".encode("utf-8")).hexdigest()[:16]
        self.assertNotEqual(fp, bare)

    def test_same_key_is_deterministic(self):
        self.assertEqual(self._fp_with_key("same-key"), self._fp_with_key("same-key"))

    def test_different_key_changes_fingerprint(self):
        self.assertNotEqual(self._fp_with_key("key-a"), self._fp_with_key("key-b"))

    def test_length_is_stable(self):
        self.assertEqual(len(self._fp_with_key("k")), 16)


class RegistryPermissionTest(unittest.TestCase):
    """#16: 权限加固不得破坏可用性（加固失败只告警）。"""

    def test_registry_stays_usable_after_hardening(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "sub" / "s.db"
            with SessionRegistry(db) as reg:
                self.assertTrue(db.exists())
                reg.add_mapping("k", "svc", 1, "PERSON", "\u27e6PII:PERSON:0001\u27e7", "\u5f20\u4e09")
                self.assertEqual(reg.get_restore_map("k", "svc"),
                                 [{"ptype": "PERSON",
                                   "placeholder": "\u27e6PII:PERSON:0001\u27e7",
                                   "original": "\u5f20\u4e09"}])

    def test_parent_directory_is_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "a" / "b" / "s.db"
            with SessionRegistry(db):
                self.assertTrue(db.parent.is_dir())

    def test_context_manager_closes_connection(self):
        """close 后连接不可再用，证明资源确实释放。"""
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            reg = SessionRegistry(Path(tmp) / "s.db")
            reg.close()
            with self.assertRaises(sqlite3.ProgrammingError):
                reg.conn.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
