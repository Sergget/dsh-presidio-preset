"""用户自定义屏蔽词 (UI 写入的 USER_TERM 规则) 端到端测试。

覆盖插件 dsh-pii-guard-terms 写入的规则文件形状:
  - 每条词一条规则, pattern 是转义后的字面量
  - 多余键 ``term`` 被 Python 侧忽略, 用于无损读回
  - 清空词表写永不匹配占位 ``(?!)`` 而不是空数组
以及该规则文件确实进脱敏链路 (占位符 / 还原 / 热更新)。
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from presidio_pii.custom_rules import CustomRuleSet  # noqa: E402
from presidio_pii.engine import PresidioPIIEngine  # noqa: E402

ENTITY_TYPE = "USER_TERM"
PLACEHOLDER_NAME = "user-term-placeholder"
NEVER_MATCH = "(?!)"


def _escape_literal(text):
    """与插件 Host 半体 escapeLiteral() 同形的转义。"""
    out = []
    for ch in text:
        if ch in ".*+?^${}()|[]\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _rule(index, term):
    """与插件 Host 半体 writeTerms() 同形的规则条目。"""
    return {
        "name": "user-term-%04d" % index,
        "entity_type": ENTITY_TYPE,
        "pattern": _escape_literal(term),
        "score": 0.95,
        "priority": 0,
        "term": term,
    }


def _placeholder_rule():
    return {
        "name": PLACEHOLDER_NAME,
        "entity_type": ENTITY_TYPE,
        "pattern": NEVER_MATCH,
        "score": 0,
        "priority": 0,
        "term": "",
    }


def _engine(rules_path):
    return PresidioPIIEngine(
        db_path=":memory:",
        custom_rules=str(rules_path),
        rules_check_interval=0.0,
    )


class UserTermsRuleFileTest(unittest.TestCase):
    """规则文件形状与命中行为。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.rules_path = Path(self._tmp.name) / "user_terms_rules.json"
        self.addCleanup(self._tmp.cleanup)

    def _write(self, rules):
        self.rules_path.write_text(
            json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")

    def test_term_key_is_ignored_by_python(self):
        """term 键是插件自定义键, Python 侧忽略但不得报错。"""
        self._write([_rule(1, "绝密代号")])
        engine = _engine(self.rules_path)
        out = engine.redact("项目代号是绝密代号，请勿外传。", "s-term")
        self.assertIn("⟦PII:USER_TERM:0001⟧", out.text)
        self.assertNotIn("绝密代号", out.text)
        self.assertEqual(out.entity_counts.get(ENTITY_TYPE), 1)

    def test_restore_is_byte_exact(self):
        """占位符可逐字还原。"""
        text = "项目代号是绝密代号，请勿外传。"
        self._write([_rule(1, "绝密代号")])
        engine = _engine(self.rules_path)
        out = engine.redact(text, "s-restore")
        restored = engine.restore(out.text, "s-restore")
        self.assertEqual(restored.text, text)

    def test_metacharacters_are_literal(self):
        """pattern 按字面量解释: a.c 不应匹配 abc。"""
        self._write([_rule(1, "a.c")])
        engine = _engine(self.rules_path)
        out = engine.redact("值是 abc 结尾", "s-meta")
        self.assertNotIn("⟦PII:USER_TERM:", out.text)
        out = engine.redact("值是 a.c 结尾", "s-meta2")
        self.assertIn("⟦PII:USER_TERM:0001⟧", out.text)

    def test_placeholder_never_matches(self):
        """清空词表写的占位规则不产生任何实体。"""
        self._write([_placeholder_rule()])
        engine = _engine(self.rules_path)
        text = "项目代号是绝密代号，请勿外传。"
        out = engine.redact(text, "s-empty")
        self.assertEqual(out.text, text)
        self.assertEqual(out.n_replaced, 0)

    def test_multiple_terms_each_get_a_rule(self):
        self._write([_rule(1, "甲计划"), _rule(2, "乙计划")])
        engine = _engine(self.rules_path)
        out = engine.redact("甲计划与乙计划都保密", "s-multi")
        self.assertEqual(out.entity_counts.get(ENTITY_TYPE), 2)
        self.assertIn("⟦PII:USER_TERM:0001⟧", out.text)
        self.assertIn("⟦PII:USER_TERM:0002⟧", out.text)

    def test_empty_array_is_not_used_as_clear_marker(self):
        """空数组不是合法的清空写法 (规则加载器会保留旧规则)。"""
        self._write([])
        rule_set = CustomRuleSet(sources=str(self.rules_path), check_interval=0.0)
        self.assertEqual(len(rule_set.rules), 0)


class UserTermsHotReloadTest(unittest.TestCase):
    """UI 改词后 1 秒内热更新 (CustomRuleSet.refresh)。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.rules_path = Path(self._tmp.name) / "user_terms_rules.json"
        self.addCleanup(self._tmp.cleanup)

    def _write(self, rules):
        self.rules_path.write_text(
            json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")

    def _touch(self):
        st = self.rules_path.stat()
        os.utime(self.rules_path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))

    def test_added_term_takes_effect_after_refresh(self):
        self._write([_rule(1, "甲计划")])
        rule_set = CustomRuleSet(sources=str(self.rules_path), check_interval=0.0)
        engine = PresidioPIIEngine(db_path=":memory:", custom_rules=rule_set)
        out = engine.redact("甲计划在推进", "s-hot")
        self.assertIn("⟦PII:USER_TERM:0001⟧", out.text)

        self._write([_rule(1, "甲计划"), _rule(2, "乙计划")])
        self._touch()
        # check_interval<=0 时自动检查关闭, 显式 reload 才会换规则 (与 hooks.reload_rules 同语义)
        self.assertTrue(rule_set.refresh(force=True))
        engine._sync_recognizers()
        out = engine.redact("乙计划在推进", "s-hot2")
        self.assertIn("⟦PII:USER_TERM:0001⟧", out.text)

    def test_engine_auto_refresh_picks_up_new_term(self):
        """运行期路径: 引擎在 analyze 前自动检查规则文件 (生产用 1 秒间隔)。"""
        self._write([_rule(1, "甲计划")])
        rule_set = CustomRuleSet(sources=str(self.rules_path), check_interval=0.01)
        engine = PresidioPIIEngine(db_path=":memory:", custom_rules=rule_set)
        out = engine.redact("乙计划在推进", "s-hot-auto")
        self.assertEqual(out.n_replaced, 0)

        self._write([_rule(1, "甲计划"), _rule(2, "乙计划")])
        self._touch()
        time.sleep(0.02)
        out = engine.redact("乙计划在推进", "s-hot-auto2")
        self.assertIn("⟦PII:USER_TERM:0001⟧", out.text)

    def test_removed_term_stops_matching(self):
        self._write([_rule(1, "甲计划"), _rule(2, "乙计划")])
        rule_set = CustomRuleSet(sources=str(self.rules_path), check_interval=0.0)
        engine = PresidioPIIEngine(db_path=":memory:", custom_rules=rule_set)
        self.assertEqual(
            engine.redact("乙计划在推进", "s-hot3").entity_counts.get(ENTITY_TYPE), 1)

        self._write([_rule(1, "甲计划")])
        self._touch()
        self.assertTrue(rule_set.refresh(force=True))
        engine._sync_recognizers()
        out = engine.redact("乙计划在推进", "s-hot4")
        self.assertEqual(out.n_replaced, 0)
        self.assertEqual(out.text, "乙计划在推进")


if __name__ == "__main__":
    unittest.main()
