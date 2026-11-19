"""preset.json -> 引擎热更新的端到端回归。

UI（PII 防护设置页）保存的是 preset.json 里的
  - 顶层 entity_types
  - config.whitelist_path
两个字段。改完之后**不重启 DSH 也必须生效**，因为 hooks._get_engine() 每次调用
都会比对 preset 签名（mtime_ns + size），变了就重载。

本文件锁定这条链路。曾经的风险是：UI 能写、但引擎不读，用户以为生效了其实没有。
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

PRESET = REPO / ".agent-presets" / "presidio-pii" / "preset.json"
NAME = "张三"


class PresetHotReloadTest(unittest.TestCase):
    """改 preset.json 后，同一进程内的单例引擎必须跟着变。"""

    def setUp(self):
        import presidio_pii.hooks as hooks
        self.hooks = hooks
        self._backup = PRESET.read_bytes()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(self._restore)
        hooks.reset_singleton()

    def _restore(self):
        PRESET.write_bytes(self._backup)
        self.hooks.reset_singleton()

    def _write_preset(self, **patch):
        data = json.loads(self._backup.decode("utf-8"))
        cfg = data.setdefault("config", {})
        for key, value in patch.items():
            cfg[key] = value
        PRESET.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")

    def test_whitelist_path_from_preset_takes_effect(self):
        wl = Path(self._tmp.name) / "wl.txt"
        wl.write_text(NAME + "\n", encoding="utf-8")

        engine = self.hooks._get_engine()
        before = engine.redact(NAME + "与李四在北京签订合同", "t-wl").text
        self.assertNotIn(NAME, before, "基线应脱敏")

        self._write_preset(whitelist_path=str(wl).replace("\\", "/"))
        engine = self.hooks._get_engine()      # 同一单例，触发签名比对
        self.assertIn(NAME, engine.whitelist, "preset 里的白名单没被读进来")

        after = engine.redact(NAME + "与李四在北京签订合同", "t-wl").text
        self.assertIn(NAME, after, "白名单词应被豁免")
        self.assertNotIn("李四", after, "白名单不该连带放行其他实体")

    def test_clearing_whitelist_restores_redaction(self):
        wl = Path(self._tmp.name) / "wl2.txt"
        wl.write_text(NAME + "\n", encoding="utf-8")
        self._write_preset(whitelist_path=str(wl).replace("\\", "/"))
        self.hooks._get_engine()

        self._write_preset(whitelist_path=None)
        engine = self.hooks._get_engine()
        self.assertEqual(engine.whitelist, [], "清空后白名单应为空")
        self.assertNotIn(NAME, engine.redact(NAME + "签字", "t-wl2").text,
                         "清空白名单后应恢复脱敏")

    def test_entity_types_from_preset_take_effect(self):
        data = json.loads(self._backup.decode("utf-8"))
        original = data.get("entity_types")
        self.assertIsInstance(original, list)

        data["entity_types"] = ["PHONE_NUMBER"]
        PRESET.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        engine = self.hooks._get_engine()
        self.assertEqual(set(engine.entity_types), {"PHONE_NUMBER"})

        # 只开手机号时，人名/地名不该再被脱敏
        text = "张三的电话是13800138000"
        out = engine.redact(text, "t-types").text
        self.assertIn("\u27e6PII:PHONE_NUMBER:", out, "手机号应仍被脱敏")
        self.assertNotIn("13800138000", out, "手机号原文不该泄漏")
        self.assertIn(NAME, out, "未启用的实体类型不该被脱敏")

    def test_unknown_preset_keeps_previous_values(self):
        """preset 写坏时只能告警，不能把收窄过的配置静默重置成全开。

        关键：基线必须先**收窄**（只开 PHONE_NUMBER），否则「全部启用」与
        「读失败回退到全部启用」在外部表现上完全一样，这条测试就失去证明力。
        """
        data = json.loads(self._backup.decode("utf-8"))
        data["entity_types"] = ["PHONE_NUMBER"]
        PRESET.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        engine = self.hooks._get_engine()
        self.assertEqual(set(engine.entity_types), {"PHONE_NUMBER"})

        PRESET.write_text("{ this is not json", encoding="utf-8")
        again = self.hooks._get_engine()
        self.assertEqual(set(again.entity_types), {"PHONE_NUMBER"},
                         "preset 解析失败应保留上一次已知好配置")
        # 只看 entity_types 还不够——要确认行为上真的还在收窄
        out = again.redact("张三的电话是13800138000", "t-bad").text
        self.assertIn(NAME, out, "人名不该重新被脱敏（说明没收窄成全开）")

    def test_new_engine_reads_preset_without_restart(self):
        """reset 后新建的引擎也必须按当前 preset 配置。"""
        data = json.loads(self._backup.decode("utf-8"))
        data["entity_types"] = ["PHONE_NUMBER"]
        PRESET.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        self.hooks.reset_singleton()
        engine = self.hooks._get_engine()
        self.assertEqual(set(engine.entity_types), {"PHONE_NUMBER"})


if __name__ == "__main__":
    unittest.main()
