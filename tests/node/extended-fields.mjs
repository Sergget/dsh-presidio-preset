import { Engine } from '../../node_pii/engine.mjs';
import { CustomRuleSet } from '../../node_pii/custom_rules.mjs';
import assert from 'node:assert/strict';
import path from 'node:path';

const repoDir = path.resolve('.');
const rules = new CustomRuleSet({ paths: [path.join(repoDir, 'rule_libraries/extended-fields.json')] });
const engine = new Engine({ repoDir, customRules: rules, dbPath: ':memory:' });

const positives = [
  ["年龄：45岁。", "45岁", "AGE"],
  ["现年 36 周岁", "36 周岁", "AGE"],
  ["出生日期：1990-03-07", "1990-03-07", "BIRTH_DATE"],
  ["生于1985年12月", "1985年12月", "BIRTH_DATE"],
  ["性别：男，民族：汉族", "男", "GENDER"],
  ["性别：男，民族：汉族", "汉族", "ETHNICITY"],
  ["学历：硕士研究生", "硕士研究生", "EDUCATION"],
  ["微信号：zhangsan_2026", "zhangsan_2026", "IM_ACCOUNT"],
  ["工号：EMP-00927", "EMP-00927", "EMPLOYEE_ID"],
  ["住址：天府大道88号3单元501室", "天府大道88号3单元501室", "LOCATION"],
  ["籍贯：山东济南", "山东济南", "LOCATION"],
  ["员工范志强，男，45岁。", "范志强", "PERSON"],
];
for (const [text, value, entity_type] of positives) {
  const found = engine.analyze(text);
  assert.ok(found.some((r) => r.entity_type === entity_type && text.slice(r.start, r.end) === value),
    `${entity_type} ${value}: ${JSON.stringify(found.map((r) => [r.entity_type, text.slice(r.start, r.end)]))}`);
}
const negativeTypes = new Set(["AGE", "BIRTH_DATE", "GENDER", "ETHNICITY", "EDUCATION", "IM_ACCOUNT", "EMPLOYEE_ID"]);
for (const text of ["适用年龄：20岁以上", "招聘年龄：3岁以下", "今年有 45 岁树龄的古树", "性别平等是基本原则", "民族政策持续完善", "学历教育研究中心"]) {
  assert.deepEqual(engine.analyze(text).filter((r) => negativeTypes.has(r.entity_type)), [], text);
}
const org = engine.analyze("他是公司总经理");
assert.ok(!org.some((r) => r.entity_type === "ORGANIZATION" && textSlice("他是公司总经理", r) === "他是公司"));
function textSlice(text, r) { return text.slice(r.start, r.end); }
console.log('NODE_EXTENDED_FIELDS_PASS', positives.length);
