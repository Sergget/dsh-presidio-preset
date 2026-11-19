/**
 * Browser half of dsh-pii-guard-terms.
 *
 * Registers a settings page (`settings.section`) where the user can add, remove
 * and save the terms that must be redacted before prompts leave the harness.
 * The page talks to the Host half over two JSON routes:
 *
 *   GET  /api/dsh-pii-guard/terms        -> list terms
 *   POST /api/dsh-pii-guard/terms/save   -> replace the term list
 *   GET  /api/dsh-pii-guard/settings     -> read guard runtime settings (P0/P1)
 *   POST /api/dsh-pii-guard/settings/save -> write guard runtime settings
 *
 * The host matches routes by pathname only, so the URLs are absolute.
 */
(function bootstrap() {
  const MODULE_ID = 'dsh-pii-guard-terms';
  const NS = 'settings.piiGuardTerms';
  const API_LIST = '/api/dsh-pii-guard/terms';
  const API_SAVE = '/api/dsh-pii-guard/terms/save';
  const API_SETTINGS = '/api/dsh-pii-guard/settings';
  const API_SETTINGS_SAVE = '/api/dsh-pii-guard/settings/save';
  const API_PRESET = '/api/dsh-pii-guard/preset';
  const API_PRESET_SAVE = '/api/dsh-pii-guard/preset/save';
  const SECTION_ID = 'pii-guard-terms';

  const I18N_ZH = {
    nav: 'PII 防护',
    title: 'PII 屏蔽词',
    intro: '在这里添加需要自动脱敏的词或短语。保存后约 1 秒内生效，所有工具结果与提示词都会先脱敏再进入模型上下文。',
    placeholder: '输入要屏蔽的词或短语，回车添加',
    add: '添加',
    remove: '删除',
    save: '保存',
    saved: '已保存',
    saving: '保存中…',
    loading: '读取中…',
    empty: '还没有屏蔽词。',
    'save.failed': '保存失败',
    'load.failed': '读取失败',
    'term.empty': '请输入非空词条',
    'term.tooLong': '词条过长',
    'term.duplicate': '词条已存在',
    'term.limit': '词条数量超出上限',
    'file.label': '规则文件',
    'count': '词条数',
    'settings.title': 'PII 防护配置',
    'settings.intro': '下列设置保存后即时生效，下一次工具调用即采用，无需重启 DSH。',
    'display.label': '显示还原模式',
    'display.hint': '控制工具结果里的占位符在界面上如何还原给用户。',
    'display.full': '完整（默认，还原为原值）',
    'display.mask': '打码（如 13*******78、z***@example.com）',
    'display.off': '关闭（原样保留占位符）',
    'failOpen.label': '失败时透传（排障用）',
    'failOpen.hint': '开启后，脱敏服务异常时工具不再拦截而是放行。仅用于排障，正常情况下应保持关闭。',
    'failOpen.warn': '警告：开启会降低防护，仅限排障时临时使用',
    'shellDisabled.label': '关闭 Shell 守卫',
    'shellDisabled.hint': '开启后整个进程不再对 shell / 后台任务做脱敏拦截。',
    'shellAllowlist.label': 'Shell 命令白名单（正则）',
    'shellAllowlist.hint': '留空表示所有命令都经过脱敏；填写正则表达式后，匹配到的命令会跳过守卫。',
    'shellAllowlist.placeholder': '例如：^pwsh -Command Get-ChildItem',
    'settings.save': '保存设置',
    'settings.saved': '已保存，下一次工具调用即生效',
    'settings.invalidRegex': '正则表达式无效',
    'preset.title': '实体类型与白名单',
    'preset.intro': '选择需要脱敏的实体类型；取消勾选后该类信息不再脱敏。保存后下一次调用即生效，无需重启 DSH。',
    'preset.typesLabel': '启用的实体类型',
    'preset.typesHint': '全部取消勾选表示启用全部类型。自定义屏蔽词始终生效，不受此处影响。',
    'preset.allOn': '全选',
    'preset.allOff': '全不选',
    'preset.whitelistLabel': '白名单文件路径',
    'preset.whitelistHint': '每行一个词，命中的词不脱敏。留空表示不使用白名单；相对路径需以 ./ 或 ../ 开头。',
    'preset.whitelistPlaceholder': '例如：./.pii_presidio_store/whitelist.txt',
    'preset.save': '保存实体配置',
    'preset.saved': '已保存，下一次调用即生效',
  };

  const I18N_EN = {
    nav: 'PII protection',
    title: 'PII blocklist',
    intro: 'Add terms or phrases that must be redacted automatically. Changes take effect within about a second: tool results and prompts are redacted before they reach the model context.',
    placeholder: 'Type a term or phrase, press Enter to add',
    add: 'Add',
    remove: 'Remove',
    save: 'Save',
    saved: 'Saved',
    saving: 'Saving…',
    loading: 'Loading…',
    empty: 'No terms yet.',
    'save.failed': 'Save failed',
    'load.failed': 'Load failed',
    'term.empty': 'Enter a non-empty term',
    'term.tooLong': 'Term is too long',
    'term.duplicate': 'Term already exists',
    'term.limit': 'Term count exceeds the limit',
    'file.label': 'Rule file',
    count: 'Terms',
    'settings.title': 'PII guard settings',
    'settings.intro': 'Changes take effect immediately on the next tool call — no DSH restart needed.',
    'display.label': 'Display restore mode',
    'display.hint': 'Controls how placeholders in tool results are restored for display.',
    'display.full': 'Full (default, restore original value)',
    'display.mask': 'Masked (e.g. 13*******78, z***@example.com)',
    'display.off': 'Off (keep placeholders verbatim)',
    'failOpen.label': 'Fail open (troubleshooting only)',
    'failOpen.hint': 'When enabled, tool calls pass through instead of being blocked if the redaction service fails. Keep off normally.',
    'failOpen.warn': 'Warning: enabling this weakens protection — use only for troubleshooting',
    'shellDisabled.label': 'Disable shell guard',
    'shellDisabled.hint': 'When enabled, shell / background tasks are no longer redaction-guarded process-wide.',
    'shellAllowlist.label': 'Shell command allowlist (regex)',
    'shellAllowlist.hint': 'Empty means every command is guarded; a matching regex lets a command skip the guard.',
    'shellAllowlist.placeholder': 'e.g. ^pwsh -Command Get-ChildItem',
    'settings.save': 'Save settings',
    'settings.saved': 'Saved — effective on the next tool call',
    'settings.invalidRegex': 'Invalid regular expression',
    'preset.title': 'Entity types & whitelist',
    'preset.intro': 'Choose which entity types get redacted; unchecking a type stops redacting it. Changes take effect on the next call, no DSH restart.',
    'preset.typesLabel': 'Enabled entity types',
    'preset.typesHint': 'Unchecking everything means all types are enabled. Custom blocklist terms always apply and are unaffected.',
    'preset.allOn': 'Select all',
    'preset.allOff': 'Clear all',
    'preset.whitelistLabel': 'Whitelist file path',
    'preset.whitelistHint': 'One term per line; matches stay unredacted. Leave empty for no whitelist. Relative paths must start with ./ or ../.',
    'preset.whitelistPlaceholder': 'e.g. ./.pii_presidio_store/whitelist.txt',
    'preset.save': 'Save entity config',
    'preset.saved': 'Saved — effective on the next call',
  };

  const CSS = [
    '.pii-guard { display: flex; flex-direction: column; padding: 16px 18px;',
    '  font-family: var(--dsw-font-family, inherit); color: var(--dsw-alias-label-primary); }',
    '.pii-guard__panel { display: flex; flex-direction: column; gap: 12px; }',
    '.pii-guard__panel + .pii-guard__panel { margin-top: 16px; }',
    '.pii-guard__divider { height: 1px; margin: 16px 0 0;',
    '  background: var(--dsw-alias-border-l2); }',
    '.pii-terms { display: flex; flex-direction: column; gap: 12px;',
    '  font-family: var(--dsw-font-family, inherit); color: var(--dsw-alias-label-primary); }',
    '.pii-terms__title { font-size: 13px; font-weight: 600; margin: 0;',
    '  color: var(--dsw-alias-label-secondary); text-transform: uppercase; letter-spacing: .04em; }',
    '.pii-terms__intro { font-size: 12px; line-height: 1.6; margin: 0;',
    '  color: var(--dsw-alias-label-secondary); }',
    '.pii-terms__row { display: flex; gap: 8px; align-items: center; }',
    '.pii-terms__input { flex: 1 1 auto; min-width: 0; padding: 7px 10px;',
    '  border: 1px solid var(--dsw-alias-border-l2); border-radius: 8px;',
    '  background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary);',
    '  font-size: 13px; outline: none; }',
    '.pii-terms__input:focus { border-color: var(--dsw-alias-brand-primary); }',
    '.pii-terms__btn { padding: 7px 14px; border-radius: 8px; cursor: pointer;',
    '  font-size: 13px; border: 1px solid var(--dsw-alias-border-l2);',
    '  background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); }',
    '.pii-terms__btn:hover { border-color: var(--dsw-alias-brand-primary); }',
    '.pii-terms__btn--primary { background: var(--dsw-alias-brand-primary);',
    '  border-color: var(--dsw-alias-brand-primary); color: var(--dsw-alias-bg-base); }',
    '.pii-terms__btn:disabled { opacity: .55; cursor: not-allowed; }',
    '.pii-terms__list { display: flex; flex-wrap: wrap; gap: 8px; min-height: 28px; }',
    '.pii-terms__chip { display: inline-flex; align-items: center; gap: 6px;',
    '  padding: 4px 8px 4px 10px; border-radius: 999px; font-size: 12px;',
    '  background: var(--dsw-alias-bg-layer-2);',
    '  border: 1px solid var(--dsw-alias-border-l1); }',
    '.pii-terms__chip button { border: none; background: transparent; cursor: pointer;',
    '  color: var(--dsw-alias-label-secondary); font-size: 13px; line-height: 1;',
    '  padding: 0 2px; }',
    '.pii-terms__chip button:hover { color: var(--dsw-alias-state-error-primary); }',
    '.pii-terms__meta { display: flex; flex-wrap: wrap; gap: 12px; font-size: 11px;',
    '  color: var(--dsw-alias-label-secondary); }',
    '.pii-terms__meta code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;',
    '  word-break: break-all; }',
    '.pii-terms__status { font-size: 12px; }',
    '.pii-terms__status--error { color: var(--dsw-alias-state-error-primary); }',
    '.pii-terms__status--ok { color: var(--dsw-alias-state-success-primary); }',
    '.pii-terms__empty { font-size: 12px; color: var(--dsw-alias-label-secondary); margin: 0; }',
    '.pii-settings { display: flex; flex-direction: column; gap: 12px;',
    '  font-family: var(--dsw-font-family, inherit); color: var(--dsw-alias-label-primary); }',
    '.pii-settings__title { font-size: 13px; font-weight: 600; margin: 0;',
    '  color: var(--dsw-alias-label-secondary); text-transform: uppercase; letter-spacing: .04em; }',
    '.pii-settings__intro { font-size: 12px; line-height: 1.6; margin: 0;',
    '  color: var(--dsw-alias-label-secondary); }',
    '.pii-settings__field { display: flex; flex-direction: column; gap: 5px; }',
    '.pii-settings__label { font-size: 13px; font-weight: 500; }',
    '.pii-settings__hint { font-size: 11px; line-height: 1.5;',
    '  color: var(--dsw-alias-label-secondary); }',
    '.pii-settings__warn { font-size: 11px; color: var(--dsw-alias-state-warning-primary); }',
    '.pii-settings__select { padding: 7px 10px; border-radius: 8px; font-size: 13px;',
    '  border: 1px solid var(--dsw-alias-border-l2);',
    '  background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); }',
    '.pii-settings__checkrow { display: flex; align-items: center; gap: 8px; font-size: 13px;',
    '  cursor: pointer; }',
    '.pii-settings__checkrow input { width: 15px; height: 15px; cursor: pointer; }',
    '.pii-preset__grid { display: grid; gap: 6px 18px;',
    '  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); margin: 2px 0 4px; }',
  ].join('\n');

  function ensureStyle() {
    if (typeof document === 'undefined') return;
    if (document.getElementById('dsh-pii-guard-terms-style')) return;
    const style = document.createElement('style');
    style.id = 'dsh-pii-guard-terms-style';
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  function interpolate(template, values) {
    return String(template).replace(/\{(\w+)\}/g, (whole, key) => (
      Object.prototype.hasOwnProperty.call(values, key) ? String(values[key]) : whole
    ));
  }

  const fallbackT = (key, values) => interpolate(I18N_ZH[key] ?? key, values ?? {});

  window.__ModuleLoader__.load({
    id: MODULE_ID,
    factory(require) {
      const React = require('react');
      const h = React.createElement;
      const { useEffect, useState, useCallback } = React;

      let t = fallbackT;

      function installI18n(ctx) {
        // Dynamic inject on purpose: a static `inject: ['locale']` would keep
        // this page from mounting on hosts without the locale service.
        ctx.inject(['locale'], (i18nCtx) => {
          const locale = i18nCtx.locale;
          const disposeZh = locale.register(NS, 'zh', I18N_ZH);
          const disposeEn = locale.register(NS, 'en', I18N_EN);
          t = locale.bind(NS);
          return () => {
            disposeEn();
            disposeZh();
            t = fallbackT;
          };
        });
      }

      async function apiRequest(path, options) {
        const response = await fetch(path, options);
        let body = {};
        try {
          body = await response.json();
        } catch {
          body = {};
        }
        if (!response.ok) {
          throw new Error(body?.error || `HTTP ${response.status}`);
        }
        return body;
      }

      function TermsIcon(props) {
        const size = Number(props?.size ?? 16);
        const active = Boolean(props?.active);
        const color = active
          ? 'var(--dsw-alias-brand-primary)'
          : 'var(--dsw-alias-label-secondary)';
        return h('svg', {
          width: size,
          height: size,
          viewBox: '0 0 24 24',
          fill: 'none',
          stroke: color,
          strokeWidth: 1.8,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
          'aria-hidden': 'true',
        },
        h('path', { key: 'a', d: 'M12 3 4 6.5v5c0 4.6 3.4 8.3 8 9.5 4.6-1.2 8-4.9 8-9.5v-5L12 3z' }),
        h('path', { key: 'b', d: 'M9 12h6' }),
        h('path', { key: 'c', d: 'M12 9v6' }));
      }

      function TermsSection() {
        const [terms, setTerms] = useState([]);
        const [draft, setDraft] = useState('');
        const [status, setStatus] = useState('');
        const [error, setError] = useState('');
        const [busy, setBusy] = useState(false);
        const [meta, setMeta] = useState({ file: '', maxTerms: 500, maxTermLength: 200 });

        const load = useCallback(async () => {
          setStatus(t('loading'));
          try {
            const body = await apiRequest(API_LIST);
            setTerms(Array.isArray(body.terms) ? body.terms : []);
            setMeta({
              file: String(body.file ?? ''),
              maxTerms: Number(body.maxTerms ?? 500),
              maxTermLength: Number(body.maxTermLength ?? 200),
            });
            setStatus('');
            setError('');
          } catch (err) {
            setError(`${t('load.failed')}: ${err instanceof Error ? err.message : String(err)}`);
            setStatus('');
          }
        }, []);

        useEffect(() => {
          load();
        }, [load]);

        function addTerm() {
          const term = draft.trim();
          if (!term) {
            setError(t('term.empty'));
            return;
          }
          if (term.length > meta.maxTermLength) {
            setError(t('term.tooLong'));
            return;
          }
          if (terms.includes(term)) {
            setError(t('term.duplicate'));
            return;
          }
          if (terms.length >= meta.maxTerms) {
            setError(t('term.limit'));
            return;
          }
          setTerms((prev) => [...prev, term]);
          setDraft('');
          setError('');
        }

        function removeTerm(term) {
          setTerms((prev) => prev.filter((item) => item !== term));
          setError('');
        }

        async function save() {
          setBusy(true);
          setStatus(t('saving'));
          try {
            const body = await apiRequest(API_SAVE, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ terms }),
            });
            setTerms(Array.isArray(body.terms) ? body.terms : terms);
            setStatus(t('saved'));
            setError('');
          } catch (err) {
            setError(`${t('save.failed')}: ${err instanceof Error ? err.message : String(err)}`);
            setStatus('');
          } finally {
            setBusy(false);
          }
        }

        const onKeyDown = (event) => {
          if (event.key === 'Enter') {
            event.preventDefault();
            addTerm();
          }
        };

        return h('div', { className: 'pii-terms' },
          h('h3', { key: 'title', className: 'pii-terms__title' }, t('title')),
          h('p', { key: 'intro', className: 'pii-terms__intro' }, t('intro')),
          h('div', { key: 'input-row', className: 'pii-terms__row' },
            h('input', {
              key: 'input',
              className: 'pii-terms__input',
              type: 'text',
              value: draft,
              placeholder: t('placeholder'),
              onChange: (event) => setDraft(event.target.value),
              onKeyDown,
            }),
            h('button', {
              key: 'add',
              type: 'button',
              className: 'pii-terms__btn',
              onClick: addTerm,
            }, t('add'))),
          h('div', { key: 'list', className: 'pii-terms__list' },
            terms.length === 0
              ? h('p', { key: 'empty', className: 'pii-terms__empty' }, t('empty'))
              : terms.map((term) => h('span', { key: term, className: 'pii-terms__chip' },
                h('span', { key: 'label' }, term),
                h('button', {
                  key: 'remove',
                  type: 'button',
                  title: t('remove'),
                  'aria-label': t('remove'),
                  onClick: () => removeTerm(term),
                }, '×')))),
          h('div', { key: 'meta', className: 'pii-terms__meta' },
            h('span', { key: 'count' }, `${t('count')}: ${terms.length}/${meta.maxTerms}`),
            meta.file ? h('span', { key: 'file' }, `${t('file.label')}: `, h('code', null, meta.file)) : null),
          h('div', { key: 'actions', className: 'pii-terms__row' },
            h('button', {
              key: 'save',
              type: 'button',
              className: 'pii-terms__btn pii-terms__btn--primary',
              disabled: busy,
              onClick: save,
            }, t('save')),
            status ? h('span', {
              key: 'status',
              className: 'pii-terms__status pii-terms__status--ok',
            }, status) : null,
            error ? h('span', {
              key: 'error',
              className: 'pii-terms__status pii-terms__status--error',
            }, error) : null));
      }

      function SettingsSection() {
        const [settings, setSettings] = useState({
          displayMode: 'full',
          failOpen: false,
          shellDisabled: false,
          shellAllowlist: '',
        });
        const [status, setStatus] = useState('');
        const [error, setError] = useState('');
        const [busy, setBusy] = useState(false);

        const load = useCallback(async () => {
          try {
            const body = await apiRequest(API_SETTINGS);
            const s = body?.settings ?? {};
            setSettings({
              displayMode: ['full', 'mask', 'off'].includes(s.displayMode) ? s.displayMode : 'full',
              failOpen: Boolean(s.failOpen),
              shellDisabled: Boolean(s.shellDisabled),
              shellAllowlist: String(s.shellAllowlist ?? ''),
            });
            setError('');
          } catch (err) {
            setError(`${t('load.failed')}: ${err instanceof Error ? err.message : String(err)}`);
          }
        }, []);

        useEffect(() => {
          load();
        }, [load]);

        const setField = (key, value) => {
          setSettings((prev) => ({ ...prev, [key]: value }));
          setStatus('');
          setError('');
        };

        async function save() {
          if (settings.shellAllowlist) {
            try {
              new RegExp(settings.shellAllowlist);
            } catch {
              setError(t('settings.invalidRegex'));
              return;
            }
          }
          setBusy(true);
          setStatus('');
          try {
            const body = await apiRequest(API_SETTINGS_SAVE, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ settings }),
            });
            const s = body?.settings ?? settings;
            setSettings({
              displayMode: s.displayMode ?? settings.displayMode,
              failOpen: Boolean(s.failOpen),
              shellDisabled: Boolean(s.shellDisabled),
              shellAllowlist: String(s.shellAllowlist ?? settings.shellAllowlist),
            });
            setStatus(t('settings.saved'));
            setError('');
          } catch (err) {
            setError(`${t('save.failed')}: ${err instanceof Error ? err.message : String(err)}`);
          } finally {
            setBusy(false);
          }
        }

        return h('div', { className: 'pii-settings' },
          h('h3', { key: 'title', className: 'pii-settings__title' }, t('settings.title')),
          h('p', { key: 'intro', className: 'pii-settings__intro' }, t('settings.intro')),
          h('div', { key: 'display', className: 'pii-settings__field' },
            h('label', { key: 'label', className: 'pii-settings__label' }, t('display.label')),
            h('span', { key: 'hint', className: 'pii-settings__hint' }, t('display.hint')),
            h('select', {
              key: 'select',
              className: 'pii-settings__select',
              value: settings.displayMode,
              onChange: (event) => setField('displayMode', event.target.value),
            },
            h('option', { key: 'full', value: 'full' }, t('display.full')),
            h('option', { key: 'mask', value: 'mask' }, t('display.mask')),
            h('option', { key: 'off', value: 'off' }, t('display.off')))),
          h('div', { key: 'failOpen', className: 'pii-settings__field' },
            h('label', { key: 'label', className: 'pii-settings__checkrow' },
              h('input', {
                key: 'check',
                type: 'checkbox',
                checked: settings.failOpen,
                onChange: (event) => setField('failOpen', event.target.checked),
              }),
              t('failOpen.label')),
            h('span', { key: 'hint', className: 'pii-settings__hint' }, t('failOpen.hint')),
            settings.failOpen ? h('span', { key: 'warn', className: 'pii-settings__warn' }, t('failOpen.warn')) : null),
          h('div', { key: 'shellDisabled', className: 'pii-settings__field' },
            h('label', { key: 'label', className: 'pii-settings__checkrow' },
              h('input', {
                key: 'check',
                type: 'checkbox',
                checked: settings.shellDisabled,
                onChange: (event) => setField('shellDisabled', event.target.checked),
              }),
              t('shellDisabled.label')),
            h('span', { key: 'hint', className: 'pii-settings__hint' }, t('shellDisabled.hint'))),
          h('div', { key: 'shellAllowlist', className: 'pii-settings__field' },
            h('label', { key: 'label', className: 'pii-settings__label' }, t('shellAllowlist.label')),
            h('span', { key: 'hint', className: 'pii-settings__hint' }, t('shellAllowlist.hint')),
            h('input', {
              key: 'input',
              className: 'pii-terms__input',
              type: 'text',
              value: settings.shellAllowlist,
              placeholder: t('shellAllowlist.placeholder'),
              onChange: (event) => setField('shellAllowlist', event.target.value),
            })),
          h('div', { key: 'actions', className: 'pii-terms__row' },
            h('button', {
              key: 'save',
              type: 'button',
              className: 'pii-terms__btn pii-terms__btn--primary',
              disabled: busy,
              onClick: save,
            }, t('settings.save')),
            status ? h('span', {
              key: 'status',
              className: 'pii-terms__status pii-terms__status--ok',
            }, status) : null,
            error ? h('span', {
              key: 'error',
              className: 'pii-terms__status pii-terms__status--error',
            }, error) : null));
      }

      // 实体类型勾选 + 白名单路径：写 preset.json，Python 引擎按 mtime 热读。
      function PresetSection() {
        const [types, setTypes] = useState([]);
        const [known, setKnown] = useState([]);
        const [whitelistPath, setWhitelistPath] = useState('');
        const [status, setStatus] = useState('');
        const [error, setError] = useState('');
        const [busy, setBusy] = useState(false);

        const load = useCallback(async () => {
          try {
            const body = await apiRequest(API_PRESET);
            const p = body?.preset ?? {};
            setKnown(Array.isArray(p.knownEntityTypes) ? p.knownEntityTypes : []);
            setTypes(Array.isArray(p.entityTypes) ? p.entityTypes : []);
            setWhitelistPath(String(p.whitelistPath ?? ''));
            setError('');
          } catch (err) {
            setError(`${t('load.failed')}: ${err instanceof Error ? err.message : String(err)}`);
          }
        }, []);

        useEffect(() => {
          load();
        }, [load]);

        const toggle = (type) => {
          setTypes((prev) => (prev.includes(type) ? prev.filter((x) => x !== type) : [...prev, type]));
          setStatus('');
          setError('');
        };

        async function save() {
          setBusy(true);
          setStatus('');
          try {
            const body = await apiRequest(API_PRESET_SAVE, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ preset: { entityTypes: types, whitelistPath } }),
            });
            const p = body?.preset ?? {};
            setTypes(Array.isArray(p.entityTypes) ? p.entityTypes : types);
            setWhitelistPath(String(p.whitelistPath ?? ''));
            setStatus(t('preset.saved'));
            setError('');
          } catch (err) {
            setError(`${t('save.failed')}: ${err instanceof Error ? err.message : String(err)}`);
          } finally {
            setBusy(false);
          }
        }

        return h('div', { className: 'pii-settings' },
          h('h3', { key: 'title', className: 'pii-settings__title' }, t('preset.title')),
          h('p', { key: 'intro', className: 'pii-settings__intro' }, t('preset.intro')),
          h('div', { key: 'types', className: 'pii-settings__field' },
            h('label', { key: 'label', className: 'pii-settings__label' }, t('preset.typesLabel')),
            h('span', { key: 'hint', className: 'pii-settings__hint' }, t('preset.typesHint')),
            h('div', { key: 'grid', className: 'pii-preset__grid' },
              known.map((type) => h('label', { key: type, className: 'pii-settings__checkrow' },
                h('input', {
                  key: 'check',
                  type: 'checkbox',
                  checked: types.includes(type),
                  onChange: () => toggle(type),
                }),
                type))),
            h('div', { key: 'bulk', className: 'pii-terms__row' },
              h('button', {
                key: 'allOn',
                type: 'button',
                className: 'pii-terms__btn',
                onClick: () => { setTypes([...known]); setStatus(''); },
              }, t('preset.allOn')),
              h('button', {
                key: 'allOff',
                type: 'button',
                className: 'pii-terms__btn',
                onClick: () => { setTypes([]); setStatus(''); },
              }, t('preset.allOff')))),
          h('div', { key: 'whitelist', className: 'pii-settings__field' },
            h('label', { key: 'label', className: 'pii-settings__label' }, t('preset.whitelistLabel')),
            h('span', { key: 'hint', className: 'pii-settings__hint' }, t('preset.whitelistHint')),
            h('input', {
              key: 'input',
              className: 'pii-terms__input',
              type: 'text',
              value: whitelistPath,
              placeholder: t('preset.whitelistPlaceholder'),
              onChange: (event) => { setWhitelistPath(event.target.value); setStatus(''); setError(''); },
            })),
          h('div', { key: 'actions', className: 'pii-terms__row' },
            h('button', {
              key: 'save',
              type: 'button',
              className: 'pii-terms__btn pii-terms__btn--primary',
              disabled: busy,
              onClick: save,
            }, t('preset.save')),
            status ? h('span', {
              key: 'status',
              className: 'pii-terms__status pii-terms__status--ok',
            }, status) : null,
            error ? h('span', {
              key: 'error',
              className: 'pii-terms__status pii-terms__status--error',
            }, error) : null));
      }

      // 单一菜单：屏蔽词与防护配置在同一设置分区内分区渲染。
      function PiiGuardSection() {
        return h('div', { className: 'pii-guard' },
          h('div', { key: 'terms', className: 'pii-guard__panel' }, h(TermsSection)),
          h('div', { key: 'divider', className: 'pii-guard__divider' }),
          h('div', { key: 'preset', className: 'pii-guard__panel' }, h(PresetSection)),
          h('div', { key: 'divider2', className: 'pii-guard__divider' }),
          h('div', { key: 'settings', className: 'pii-guard__panel' }, h(SettingsSection)));
      }

      const exports = {};
      exports.inject = ['slots'];
      exports.apply = (ctx) => {
        installI18n(ctx);
        ctx.effect(() => {
          ensureStyle();
          return () => {};
        });
        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: SECTION_ID,
          order: 30,
          label: () => t('nav'),
          locale: NS,
        }, PiiGuardSection));
        ctx.slots.inject('settings.section.icon', () => ctx.slots.register({
          name: 'settings.section.icon',
          id: SECTION_ID,
          order: 30,
        }, TermsIcon));
      };
      return exports;
    },
  });
})();
