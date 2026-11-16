/**
 * Browser half of dsh-pii-guard-terms.
 *
 * Registers a settings page (`settings.section`) where the user can add, remove
 * and save the terms that must be redacted before prompts leave the harness.
 * The page talks to the Host half over two JSON routes:
 *
 *   GET  /api/dsh-pii-guard/terms        -> list terms
 *   POST /api/dsh-pii-guard/terms/save   -> replace the term list
 *
 * The host matches routes by pathname only, so the URLs are absolute.
 */
(function bootstrap() {
  const MODULE_ID = 'dsh-pii-guard-terms';
  const NS = 'settings.piiGuardTerms';
  const API_LIST = '/api/dsh-pii-guard/terms';
  const API_SAVE = '/api/dsh-pii-guard/terms/save';
  const SECTION_ID = 'pii-guard-terms';

  const I18N_ZH = {
    nav: 'PII 屏蔽词',
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
  };

  const I18N_EN = {
    nav: 'PII blocklist',
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
  };

  const CSS = [
    '.pii-terms { display: flex; flex-direction: column; gap: 12px; padding: 16px 18px;',
    '  font-family: var(--dsw-font-family, inherit); color: var(--dsw-alias-label-primary); }',
    '.pii-terms__title { font-size: 15px; font-weight: 600; margin: 0; }',
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
          h('h2', { key: 'title', className: 'pii-terms__title' }, t('title')),
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
        }, TermsSection));
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
