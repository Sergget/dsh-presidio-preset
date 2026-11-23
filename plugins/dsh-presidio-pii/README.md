# dsh-presidio-pii

Unified DeepSeek Harness (DSH) bundle combining:

- **Agent Preset (`preset-presidio-pii`)**: narrow-surface PII protection mode (`read_redacted` / `write_raw` / `restore` / `ls`, plus runtime redaction guard and `presidio-pii` skill).
- **Runtime Guard (`dsh-presidio-pii/guard`)**: intercepts `tools/post-execute`, wraps write tools on `agent/created`, hides `read_image`, and restores placeholders on `agent/assistant-stream`.
- **Safe FS Tools (`dsh-presidio-pii/fs`)**: `read_redacted`, `write_raw`, `restore`, `ls` backed by the bundled Node PII engine (`node_pii/`).
- **Host Settings API & Web UI (`dsh-presidio-pii`, `./client`)**: `/api/dsh-pii-guard/{terms,settings,preset}` routes and the `PII 防护` settings section.

## Path Resolution

- Static package resources (`node_pii/`, `assets/`, `rule_libraries/`, `skills/`, `defaults/preset.json`) are resolved relative to the installed package via `import.meta.url`.
- Runtime user data (`sessions.db`, `hook_log.jsonl`, `guard-settings.json`, `user_terms_rules.json`, `preset.json`) defaults to `$DSH_HOME/data/presidio-pii` via `dshHomePath('data', 'presidio-pii')` (or `config.dataDir`, `config.repo`, `PII_GUARD_DATA_DIR`, `PII_GUARD_REPO`).
