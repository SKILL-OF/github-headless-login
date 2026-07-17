---
name: github-headless-login
description: Autonomous headless GitHub web login — submits credentials and TOTP 2FA via HTTP, issues a classic PAT, and pipes it to gh auth login. No browser, no human, no interactive prompt.
scope: any agent that needs to re-authenticate gh CLI to a GitHub account without human intervention
trigger: when gh CLI auth is expired or absent and a non-interactive PAT issuance is required
---

# github-headless-login

Performs a complete GitHub authentication cycle autonomously:

1. GET `/login` — fetch CSRF token
2. POST `/session` — submit username + password
3. POST `/sessions/two-factor` — submit TOTP code (`app_otp` field)
4. GET `/settings/tokens/new` — fetch PAT creation form (with sudo re-confirmation if needed)
5. POST `/settings/tokens` — submit PAT form, extract new token from response
6. Print PAT to stdout — caller pipes to `gh auth login --with-token`

## Usage

```bash
# Password on stdin; TOTP generated internally from vault
assemble-password.sh | python3 scripts/github-headless-login.py

# Full re-auth pipeline
assemble-password.sh | python3 scripts/github-headless-login.py | gh auth login --with-token
```

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `GITHUB_USERNAME` | `aurora-thesean` | Account to log in as |
| `GH_PAT_NAME` | `aurora-agent` | PAT description prefix (timestamp appended) |
| `GH_PAT_SCOPES` | `repo,gist,read:org,workflow` | Comma-separated scopes |
| `AGE_KEY` | `~/.aurora-agent/keys/totp-key.txt` | Forwarded to generate-totp.sh |
| `TOTP_VAULT` | `~/.aurora-agent/secrets/totp-encrypted.age` | Forwarded to generate-totp.sh |

Requires `SKILL-OF/card-key-derivation` installed alongside — calls `generate-totp.sh`
from the same `scripts/` directory to generate the TOTP code.

## Security properties

- Password read from stdin; never appears in a process cmdline or temp file
- TOTP generated via subprocess stdout; never passed as an argument
- Cookie jar is in-memory only (`http.cookiejar.CookieJar`); no cookies written to disk
- PAT written to stdout only; caller is responsible for consuming it securely
- No credentials written to disk at any point

## Known limitations

- Classic PATs only (fine-grained PATs use a different form structure)
- PAT name must be unique per account — script appends `YYYYMMDD-HHMM` to avoid collisions
- Depends on GitHub's web form structure; may need updates if GitHub changes their login UI
- Requires `oathtool` on PATH (via `SKILL-OF/card-key-derivation` dependency)

## Local install

```bash
gh repo clone SKILL-OF/github-headless-login ~/.local/lib/skills/github-headless-login
cp ~/.local/lib/skills/github-headless-login/SKILL.md \
   ~/.claude/skills/github-headless-login.skill.md
```
