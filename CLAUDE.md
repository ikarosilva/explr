# Security Rules

NEVER display, cat, echo, read, or print the contents of files that may contain secrets, including:
- ~/.git-credentials
- .env files
- .env.local, .env.production, .env.* files
- **/credentials/**
- **/*token*
- **/*secret*
- *.pem, *.key files
- ~/.ssh/id_* (private keys)
- ~/.netrc
- ~/.aws/credentials
- **/*password*
- config files containing API keys

When checking these files:
- Only verify they exist using `test -f` or `ls`
- Check file format or line count without showing content
- Never use cat, head, tail, less, more, or Read tool on these files
- If you need to verify content, describe what to look for and let the user check manually

# Pre-Commit Safety Check

When the user asks to check code before committing (or uses phrases like "check before commit", "safe to commit", "review for commit"):

1. Run `git status` to see all staged and untracked files
2. Read each new or modified file that will be committed
3. Check for sensitive information:
   - API keys, tokens, secrets
   - Passwords or credentials
   - Private keys or certificates
   - Personal information (emails, names, addresses)
   - Hardcoded internal URLs or IPs
   - Database connection strings with credentials
4. Report findings in a table format:
   | File | Status | Safe? | Notes |
5. Give a clear ✅ Safe or ❌ Not Safe verdict
