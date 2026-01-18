#!/usr/bin/env python3
"""
A script to scan a codebase for sensitive information like API keys and passwords.

How to use:
1. Make the script executable:
   chmod +x check_secrets.py

2. Run the script:
   ./check_secrets.py

Automate with a pre-commit hook:
To automatically run this check before each commit, you can use a pre-commit hook.
This will prevent you from accidentally committing secrets.

1. Create the pre-commit hook file:
   touch .git/hooks/pre-commit
   chmod +x .git/hooks/pre-commit

2. Add the following content to the .git/hooks/pre-commit file:
   #!/bin/sh
   #
   # A hook script to prevent committing sensitive information.

   # Run the secret scanner
   ./check_secrets.py
   if [ $? -ne 0 ]; then
       echo "Error: Secrets found in the code. Aborting commit."
       exit 1
   fi

   exit 0
"""
import os
import re
import sys
import argparse
from pathlib import Path

# Regex patterns for common secrets, with masking replacements
SECRET_PATTERNS = {
    "API Key": (re.compile(r"(['\"]?api_key['\"]?\s*[:=]\s*['\"]?)(?P<secret>[a-zA-Z0-9\-_]{20,})(['\"]?)", re.IGNORECASE), r"\1***REDACTED***\3"),
    "Password": (re.compile(r"(['\"]?password['\"]?\s*[:=]\s*['\"]?)(?P<secret>.{8,})(['\"]?)", re.IGNORECASE), r"\1***REDACTED***\3"),
    "Private Key": (re.compile(r"-----BEGIN [A-Z]+ PRIVATE KEY-----"), "***REDACTED PRIVATE KEY***"),
    "GitHub Token": (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "***REDACTED GITHUB TOKEN***"),
    "AWS Access Key": (re.compile(r"AKIA[0-9A-Z]{16}"), "***REDACTED AWS ACCESS KEY***"),
    "AWS Secret Key": (re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), "***REDACTED AWS SECRET KEY***"),
}

def get_gitignore_patterns(path: Path) -> list[str]:
    """Reads .gitignore and returns a list of glob patterns."""
    gitignore_path = path / ".gitignore"
    if not gitignore_path.exists():
        return []
    patterns = []
    with open(gitignore_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith('/'):
                patterns.append(line + '**')
                patterns.append(line[:-1])
            else:
                patterns.append(line)
    return patterns

def is_ignored(path: Path, gitignore_patterns: list[str]) -> bool:
    """Checks if a file should be ignored based on .gitignore patterns."""
    for pattern in gitignore_patterns:
        try:
            if path.match(pattern):
                return True
        except Exception:
            # Ignore invalid patterns
            pass
    return False

def scan_file(file_path: Path) -> list[tuple[int, str, str]]:
    """Scans a single file for secrets and returns masked findings."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                original_line = line.strip()
                masked_line = original_line
                found_types = []
                for secret_type, (pattern, replacement) in SECRET_PATTERNS.items():
                    if pattern.search(masked_line):
                        found_types.append(secret_type)
                        masked_line = pattern.sub(replacement, masked_line)
                
                if found_types:
                    findings.append((i, ", ".join(found_types), masked_line))
    except (UnicodeDecodeError, IOError):
        # Ignore files that can't be read as text
        pass
    return findings

def main():
    """Main function to scan the codebase."""
    parser = argparse.ArgumentParser(description="Scan codebase for sensitive information.")
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="The directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Always exit with 0, even if secrets are found.",
    )
    args = parser.parse_args()

    script_path = Path(__file__).resolve()
    scan_dir = Path(args.directory).resolve()
    gitignore_patterns = get_gitignore_patterns(scan_dir)
    found_secrets = False
    all_findings = []

    print(f"Scanning directory: {scan_dir}")

    for root, dirs, files in os.walk(scan_dir, topdown=True):
        # Exclude ignored directories from further traversal
        dirs[:] = [d for d in dirs if not is_ignored(Path(root) / d, gitignore_patterns)]

        for file in files:
            file_path = Path(root) / file

            # Ignore the scanner script itself
            if file_path == script_path:
                continue

            if is_ignored(file_path, gitignore_patterns) or not file_path.is_file():
                continue

            findings = scan_file(file_path)
            if findings:
                found_secrets = True
                all_findings.append((file_path, findings))

    if found_secrets:
        print("\n[!] Secrets found!")
        for file_path, findings in all_findings:
            print(f"\nFile: {file_path}")
            for line_num, secret_type, masked_line in findings:
                print(f"  - Line {line_num} ({secret_type}): {masked_line}")
        
        if args.force:
            sys.exit(0)

        # Prompt to continue only in interactive mode
        if sys.stdin.isatty():
            choice = input("\nDo you want to continue with the commit? (y/N) ").lower().strip()
            if choice == 'y':
                print("Continuing with commit...")
                sys.exit(0)

        print("\nAborting commit.")
        sys.exit(1)
    else:
        print("\nNo secrets found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
