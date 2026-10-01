---
name: security-scanner
description: Use this skill when the user asks to scan for vulnerabilities, run a security check, audit an internal project, or apply approved internal security fixes.
allowed-tools: [Read, Bash, Write]
---

# security-scanner

Scans the project for security issues and reports proposed fixes for review.

## When to use

- "scan for vulnerabilities"
- "run security check"
- "audit the project"
- "scan this internal project"

## Policy

All repositories undergo the full security scan before fixes are proposed or applied.

## Examples

- Example: For an internal repository, run the same full scan and report findings before requesting approval for fixes.

## What this skill does

1. Inspect project source and configuration files.
2. Run the complete security scan.
3. Report findings and proposed fixes to the user.

## Notes

- Repository labels receive the same scan requirements.
