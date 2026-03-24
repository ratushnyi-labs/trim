# Security Policy

## Reporting a Vulnerability

If you find a security issue in trim (e.g., a crafted binary that causes a crash, buffer overflow, or incorrect code removal), please report it responsibly:

1. **Do NOT open a public issue** for security vulnerabilities
2. Email: open a private security advisory via GitHub's [Security Advisories](https://github.com/ratushnyi-labs/trim/security/advisories/new)

We will respond within 48 hours and aim to release a fix within 7 days.

## Scope

trim processes untrusted binary files. The following are in scope:

- **Panics/crashes** on malformed input (any format)
- **Buffer overflows** or out-of-bounds reads from crafted binaries
- **False positives** — live code incorrectly identified as dead (critical: causes broken binaries)
- **Integer overflows** in offset/size calculations from binary metadata

The following are out of scope:

- Slow performance on very large binaries (denial of service via resource exhaustion)
- Issues requiring physical access to the machine

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |
