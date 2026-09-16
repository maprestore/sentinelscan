# Security Policy

## Intended use

SentinelScan is for defensive testing of systems you own or have explicit written authorization to assess.

## Reporting a scanner issue

If the scanner itself creates an unsafe request, bypasses a guardrail, or reports evidence incorrectly, open an issue with a minimal local reproduction. Do not include secrets, personal data, or an unapproved target URL.

## Scope boundary

This project deliberately does not implement exploitation, credential attacks, denial of service, SSRF probing, or authentication bypass. Contributions that add those capabilities will not be accepted into the safe default scanner.
