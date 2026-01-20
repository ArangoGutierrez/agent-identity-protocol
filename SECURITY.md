# Security Policy

The Agent Identity Protocol (AIP) is a security-critical project. We take vulnerability reports seriously and appreciate responsible disclosure.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :white_check_mark: (pre-release) |

During the pre-1.0 phase, security fixes will be applied to the `main` branch only.

## Reporting a Vulnerability

### DO NOT file a public GitHub issue for security vulnerabilities.

Instead, please report security issues through one of these channels:

### Option 1: GitHub Security Advisories (Preferred)

1. Go to the [Security Advisories page](https://github.com/ArangoGutierrez/agent-identity-protocol/security/advisories)
2. Click "Report a vulnerability"
3. Fill out the form with details

### Option 2: Email

Send details to: **arangogutierrez@gmail.com** (PGP key below)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested fixes (optional)

### PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[Key will be published upon project launch]
-----END PGP PUBLIC KEY BLOCK-----
```

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial Assessment | Within 7 days |
| Status Update | Every 14 days |
| Fix Development | Varies by severity |
| Public Disclosure | After fix is released |

## Severity Classification

We use CVSS v3.1 for severity scoring:

| Severity | CVSS Score | Response Target |
|----------|------------|-----------------|
| Critical | 9.0 - 10.0 | 24-48 hours |
| High | 7.0 - 8.9 | 7 days |
| Medium | 4.0 - 6.9 | 30 days |
| Low | 0.1 - 3.9 | 90 days |

## Scope

### In Scope

- AIP proxy implementation (`proxy/`)
- Client SDKs (`sdk/`)
- Manifest parsing and validation
- Identity token generation and validation
- Policy engine and authorization logic
- Egress filtering implementation
- Audit logging (data integrity)

### Out of Scope

- Example applications (`examples/`) — for demonstration only
- Documentation websites
- Third-party dependencies (report upstream)
- Theoretical attacks without proof of concept

## Security Considerations for AIP

When evaluating potential vulnerabilities, consider these AIP-specific concerns:

### High Priority
- **Manifest bypass**: Agent executing actions not declared in manifest
- **Token forgery**: Creating valid AIP tokens without authorization
- **Policy engine bypass**: Circumventing authorization checks
- **Audit log tampering**: Modifying or deleting audit records
- **Egress filter bypass**: Exfiltrating data despite restrictions

### Medium Priority
- **Privilege escalation**: Agent gaining capabilities beyond manifest scope
- **Session hijacking**: Taking over another agent's session
- **Denial of service**: Crashing proxy or exhausting resources
- **Information disclosure**: Leaking manifest contents or token data

### Lower Priority
- **Configuration issues**: Insecure defaults (should be documented)
- **Timing attacks**: Information leakage via response times
- **Verbose errors**: Stack traces or internal paths exposed

## Safe Harbor

We support security research conducted in good faith. Researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts you own or have explicit permission to test
- Do not exploit vulnerabilities beyond what is necessary to demonstrate them
- Report vulnerabilities promptly and do not disclose publicly until we've addressed them

...will not face legal action from us related to their research.

## Recognition

We maintain a [SECURITY_ACKNOWLEDGMENTS.md](SECURITY_ACKNOWLEDGMENTS.md) file to recognize researchers who responsibly disclose vulnerabilities.

## Contact

- **Security Reports**: arangogutierrez@gmail.com
- **General Questions**: GitHub Discussions
- **Urgent Issues**: Include "URGENT" in email subject

---

*This security policy is based on industry best practices and will be updated as the project matures.*
