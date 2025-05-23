# Threat Model: Secure Containerized Microservices

## 1. Overview
This document outlines the threat modeling exercise performed on the initial insecure application, following STRIDE and MITRE ATT&CK methodologies.

---

## 2. STRIDE Analysis

| Threat Category | Example | Impact | Mitigation |
|----------------|---------|--------|------------|
| Spoofing        | Lack of auth on `/calculate` | Unauthorized access | Add auth/token check |
| Tampering       | Unsafe IP input to `ping` | Command injection | Input validation |
| Repudiation     | No logging | Difficult to audit usage | Implement access logs |
| Information Disclosure | Hardcoded passwords | Credential leak | Use env variables |
| Denial of Service | Unrestricted `ping` or `eval` | Resource exhaustion | Rate limiting |
| Elevation of Privilege | Runs as root | Full system compromise | Use non-root user |

---

## 3. MITRE ATT&CK Mapping (Containers)

| Tactic         | Technique ID | Technique Name | Application Relevance |
|----------------|--------------|----------------|------------------------|
| Initial Access | T1190         | Exploit Public-Facing Application | Command injection in `/ping` |
| Execution      | T1059         | Command and Scripting Interpreter | Use of `eval()` |
| Persistence    | T1525         | Implant Container Image | No image signing or validation |
| Privilege Escalation | T1611  | Escape to Host | Root container user |
| Defense Evasion | T1211        | Exploitation for Defense Evasion | Lack of file system isolation |

---

## 4. Controls Mapping

| Issue | Recommended Control | Framework Reference |
|-------|---------------------|---------------------|
| Hardcoded secrets | Environment secrets | NIST 800-53: SC-12, SC-28 |
| Root container user | Add `USER appuser` | NIST 800-53: AC-6, CM-6 |
| No network restrictions | Isolate with Docker networks | NIST 800-53: SC-7 |
| Missing health check | Add `HEALTHCHECK` | CIS Docker Benchmark |
| Unvalidated inputs | Strict input validation | OWASP Top 10: A1-Injection |

---

## 5. Risk Rating Summary

| Threat | Risk | Likelihood | Impact | Mitigation Priority |
|--------|------|------------|--------|----------------------|
| Command Injection | High | High | Critical | Immediate |
| Credential Exposure | Medium | High | Medium | High |
| Eval-based execution | High | Medium | High | Immediate |
| Root user in container | High | Medium | Critical | Immediate |

---

## 6. Conclusion

This threat model identifies the major flaws in the system and informs the remediation and architecture redesign. The final implementation significantly reduces the attack surface and enforces least privilege, defense in depth, and secure defaults.

