
# Securing Containerized Microservices

---

## Assignment Overview

In this assignment, you will assume the role of a **cybersecurity architect** tasked with securing a vulnerable containerized application. You will receive an intentionally insecure multi-service Python web app and must transform it into a secure deployment. The exercise includes environment setup, code remediation, threat modeling, security architecture design, and verification. Your deliverables will include a screen recording of your analysis and remediation process, along with a technical report.

---

## Assignment Instructions

### Part 1: Environment Setup

1. **Understand the Application:**
   - Review the Flask app in the `before/` directory.
   - Note common vulnerabilities such as hardcoded secrets, `eval()` usage, command injection, and insecure defaults.

2. **Run the Environment:**
   - Use `make start` to launch the application.
   - Test the endpoints: `/`, `/ping?ip=8.8.8.8`, and `/calculate?expr=2+3`.

3. **Initial Scanning:**
   - Run `make check`, `make scan`, and `make host-security`.
   - Record identified vulnerabilities and misconfigurations.

### Part 2: Secure the App and Container

1. **Code Remediation:**
   - Refactor `app.py` to:
     - Eliminate hardcoded passwords.
     - Replace `eval()` with `ast.literal_eval`.
     - Validate all inputs.
     - Restrict Flask to localhost.

2. **Docker Hardening:**
   - Use a minimal base image.
   - Ensure the app runs as a non-root user.
   - Add a `HEALTHCHECK` directive.
   - Implement multi-stage builds if possible.

3. **docker-compose.yml Improvements:**
   - Add `read_only`, `security_opt`, `mem_limit`, and `pids_limit`.
   - Restrict port exposure to `127.0.0.1`.
   - Use `.env` files for secret handling.

### Part 3: Threat Modeling

1. **Threat Model Documentation:**
   - Perform STRIDE analysis on the app.
   - Use MITRE ATT&CK for Containers to identify relevant techniques.
   - Create a table mapping vulnerabilities to controls (e.g., NIST 800-53).

2. **Save and Submit:**
   - Write results in `deliverables/threat_model.md`.

### Part 4: Security Architecture Implementation

1. **Architecture Design:**
   - Draft a diagram showing the hardened app infrastructure (use tools like Lucidchart or draw.io).
   - Save as `deliverables/architecture_diagram.png`.

2. **Auto-Hardening Script:**
   - Write a Python script (`docker_security_fixes.py`) to:
     - Update `daemon.json` with hardening flags.
     - Inject `USER`, `HEALTHCHECK`, and limits into Dockerfile and Compose.

### Part 5: Recording the Simulation

1. **Record Your Screen:**
   - Use OBS or QuickTime.
   - Include:
     - Initial scan and vulnerable app behavior.
     - Code and config remediation.
     - Threat model explanation.
     - Re-scans showing reduced vulnerabilities.

2. **Add Commentary:**
   - Use voiceover or annotations.
   - Describe what you are doing and why.

3. **Export:**
   - Save as MP4.

### Part 6: Summary Report

Write `deliverables/summary_report.md` (1–2 pages) including:
- Steps taken.
- Vulnerabilities found and fixed.
- Architecture and how it improves security.
- Reflection on lessons learned.

---

## Expectations

Students are expected to:
- Submit a screen recording (MP4) demonstrating the analysis, remediation, and verification process.
- Provide a link to publicly accessible GitHub repository with code and documentation.
- Ensure all deliverables are clear, well-organized, and professionally presented.
- Reflect critically on the security improvements and lessons learned.

---

## Grading Rubric

| Category                        | Excellent (90–100%)                                                  | Good (80–89%)                                              | Satisfactory (70–79%)                                      | Needs Improvement (60–69%)                                | Unsatisfactory (0–59%)                       |
|--------------------------------|------------------------------------------------------------------------|------------------------------------------------------------|------------------------------------------------------------|------------------------------------------------------------|----------------------------------------------|
| **Clarity & Organization**     | Clear, structured video/report with annotations and citations         | Mostly clear, minor issues                                 | Adequate, some structure missing                           | Unclear or disorganized                                  | Missing or unreadable                        |
| **Technical Depth**            | In-depth threat mapping, strong security fixes, MITRE alignment      | Mostly strong analysis and fixes                           | Satisfactory but shallow fixes and mapping                | Basic or incorrect fixes                               | No meaningful technical work                 |
| **Completeness of Simulation** | All stages completed, evidence of secure remediation                 | Most stages complete with small issues                     | Many steps complete, some missing or partially done        | Incomplete setup or remediation                        | Little to no simulation                      |
| **Recording Quality**          | Clear, audible, well-paced, detailed                                 | Mostly clear, minor issues                                | Adequate but basic or unclear explanations                | Low quality, poor narration                  | Not submitted or unusable                   |
| **Reflection & Reasoning**     | Insightful report, strong connection to SSDLC, DiD, etc.             | Clear report with basic insight                           | Simple report, shallow reasoning                          | Minimal insight or understanding                        | No reflection or insight                     |

