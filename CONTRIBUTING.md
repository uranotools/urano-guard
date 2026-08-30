# Contributing to @uranotools/urano-guard

Thank you for your interest in contributing to **Urano Guard**! Together we are building the fastest, most resilient open-source AI firewall and threat inspection layer for APIs and intelligent agents.

---

## 📋 Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs & False Positives](#reporting-bugs--false-positives)
  - [Suggesting New Threat Inspectors](#suggesting-new-threat-inspectors)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Setup](#development-setup)
- [Creating a New Inspector](#creating-a-new-inspector)
- [Coding & Security Standards](#coding--security-standards)

---

## 📜 Code of Conduct
This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## 💡 How Can I Contribute?

### Reporting Bugs & False Positives
If a legitimate request is blocked (false positive) or an attack bypasses an inspector, please open an issue using the **Threat Rule / Bypass Report** template with:
- The sanitized payload structure
- The matched rule or inspector
- The expected verdict vs. actual verdict

### Suggesting New Threat Inspectors
Have a defense pattern for emerging LLM jailbreaks, GraphQL abuse, or serverless tampering? Create an issue under **New Inspector Proposal**.

---

## 🛠️ Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/uranotools/urano-guard.git
cd urano-guard

# 2. Install dependencies
npm install

# 3. Check types and lint
npm run typecheck
npm run lint

# 4. Tests
npm test

# 5. Build output
npm run build
```

---

## 🧩 Creating a New Inspector

All inspectors must inherit from `InspectorBase` in `src/inspectors/InspectorBase.ts`:

```ts
import { InspectorBase, GuardRequestContext, ThreatIncident } from '@uranotools/urano-guard';

export class CustomExploitInspector extends InspectorBase {
    readonly name = 'CustomExploitInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident | null {
        if (!this.enabled) return null;

        if (someVulnerabilityCheck(context.body)) {
            return {
                id: `thr_custom_${Date.now()}`,
                category: 'CUSTOM',
                severity: 'HIGH',
                riskScore: 80,
                summary: 'Detected custom exploit attempt',
                detectedAt: new Date().toISOString(),
                sender: context.senderId || context.ip
            };
        }

        return null;
    }
}
```

---

## 🔒 Security & Performance Guidelines
1. **Zero External Heavy Dependencies:** The core SDK must remain lightweight with minimal dependencies.
2. **Sub-millisecond Local Execution:** All local regex patterns must be optimized to prevent ReDoS (Regular Expression Denial of Service).
3. **Fail-Safe Design:** Always handle exceptions gracefully so unexpected inputs do not crash the host HTTP process.

---

## Releasing

1. Bump `version` in `package.json` (semver).
2. Add a section to [CHANGELOG.md](CHANGELOG.md).
3. `npm test`, `npm run lint`, `npm run build`.
4. Commit, tag `vX.Y.Z`, push the tag.
5. Create a **GitHub Release** for that tag — [publish.yml](.github/workflows/publish.yml) runs lint, tests, and `npm publish --access public --provenance`.

Do not publish from a local machine unless npm provenance is not required.
