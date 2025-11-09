import express from 'express';
import { verifyToken } from '../middleware/auth.js';
import { db } from '../config/firebase-admin.js';
import axios from 'axios';

const router = express.Router();

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';

/**
 * Create HIPAA compliance analysis prompt
 */
function createHIPAAAnalysisPrompt(codebase, repoName = 'unknown') {
  return `You are an automated HIPAA Compliance Auditor for codebases. Your job is to **scan the entire repository** (files under REPO_ROOT) and return a structured, evidence-backed HIPAA readiness report. You **must not** modify any files. You **must not** access or output any real Protected Health Information (PHI). If sample data or environment contains PHI, treat it as sensitive and redact it; replace with synthetic placeholders. Use only the code and configuration files available in the repository and any metadata the runtime provides (file paths, commit history, CI config). If you need to verify an uncertain external vendor or service, list it as "requires manual verification" and provide instructions on what to verify and where.

SCOPE:

- Scan: all source files, infra-as-code (Terraform/CloudFormation), Dockerfiles, CI/CD pipelines (GitHub Actions/GitLab/Bitbucket), config files (.env, .yml, .json), package manifests (package.json, requirements.txt, go.mod), infra config (aws/*.tf, azure/*.bicep), Kubernetes manifests, playbooks, and README/security docs.

- Exclude/ignore: /node_modules, /vendor, build artifacts, .git directories.

- Do not attempt to decrypt secrets or fetch external systems.

OBJECTIVES (order of priority):

1. Identify PHI handling surfaces and classify them (ingest, store, transmit, display, log).

2. Evaluate Technical Safeguards: encryption at rest/in transit, auth, RBAC, MFA, session management, logging, tamper-resistance.

3. Evaluate Administrative Safeguards: documented policies, BAAs referenced in docs, training artifacts, role definitions, incident response artifacts.

4. Evaluate Physical/Infrastructure Safeguards: hosting provider config, storage controls, backups, key management references.

5. Evaluate DevOps & CI/CD: secrets in code, test data with PHI, environment segregation, automated scans, dependency vulnerabilities, deployment policies.

6. Produce prioritized remediation items (code changes, infra changes, process changes), with severity (Critical/High/Medium/Low), exact file locations, recommended code snippets/commands, and estimated effort (in hours).

7. Output machine-readable JSON (schema below) and a human summary.

CHECKLIST / RULES TO APPLY:

- Encryption at rest: check database config, S3/EBS encryption flags, libs using encryption, KMS usage.

- Encryption in transit: check HTTP endpoints, TLS enforcement in config, HSTS, secure cookie flags.

- Auth: check for OAuth, password hashing (bcrypt/Argon2), MFA requirement for admin roles, role definitions in code.

- Secrets: search for hardcoded secrets, API keys, private keys, .env files checked into repo, or credentials in CI logs.

- Logging: search for console.log / print statements and structured logging that may include PHI fields; check log redaction patterns.

- Data minimization & masking: check front-end templates/APIs for direct PHI exposure; check for use of identifiers vs PII.

- Audit logging: ensure access events are logged with user id, timestamp, action, resource.

- BAAs: search docs for vendor names (AWS, GCP, Twilio, SendGrid, Stripe, Okta) and whether repo has references to BAAs or privacy/terms docs. If vendor used and no BAA reference, flag.

- Backups & retention: look for backup config or lifecycle rules; retention policy notes.

- CI/CD: check for pipeline steps that publish artifacts to public repos, deploy from unreviewed branches, or run tests with production credentials.

- Third-party dependencies: list direct deps and flag those with known security issues (report package name & version — do not fetch external vulnerability DB; provide commands to run e.g., \`npm audit\`, \`pip-audit\`).

- Tests & environments: flag usage of production DB in tests or staging using real data. Ensure non-production environments use synthetic data.

- Infrastructure isolation: check network/security group references (open 0.0.0.0/0 on DB ports), public S3 buckets, and unauthenticated API endpoints.

- Tamper-resistance: identify WORM or immutability in logs/backups (if present).

- Documentation: check for security policies, incident response, training docs. If missing, mark administrative gap.

OUTPUT FORMAT:

Return a JSON object exactly matching the schema below. After JSON output, provide a plain-language executive summary (≤ 300 words) and a prioritized remediation list with code/infra examples. For each evidence item include file path + line numbers or snippet references. For any vendor, include explicit "BAA required: yes/no/unknown" and what to do next.

SAFETY:

- Redact any suspected PHI in your output. Represent redactions with the token "[REDACTED_PHI]". Do not print real SSNs, phone numbers, names or medical records.

**Codebase to Analyze:**

${codebase}

**IMPORTANT:** Return ONLY valid JSON matching this exact schema:

{
  "metadata": {
    "repo": "${repoName}",
    "scan_date": "${new Date().toISOString()}",
    "scanned_by": "scanara-ai-v1"
  },
  "scores": {
    "overall_score": 0.0,
    "technical_safeguards_score": 0.0,
    "administrative_safeguards_score": 0.0,
    "physical_safeguards_score": 0.0,
    "audit_coverage_score": 0.0,
    "encryption_coverage_percent": 0.0
  },
  "summary": {
    "top_issues_count": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "top_3_findings": [
      {
        "title": "",
        "severity": "",
        "description": "",
        "file_paths": [""],
        "line_refs": [""],
        "remediation": ""
      }
    ]
  },
  "detailed_findings": [
    {
      "id": "F-0001",
      "category": "encryption_at_rest",
      "severity": "critical",
      "description": "",
      "evidence": [
        {"file": "", "line_start": 0, "line_end": 0, "snippet": ""}
      ],
      "recommended_fix": {
        "type": "code/infra/process",
        "patch_example": "",
        "commands": [""],
        "estimated_hours": 0.0
      }
    }
  ],
  "metrics": {
    "mfa_coverage_percent": 0.0,
    "rbac_coverage_percent": 0.0,
    "secrets_in_code_count": 0,
    "baas_coverage_percent": 0.0,
    "log_redaction_coverage_percent": 0.0,
    "immutable_logs_enabled": false,
    "public_bucket_count": 0,
    "tls_enforced": true,
    "test_data_with_real_phi_count": 0,
    "ci_secrets_exposed_count": 0,
    "dependency_vulnerabilities_count": 0
  },
  "remediation_plan": [
    {
      "id": "R-0001",
      "title": "Example fix",
      "priority": "critical",
      "steps": ["step1", "step2"],
      "files_to_change": [""],
      "estimated_hours": 2.5
    }
  ],
  "actions_required": {
    "manual_verification": [
      {
        "issue_id": "F-XXXX",
        "action": "Verify BAA with SendGrid (or Paubox)",
        "how_to_verify": "Check account management console, request signed BAA PDF, store copy in secure compliance folder"
      }
    ]
  },
  "component_analysis": {
    "administrative_safeguards": {
      "status": "compliant/non_compliant/partial",
      "score": 0.0,
      "components": [
        {
          "name": "HIPAA Compliance Officer",
          "status": "compliant/non_compliant/not_found",
          "description": "Brief description of compliance status",
          "evidence": "What was found or missing",
          "remediation": "How to fix if non-compliant",
          "files": [""]
        },
        {
          "name": "Employee Training",
          "status": "compliant/non_compliant/not_found",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Access Control Policy",
          "status": "compliant/non_compliant/not_found",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Risk Analysis & Management",
          "status": "compliant/non_compliant/not_found",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Incident Response Plan",
          "status": "compliant/non_compliant/not_found",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Business Associate Agreements",
          "status": "compliant/non_compliant/not_found",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Audit Policy",
          "status": "compliant/non_compliant/not_found",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Data Retention & Disposal Policy",
          "status": "compliant/non_compliant/not_found",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Security Management Process",
          "status": "compliant/non_compliant/not_found",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        }
      ]
    },
    "technical_safeguards": {
      "status": "compliant/non_compliant/partial",
      "score": 0.0,
      "components": [
        {
          "name": "Encryption at Rest",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Encryption in Transit",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Unique User IDs",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Authentication",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Role-Based Access Control (RBAC)",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Multi-Factor Authentication (MFA)",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Audit Logging",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Data Integrity Verification",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Session Management",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Automatic Logout",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        }
      ]
    },
    "physical_safeguards": {
      "status": "compliant/non_compliant/partial",
      "score": 0.0,
      "components": [
        {
          "name": "Server Access Control",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Workstation Security",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Device & Media Control",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Backup Security",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        }
      ]
    },
    "data_handling": {
      "status": "compliant/non_compliant/partial",
      "score": 0.0,
      "components": [
        {
          "name": "PHI in Logs",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "PHI in URLs",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Input Sanitization",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Secrets Management",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        },
        {
          "name": "Dependency Security",
          "status": "compliant/non_compliant/partial",
          "description": "",
          "evidence": "",
          "remediation": "",
          "files": [""]
        }
      ]
    }
  }
}

**Scoring Algorithm:**
Overall Score (0–100) = weighted sum:
- Technical Safeguards (45% of score)
- Administrative Safeguards (30%)
- Physical Safeguards (10%)
- Audit & Logging Coverage (10%)
- CI/CD & DevOps Hygiene (5%)

Compute each subscore (0–100) from binary and continuous checks. Round scores to 1 decimal place.

**CRITICAL: Component Analysis Requirement**
You MUST provide a detailed component_analysis section that evaluates EACH individual HIPAA component:

1. **Administrative Safeguards** - Evaluate all 9 components:
   - HIPAA Compliance Officer (check for designation in docs/code)
   - Employee Training (check for training logs, documentation)
   - Access Control Policy (check for RBAC implementation)
   - Risk Analysis & Management (check for risk assessment docs)
   - Incident Response Plan (check for incident response documentation)
   - Business Associate Agreements (check for BAA references)
   - Audit Policy (check for audit logging implementation)
   - Data Retention & Disposal Policy (check for retention policies)
   - Security Management Process (check for security documentation)

2. **Technical Safeguards** - Evaluate all 10 components:
   - Encryption at Rest (check database/config encryption)
   - Encryption in Transit (check TLS/HTTPS enforcement)
   - Unique User IDs (check for shared accounts)
   - Authentication (check OAuth/JWT implementation)
   - Role-Based Access Control (check RBAC implementation)
   - Multi-Factor Authentication (check MFA requirements)
   - Audit Logging (check for PHI access logging)
   - Data Integrity Verification (check for hash verification)
   - Session Management (check JWT expiration, CSRF)
   - Automatic Logout (check session timeout)

3. **Physical Safeguards** - Evaluate all 4 components:
   - Server Access Control (check cloud provider config)
   - Workstation Security (check endpoint security)
   - Device & Media Control (check removable storage policies)
   - Backup Security (check backup encryption)

4. **Data Handling** - Evaluate all 5 components:
   - PHI in Logs (check for PHI in console.log/print)
   - PHI in URLs (check for PHI exposure in URLs)
   - Input Sanitization (check XSS/SQL injection prevention)
   - Secrets Management (check for hardcoded secrets)
   - Dependency Security (check for vulnerable dependencies)

For EACH component, provide:
- status: "compliant" if fully compliant, "partial" if partially compliant, "non_compliant" or "not_found" if missing
- description: Brief explanation of current state
- evidence: What was found in the codebase (or what's missing)
- remediation: Step-by-step instructions on how to fix if non-compliant
- files: Array of file paths where issues were found or where fixes should be applied

Provide a comprehensive analysis focusing on actionable, specific issues with exact file paths and line numbers.`;
}

/**
 * POST /api/audit/run
 * Run HIPAA compliance audit on codebase
 */
router.post('/run', verifyToken, async (req, res) => {
  try {
    const { appId } = req.body;
    const userId = req.user.uid;

    if (!appId) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'appId is required'
      });
    }

    // Get app to verify ownership
    const appsRef = db.collection('apps');
    const appDoc = await appsRef.doc(appId).get();

    if (!appDoc.exists) {
      return res.status(404).json({
        error: 'Not found',
        message: 'App not found'
      });
    }

    const appData = appDoc.data();
    if (appData.userId !== userId) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have access to this app'
      });
    }

    // Get codebase from Firestore
    const codebaseId = appData.codebaseId;
    if (!codebaseId) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'No codebase found for this app. Please import a repository first.'
      });
    }

    const codebaseRef = db.collection('codebases');
    const codebaseDoc = await codebaseRef.doc(codebaseId).get();

    if (!codebaseDoc.exists) {
      return res.status(404).json({
        error: 'Not found',
        message: 'Codebase not found'
      });
    }

    const codebaseData = codebaseDoc.data();
    const files = codebaseData.files || [];

    if (files.length === 0) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'Codebase is empty'
      });
    }

    // Prepare codebase for analysis (limit to first 100 files to avoid token limits)
    const filesToAnalyze = files.slice(0, 100);
    const codebaseText = filesToAnalyze.map(file => {
      return `=== File: ${file.path} ===\n${file.content}\n`;
    }).join('\n\n');

    // Create audit record
    const auditRef = db.collection('audits');
    const auditDoc = await auditRef.add({
      appId: appId,
      userId: userId,
      status: 'running',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // Send to OpenAI for analysis
    try {
      const prompt = createHIPAAAnalysisPrompt(codebaseText, appData.name || 'unknown');

      const openaiResponse = await axios.post(
        OPENAI_API_URL,
        {
          model: 'gpt-4o-mini',
          messages: [
            {
              role: 'system',
              content: 'You are a HIPAA compliance expert. Analyze code and return structured JSON with compliance findings.'
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          temperature: 0.2,
          max_tokens: 8000,
          response_format: { type: 'json_object' }
        },
        {
          headers: {
            'Authorization': `Bearer ${OPENAI_API_KEY}`,
            'Content-Type': 'application/json'
          }
        }
      );

      let analysisResult;
      try {
        const content = openaiResponse.data.choices[0].message.content;
        // Extract JSON from response (handle cases where there's text before/after JSON)
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          analysisResult = JSON.parse(jsonMatch[0]);
        } else {
          throw new Error('No JSON found in OpenAI response');
        }
      } catch (parseError) {
        console.error('Error parsing OpenAI response:', parseError);
        throw new Error('Failed to parse analysis results');
      }

      // Determine compliance status based on overall score
      const overallScore = analysisResult.scores?.overall_score || 0;
      let complianceStatus = 'Non-Compliant';
      if (overallScore >= 80) {
        complianceStatus = 'Compliant';
      } else if (overallScore >= 60) {
        complianceStatus = 'Needs Attention';
      }

      // Update audit record with results (store full analysis)
      await auditRef.doc(auditDoc.id).update({
        status: 'completed',
        complianceScore: overallScore,
        complianceStatus: complianceStatus,
        // Store full analysis result
        metadata: analysisResult.metadata || {},
        scores: analysisResult.scores || {},
        summary: analysisResult.summary || {},
        detailedFindings: analysisResult.detailed_findings || [],
        metrics: analysisResult.metrics || {},
        remediationPlan: analysisResult.remediation_plan || [],
        actionsRequired: analysisResult.actions_required || {},
        componentAnalysis: analysisResult.component_analysis || {},
        // Legacy fields for backward compatibility
        findings: analysisResult.detailed_findings || [],
        categories: {
          technicalSafeguards: { score: analysisResult.scores?.technical_safeguards_score || 0 },
          administrativeSafeguards: { score: analysisResult.scores?.administrative_safeguards_score || 0 },
          physicalSafeguards: { score: analysisResult.scores?.physical_safeguards_score || 0 },
          auditCoverage: { score: analysisResult.scores?.audit_coverage_score || 0 }
        },
        updatedAt: new Date().toISOString(),
      });

      // Update app with latest audit
      await appsRef.doc(appId).update({
        latestAuditId: auditDoc.id,
        latestAuditScore: overallScore,
        updatedAt: new Date().toISOString(),
      });

      res.json({
        success: true,
        auditId: auditDoc.id,
        complianceScore: overallScore,
        status: complianceStatus,
        scores: analysisResult.scores || {},
        summary: analysisResult.summary || {},
        findings: analysisResult.detailed_findings || [],
        metrics: analysisResult.metrics || {},
        remediationPlan: analysisResult.remediation_plan || [],
        actionsRequired: analysisResult.actions_required || {},
        componentAnalysis: analysisResult.component_analysis || {},
        message: 'Audit completed successfully'
      });
    } catch (openaiError) {
      console.error('OpenAI API error:', openaiError);
      
      // Update audit record with error
      await auditRef.doc(auditDoc.id).update({
        status: 'failed',
        error: openaiError.message || 'Failed to analyze codebase',
        updatedAt: new Date().toISOString(),
      });

      throw new Error(`OpenAI API error: ${openaiError.message || 'Failed to analyze codebase'}`);
    }
  } catch (error) {
    console.error('Error running audit:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message || 'Failed to run audit'
    });
  }
});

/**
 * GET /api/audit/history/:appId
 * Get audit history for an app
 */
router.get('/history/:appId', verifyToken, async (req, res) => {
  try {
    const { appId } = req.params;
    const userId = req.user.uid;

    // Verify app ownership
    const appsRef = db.collection('apps');
    const appDoc = await appsRef.doc(appId).get();

    if (!appDoc.exists) {
      return res.status(404).json({
        error: 'Not found',
        message: 'App not found'
      });
    }

    const appData = appDoc.data();
    if (appData.userId !== userId) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have access to this app'
      });
    }

    // Get all audits for this app
    const auditsRef = db.collection('audits');
    const snapshot = await auditsRef.where('appId', '==', appId).get();

      const audits = [];
      snapshot.forEach((doc) => {
        const data = doc.data();
        audits.push({
          id: doc.id,
          complianceScore: data.complianceScore || 0,
          status: data.complianceStatus || data.status || 'Unknown',
          summary: data.summary || {},
          findings: data.detailedFindings || data.findings || [],
          scores: data.scores || {},
          metrics: data.metrics || {},
          remediationPlan: data.remediationPlan || [],
          actionsRequired: data.actionsRequired || {},
          componentAnalysis: data.componentAnalysis || {},
          categories: data.categories || {},
          createdAt: data.createdAt,
          updatedAt: data.updatedAt,
        });
      });

    // Sort by creation date (newest first)
    audits.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({
      success: true,
      audits: audits
    });
  } catch (error) {
    console.error('Error fetching audits:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message || 'Failed to fetch audits'
    });
  }
});

export default router;

