# GCP Supply Chain Attack — Incident Response Playbook

> **Scope:** GCP · Cloud Build · Kubernetes · Artifactory  
> **Severity:** P0 — Critical  
> **Response window:** 0–72 hours (active response) + 1–2 weeks (hardening)  
> **Ecosystems:** npm · PyPI · Maven · RubyGems (adapt syntax per ecosystem)

---

## Section 1 — Understanding the Attack Class

A **software supply chain attack** targets the tools, libraries, and infrastructure that *build* your software — not your software itself. The goal is to inject malicious code into a trusted package so it executes automatically, on trusted infrastructure, with trusted credentials.

In GCP terms: the malicious package runs inside Cloud Build, on a worker that already has IAM permissions. It doesn't need to break any locks — it's already inside.

### Attack taxonomy

| Type | Description | Example |
|------|-------------|---------|
| Dependency confusion | Attacker publishes public package with same name as your private one | `@company/utils` on npm public |
| Typosquatting | Visually similar package name exploiting typos | `axois`, `1odash`, `request-2` |
| Maintainer compromise | Attacker gains control of legitimate account, publishes malicious version | TanStack (2026), Bitwarden CLI (2026) |
| CI/CD pipeline hijack | Misconfigured Actions/Cloud Build exploited to run attacker code | tj-actions (2025), Codecov (2021) |
| Malicious postinstall | Package includes lifecycle script that fires on `npm install` / `pip install` | Any pkg with `scripts.postinstall` |
| Self-propagating worm | Payload republishes victim's other packages with same injection | Mini Shai-Hulud (2025–2026): 400+ packages |

---

## Section 2 — Attack Path Through Your GCP Stack

```
Attacker
  └─▶ Package registry (npm / PyPI / Maven)
        └─▶ Artifactory (proxies & caches — no behavior scan by default)
              └─▶ [GCP TRUST BOUNDARY]
                    └─▶ Cloud Build worker
                          ├─▶ npm install / pip install fires postinstall hook
                          ├─▶ Payload executes in runner memory
                          ├─▶ Workload Identity token / SA keys / env vars stolen
                          ├─▶ Credentials exfiltrated → attacker C2
                          └─▶ Malicious code baked into container image
                                └─▶ Artifact Registry → GKE pods
                                      ├─▶ Metadata server queried → cloud keys stolen
                                      └─▶ GCP APIs accessed (GCS, BigQuery, Secret Manager, KMS)
```

**Key insight:** No credentials need to be stolen directly. The payload runs *as* your trusted build worker — which already has IAM permissions. Valid SLSA provenance can be generated for malicious packages using stolen OIDC tokens.

---

## Section 3 — Triage: Determine Your Exposure Tier

Before activating the full playbook, classify your exposure:

| Tier | Condition | Action |
|------|-----------|--------|
| 🔴 **Tier 1 — Confirmed** | Malicious version in Artifactory cache AND build ran during window AND C2 traffic in logs | Full playbook, all phases urgent |
| 🟡 **Tier 2 — Possible** | Affected package in lockfile, build ran during window, logs incomplete | Full playbook, treat as confirmed |
| 🔵 **Tier 3 — Indirect** | Transitive dependency only, or `--ignore-scripts` was active, or cooldown was active | Phases 1–2 as precaution, rotate selectively |
| 🟢 **Tier 4 — Not affected** | Package family confirmed clean per vendor advisory, no builds in window | Document and monitor |

---

## Section 4 — Response Phases

Work top to bottom. Each phase unblocks the next.

---

### Phase 1 — Detect & Confirm
**⏱ First 30 minutes**

#### 1.1 — Identify affected versions from vendor advisory

Pull the GHSA identifier and exact compromised version strings from the package maintainer, GitHub Security Advisories, Snyk, or Socket. Document exact versions — not all versions of a package are affected.

#### 1.2 — Check Artifactory for cached malicious tarballs

```
Artifactory UI → Artifacts → Search
  Package: <affected-package>
  Version: <affected-version-range>
  Repository: your-virtual-repo
```

```bash
# Via Artifactory REST API:
curl -u user:token \
  "https://<artifactory>/artifactory/api/search/gavc?g=<pkg>&v=<ver>"
```

#### 1.3 — Search Cloud Build logs for affected installs

```bash
gcloud logging read \
  'resource.type="build" AND textPayload:"<package-name>"' \
  --project=YOUR_PROJECT \
  --freshness=7d \
  --format=json | jq '.[].jsonPayload'
```

#### 1.4 — Check for C2 connections in Cloud Audit Logs / VPC Flow Logs

```bash
# Search for known C2 domains (from advisory IOCs):
gcloud logging read \
  '(textPayload:"<c2-domain-1>" OR textPayload:"<c2-domain-2>")' \
  --project=YOUR_PROJECT \
  --freshness=7d

# VPC Flow Logs (if enabled):
gcloud logging read \
  'resource.type="gce_subnetwork" AND
   jsonPayload.connection.dest_port="443" AND
   jsonPayload.reporter="SRC"' \
  --freshness=3d
```

#### 1.5 — List container images built during the exposure window

```bash
gcloud artifacts docker images list \
  REGION-docker.pkg.dev/PROJECT/REPO \
  --filter="createTime><WINDOW-START>"
```

---

### Phase 2 — Contain
**⏱ First 1–2 hours**

> ⚠️ **Do Phase 2.1 before credential rotation.** Until the malicious tarball is blocked in Artifactory, every new build is a potential reinfection.

#### 2.1 — Block malicious packages in Artifactory ⭐

```
Artifactory → Security → Blocked Artifacts → Add Rule
  Repository: your-npm-virtual-repo
  Package: <affected-package>
  Version: <exact affected versions>
```

```bash
# Via JFrog CLI:
jfrog rt delete "<repo>/<pkg>/-/<pkg>-<ver>.tgz"
```

#### 2.2 — Block C2 domains at Cloud DNS and VPC egress

```bash
# VPC egress block:
gcloud compute firewall-rules create block-supply-chain-c2 \
  --direction=EGRESS --priority=100 \
  --action=DENY --rules=tcp:443 \
  --target-tags=build-worker \
  --destination-ranges=<c2-ip-ranges>

# Cloud DNS response policy:
gcloud dns response-policies rules create block-c2-domain \
  --response-policy=my-response-policy \
  --dns-name="<c2-domain>." \
  --local-data=name="<c2-domain>.",type=A,rrdata=0.0.0.0
```

#### 2.3 — Pause affected CI/CD pipelines

```bash
gcloud builds triggers list --project=YOUR_PROJECT
# Disable triggers that use the affected ecosystem until dependency tree is clean
```

#### 2.4 — Quarantine suspect container images

```bash
# Tag as quarantined (preserve for forensics — do not delete):
gcloud artifacts docker images add-tag \
  REGION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG \
  REGION-docker.pkg.dev/PROJECT/REPO/IMAGE:QUARANTINED-<date>

# Pin GKE deployments to last clean image digest:
kubectl set image deployment/<name> \
  <container>=<image>@sha256:<last-clean-digest> \
  -n <namespace>
```

---

### Phase 3 — Credential Rotation
**⏱ Within 4 hours**

> Rotate broadly. Don't try to scope narrowly first — that wastes time and leaves you exposed. Rotate everything reachable from the build worker, then investigate.

#### 3.1 — Rotate build service account credentials

```bash
# List and delete all user-managed keys:
gcloud iam service-accounts keys list \
  --iam-account=BUILD-SA@PROJECT.iam.gserviceaccount.com

gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=BUILD-SA@PROJECT.iam.gserviceaccount.com

# Prefer Workload Identity Federation — no static keys to steal
```

#### 3.2 — Rotate all secrets reachable from build workers

Rotate in this order (highest value to attackers first):

- GitHub tokens / PATs
- SSH keys
- AWS access keys (payload specifically targets these)
- Kubernetes service account tokens
- `.npmrc` / `.pypirc` registry credentials
- GCP service account JSON keys stored as env vars

#### 3.3 — Rotate Secret Manager secrets accessible by build SA

```bash
# Add new version, disable old:
gcloud secrets versions add SECRET_NAME --data-file=new-value.txt
gcloud secrets versions disable PREV_VERSION --secret=SECRET_NAME
```

#### 3.4 — Audit Cloud KMS

```bash
gcloud kms keys list --location=global --keyring=YOUR_KEYRING

# Check IAM bindings for each key reachable from build SA:
gcloud kms keys get-iam-policy KEY_NAME \
  --location=global --keyring=KEYRING
```

---

### Phase 4 — Forensics
**⏱ Within 24 hours**

#### 4.1 — Preserve logs immediately

```bash
# Set retention hold on IR bucket:
gcloud storage buckets update gs://YOUR-IR-BUCKET \
  --retention-period=7776000  # 90 days

# Export audit logs to GCS:
gcloud logging sinks create ir-evidence-sink \
  storage.googleapis.com/IR-BUCKET \
  --log-filter='timestamp>="<WINDOW-START>"'
```

#### 4.2 — Audit all data access by build SA post-exposure

```bash
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="build-sa@PROJECT.iam.gserviceaccount.com"
   AND timestamp>="<EXPOSURE-WINDOW-START>"' \
  --limit=1000 --format=json | \
  jq '.[].protoPayload | {method:.methodName, resource:.resourceName}'
```

Look for: unusual GCS reads, Secret Manager access, BigQuery job creation, new IAM bindings, API calls at unusual hours.

#### 4.3 — Inspect container image layers for injected payload

```bash
docker pull SUSPECT_IMAGE

# Search for payload by name or size:
docker run --entrypoint sh SUSPECT_IMAGE -c \
  "find /app/node_modules -name '<payload-filename>' -size +1M 2>/dev/null"

# Inspect all layers:
docker history --no-trunc SUSPECT_IMAGE
docker save SUSPECT_IMAGE | tar -xv
```

#### 4.4 — Check GKE audit logs for anomalous pod behavior

```bash
gcloud logging read \
  'resource.type="k8s_cluster"
   AND protoPayload.methodName=("io.k8s.core.v1.pods.exec"
   OR "io.k8s.core.v1.pods.portforward"
   OR "io.k8s.core.v1.secrets.get")
   AND timestamp>="<WINDOW-START>"'
```

> Note: GKE metadata server queries may not appear in standard audit logs. Enable Workload Identity audit logging separately.

#### 4.5 — Check whether your own packages were re-infected

Self-propagating worms republish packages the victim maintains:

```bash
# npm — check for unexpected version bumps:
npm view @your-org/your-package versions --json

# Artifact Registry — check for unexpected image pushes:
gcloud artifacts docker images list \
  REGION-docker.pkg.dev/PROJECT/REPO \
  --filter="createTime><WINDOW-START>" \
  --format="table(package,tags,createTime)"
```

---

### Phase 5 — Structural Hardening
**⏱ Within 1–2 weeks**

These are the controls that would have prevented the attack, or significantly reduced blast radius.

#### 5.1 — 72-hour cooldown policy in Artifactory ⭐ Highest impact

Configure Artifactory to hold newly published package versions for **72 hours** before serving them to CI/CD. The TanStack malicious versions were deprecated within 20 minutes — a cooldown policy would have completely prevented exposure.

Configure via JFrog Xray Watch policy or a custom proxy/quarantine rule on virtual repositories.

#### 5.2 — Disable lifecycle scripts in CI/CD installs

```yaml
# npm — in cloudbuild.yaml:
steps:
  - name: 'node:20'
    entrypoint: npm
    args: ['install', '--ignore-scripts']

# pip — use --no-build-isolation or pre-download + audit wheels
# Maven — disable exec plugin in CI profile
```

#### 5.3 — Apply least privilege to build service accounts

Minimum viable build SA roles:
- `roles/logging.logWriter`
- `roles/artifactregistry.writer` (push images only)
- `roles/storage.objectCreator` (write build artifacts only)

```bash
# Audit current permissions:
gcloud projects get-iam-policy PROJECT \
  --flatten="bindings[].members" \
  --filter="bindings.members:build-sa@" \
  --format="table(bindings.role)"
```

Use separate service accounts per environment (dev/staging/prod).

#### 5.4 — Enable JFrog Xray behavioral scanning

Enable Xray on all npm and PyPI virtual repositories in Artifactory. Xray scans package contents for malicious lifecycle scripts and known CVEs before serving to consumers.

#### 5.5 — Use Workload Identity Federation — eliminate static SA keys

```bash
# Create WIF pool and bind to specific repo + branch:
gcloud iam workload-identity-pools create "cicd-pool" \
  --project=PROJECT --location="global"

gcloud iam service-accounts add-iam-policy-binding \
  BUILD-SA@PROJECT.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/.../attribute.repository/org/repo"
```

Short-lived tokens scoped to a specific repo mean stolen tokens expire in minutes, not years.

#### 5.6 — Enable Security Command Center + alert on build anomalies

Alert on:
- Service account API calls outside business hours
- New IAM role bindings on sensitive roles
- Outbound connections from build worker subnets to uncategorized domains
- Unexpected image pushes to Artifact Registry

---

## Section 5 — IOC Reference (TanStack / Mini Shai-Hulud, May 2026)

Use as a concrete reference. Replace with IOCs from the relevant GHSA/CVE for any future incident.

| Type | Indicator | Context |
|------|-----------|---------|
| C2 domain | `filev2.getsession.org` | Primary exfil via Session/Oxen E2E encrypted upload |
| C2 domain | `seed1/2/3.getsession.org` | Secondary exfil nodes |
| C2 domain | `git-tanstack.com` | Attacker-controlled infrastructure |
| Payload file | `router_init.js` (~2.3 MB) | Injected into node_modules of each affected package |
| GitHub account | `voicproducoes` | Attacker account used to open malicious PR |
| Fork name | `zblgg/configuration` | Renamed to evade fork-list detection |
| CVE | `CVE-2026-45321` | Severity: Critical |
| GHSA | `GHSA-g7cv-rxg3-hmpx` | Full affected package list in this advisory |
| npm window | `2026-05-11 19:20–19:26 UTC` | 84 versions across 42 `@tanstack/*` packages |
| Threat group | `TeamPCP` | Also: Trivy (Mar 2026), Bitwarden CLI (Apr 2026) |

---

## Section 6 — Control Effectiveness Summary

| Control | Prevents at | Impact |
|---------|-------------|--------|
| 72-hr Artifactory cooldown | Artifactory stage | ⭐ Stops attack before CI/CD runs |
| Xray behavioral scanning | Artifactory stage | Flags malicious scripts on cache |
| `--ignore-scripts` in CI | Build worker | Blocks postinstall execution vector |
| Least-privilege build SA | Build worker + GKE | Limits blast radius if execution occurs |
| Workload Identity Federation | Build worker | Short-lived tokens reduce credential theft window |
| Security Command Center alerting | All stages | Detects — does not prevent |

---

## References

- [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [StepSecurity — Mini Shai-Hulud](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- [Wiz blog — campaign overview](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [Snyk advisory](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [JFrog Xray documentation](https://jfrog.com/help/r/jfrog-security-documentation/jfrog-xray)

---

*GCP Supply Chain Attack IR Playbook — Generalized Framework*  
*Generated: 2026-05-14 · Adapt commands and IOCs per incident advisory*
