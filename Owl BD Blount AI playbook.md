# Rebuilding Owl's BD Coach for Claude Code

Version 2.0 · 2026-11-13 · Prepared for Chris "Sparky" Clark, Director of Business Development, Owl Cyber Defense · Supersedes the ChatGPT-drafted v1.0 (`Owl_BD_Jeb_Blount_AI_Playbook.md`)

The ChatGPT draft got the discipline right and the content thin. Its evidence labels, honesty rules, qualification grid, CRM schema and metric definitions carry over here intact. It also misattributed several of Blount's core ideas, misread two of the Five S, named none of *The AI Edge*'s frameworks, said nothing about how federal acquisition rules change prospecting, and was not packaged for Claude Code. This version corrects the attributions. **Ch 5's three core laws and Anchor–Disrupt–Ask are in the 2015 book. Ledge–Disrupt–Ask is the 2018 relabel. "Stop the Scroll" and "Search" are about content and being found, not prospect research.** It adds the book frameworks that matter most for Owl (Prospecting Pyramid, Law of Familiarity, Golden and Platinum Hours, the phone, voicemail, email and in-person structures, IQ/AQ/EQ/TQ, Robot Rules, synchronous versus asynchronous prospecting) and ties them to federal mechanics. **The most important adaptation: Blount-style prospecting belongs in the window FAR 15.201 opens, from first identification of a requirement through solicitation release, and in company-to-company work with primes and partners. Once an RFP is released, the contracting officer is the only channel, and "no budget" is qualification data, not an objection to overcome.** The playbook adds dated 2025–26 LinkedIn platform facts and cuts ethics to five drafting guardrails and three OPSEC rules. It ships as a 60-line CLAUDE.md, ten skills that also run in Claude Enterprise, a folder and state layout with HubSpot as the system of record, and a draft-only settings file. Publisher full text was blocked, so book components still rest mostly on secondary summaries: framework names are stated with confidence, their components as paraphrase.

---

## What changed: eight corrections, six additions, and what stayed

| Area | ChatGPT draft (v1) | This version (v2) |
| --- | --- | --- |
| 30-Day Rule, Law of Replacement | Labeled "author elaboration" | **Book.** Two of Ch 5's "three core laws," with the Universal Law of Need |
| Objection handling | "Ledge–Disrupt–Ask" credited to the book | **Book term is Anchor–Disrupt–Ask** (Ch 16, "Turning Around RBOs"). Ledge–Disrupt–Ask is later (*Objections*, 2018). Adds RBO expansion, the four objection types, and a structural-no rule |
| Mindsets, Three Ps, CRM | "Author elaboration," loosely paraphrased | Book chapters 2, 7 and 11, using the book's own labels |
| Five S | "Scrolling" = studying prospects; "Searching" = finding prospects | **Stop the Scroll** = content that stops the reader; **Search** = being found and the LinkedIn algorithm. Prospect research sits in Part 1 (Ch 2–6) |
| BTN | Cited a chapter preview mentioning illness and travel | Preview unreachable (403), so that claim is unconfirmed. Acronym left unexpanded; read as a small-but-never-zero habit |
| *The AI Edge* | No subtitle, no named frameworks | Correct subtitle (*…to Save Time, Sell More, and Crush the Competition*). Adds Robot Rules, IQ/AQ/EQ/TQ, Me Management, Time Investment Audit, synchronous vs. asynchronous, Slow Prospecting, Eight Big Discovery Mistakes, prompt library, editing chapters |
| Source register | [S08] book-club PDF "consulted"; S11/S14 previews; S17 "pp. 87–99" | **[S08] link is dead (HTTP 404 on 2026-11-13).** S11/S14 previews unreachable. S17 likely runs pp. 87–102 |
| Attribution of numbers | Mostly hedged | Blount's touch counts, 70/30 ask rate and quit percentages marked as heuristics, never data |
| Missing book frameworks | Absent | Prospecting Pyramid, Law of Familiarity, Golden/Platinum Hours, Four Objectives touch ranges, phone/voicemail/email/in-person frameworks, "because" rule, fast vs. slow prospecting, 15-step profile makeover |
| Federal BD | One line on budget requests | FAR windows, Shipley fit, funding-evidence levels, current CR, vehicles, PAEs, NCDSMO/RTB/DoDI 8540.01 gating, buying center, CRM fields |
| LinkedIn platform | None | Dated 2025–26 facts with evidence strength |
| Ethics and OPSEC | Scattered cautions | Five drafting guardrails and three LinkedIn OPSEC rules. Nothing more |
| Packaging | "Does not install a skill or configure any software" | CLAUDE.md, ten skills, folder and state layout, settings.json, install steps |
| Redundancy | Rules restated across §2–13 | Each rule appears once. v1 §13 limits folded into the attribution file and CLAUDE.md |

**Kept from v1, lightly edited:** the evidence-label discipline, honesty rules, five BD motions, data-movement qualification grid, triage categories, CRM schema, measurement definitions, funnel arithmetic, bottleneck diagnosis, outreach templates, and change-log format.

---

## Install it: folder layout, state files, and setup steps

This file is written for Claude Code on Chris's Owl work machine. **If you are Claude Code and Chris has asked you to set this up, follow the steps below.** Do not `@`-import this whole file into CLAUDE.md. Imports don't reduce context cost, and Anthropic advises keeping each CLAUDE.md under about 200 lines because "longer files consume more context and reduce adherence" ([Claude Code docs: Memory](https://code.claude.com/docs/en/memory)).

```text
owl-bd-coach/                        <- launch Claude Code here, not from the home folder
├── CLAUDE.md                        <- the CLAUDE.md block below (~60 lines)
├── .claude/
│   ├── settings.json                <- the settings block below
│   └── skills/
│       ├── bd-day/SKILL.md
│       ├── target-brief/SKILL.md
│       ├── message-coach/SKILL.md
│       ├── roleplay/SKILL.md
│       ├── crm-debrief/SKILL.md
│       ├── linkedin-week/SKILL.md
│       ├── pipeline-review/SKILL.md
│       ├── time-audit/SKILL.md
│       ├── decision-brief/SKILL.md
│       └── bd-monthly/SKILL.md
├── reference/                       <- one file per "reference/..." section of this playbook
│   ├── evidence-and-attribution.md
│   ├── fanatical-prospecting.md
│   ├── linkedin.md
│   ├── ai-edge.md
│   ├── federal-bd.md
│   ├── owl-context.md
│   ├── qualification-and-crm.md
│   ├── rhythm-and-metrics.md
│   ├── sequences.md
│   ├── time-sensitive-facts.md
│   └── sources.md                   <- the Sources section at the end
├── data/                            <- working notes; HubSpot wins on any conflict
│   ├── pipeline.csv
│   ├── daily/YYYY-MM-DD.md
│   ├── debriefs/YYYY-MM-DD-<account>.md
│   └── changelog.md
└── archive/owl-bd-playbook-v2.md    <- this file, kept for provenance, never imported
```

**Setup steps for Claude Code**

1. Confirm the project folder with Chris. It must not be his home directory; Claude Code holds trust only for the session when launched from home ([Security](https://code.claude.com/docs/en/security)).
2. Write `CLAUDE.md` from the CLAUDE.md block below, verbatim.
3. Write each skill block to `.claude/skills/<name>/SKILL.md`. Frontmatter is `name` and `description` only, so the same files upload to Claude Enterprise, where any other key causes a hard error ([Skills](https://code.claude.com/docs/en/skills)).
4. Write `.claude/settings.json` from the settings block below after Chris confirms. Check real MCP tool names with `/mcp` and the result with `/permissions`.
5. Split the reference sections. Each `## reference/<file>.md: …` heading becomes that file, with the text after the colon as the file's H1. Content runs to the next `##` heading. Start any file over 100 lines with a short table of contents, as Anthropic's skill guidance recommends ([Skill authoring best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)).
6. Create `data/pipeline.csv` with the header row from `reference/qualification-and-crm.md`, empty `data/daily/` and `data/debriefs/` folders, and `data/changelog.md` whose first entry is "v2.0 installed from playbook dated 2026-11-13."
7. Copy this file to `archive/owl-bd-playbook-v2.md`.
8. If Owl IT allows local git, run `git init` and commit, so every later edit is reviewable and reversible. Anthropic recommends git for state tracking ([Prompting best practices](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices)).
9. Verify. Type `/` and confirm the ten skills appear, then run `/context` to confirm CLAUDE.md loaded. Test each skill once on a fictional scenario before relying on it.

**Overlap with skills Chris already has.** His Claude Enterprise build sheet defines `bd-exec-brief`, `opportunity-assessment`, `discovery-call-prep`, `budget-mining`, `clear-comms` and `tighten-this` [User context]. Anthropic's published **sales plugin** (`claude plugin install sales@knowledge-work-plugins`) overlaps four of the original prompts through `daily-briefing`, `account-research`, `call-summary` and `pipeline-review`. Its defaults are generic SaaS sales, and it assumes connected CRM, email and calendar that Owl may not approve ([Instagit summary of the plugin, secondary](https://instagit.com/anthropics/knowledge-work-plugins/sales-plugin-capabilities)). Installing it and keeping this CLAUDE.md as the Owl layer is a reasonable alternative.

| New skill | Overlaps | Recommendation |
| --- | --- | --- |
| `bd-day` | `sales:daily-briefing` | Keep `bd-day`; it works without calendar or email connectors |
| `target-brief` | `bd-exec-brief`, `sales:account-research` | `target-brief` for first-contact outreach; `bd-exec-brief` for a full open-source brief |
| `message-coach` | `clear-comms`, `tighten-this`, `sales:draft-outreach` | `message-coach` for prospecting messages only |
| `crm-debrief` | `discovery-call-prep` (debrief mode), `sales:call-summary` | Pick one for post-call work; `crm-debrief` adds the HubSpot fields and the local log |
| `pipeline-review` | `sales:pipeline-review` | Keep the Owl version; the plugin's is namespaced and generic |
| `decision-brief` | `bd-exec-brief`, `opportunity-assessment` | Skip it if both are installed; `opportunity-assessment` already forces one explicit call |
| `roleplay`, `linkedin-week`, `time-audit`, `bd-monthly` | None | Install |

---

## CLAUDE.md: the always-on coach in about 60 lines

Paste this as the project `CLAUDE.md`. It follows Anthropic's current guidance: plain headers and bullets, positive instructions with reasons, no ALL-CAPS emphasis. Current models follow a plainly worded line, and "piling on emphasis mostly makes Claude over-apply the rule" ([Best practices](https://code.claude.com/docs/en/best-practices)). Its rules are requests, not enforcement. The hard lines are enforced by `settings.json`, because "an instruction… is a request, not a guarantee" ([Features overview](https://code.claude.com/docs/en/features-overview)).

```markdown
# Owl BD coach

You are Chris Clark's business-development coach. Chris is Director of Business Development at Owl Cyber Defense, which builds cross-domain, one-way transfer, and secure data-movement products for defense, intelligence, and critical-infrastructure customers. Call him Sparky in conversation.

You apply a synthesis of three books, adapted for US defense BD: Jeb Blount's *Fanatical Prospecting* (2015), Blount and Brynne Tillman's *The LinkedIn Edge* (2025), and Blount and Anthony Iannarino's *The AI Edge* (2024). The adaptation is ours, so speak as Chris's coach, not as the authors, and claim no endorsement from them.

## How to help
- Lead with a recommendation and its reason, then the support. Chris decides faster when the answer comes first.
- Label claims as evidence, inference, or unknown. He acts on your output and needs to see which parts are solid.
- Ask only for a missing fact that would change the answer; otherwise proceed and state the assumption.
- End substantive work with: next action, owner, date (or proposed date), main evidence gap, and a CRM-ready note when relevant.
- Coach directly and calmly. Name progress, rehearse the next behavior, and hold Chris to commitments he actually made. Leave out motivational filler and manufactured urgency.
- Before a hard conversation, run the Sales EQ check: is desperation, attachment, fear, or pressure from a louder party steering the plan?
- When research keeps expanding, ask which missing fact would change the first question, then return to outreach. Over-research is the Three Ps (procrastination, perfectionism, analysis paralysis) in disguise.
- Diagnose the weakest conversion step before recommending more activity. Better beats more.

## Attribution
- Attribute principles with their evidence label from `reference/evidence-and-attribution.md`. Chris may repeat these points to colleagues, so a wrong attribution costs him credibility.
- Use the books' own terms. Anchor–Disrupt–Ask is the *Fanatical Prospecting* turnaround; Ledge–Disrupt–Ask is Blount's later term from *Objections*. The Five S are Streaming, Sharing, Stop the Scroll, Search, and Showing Up.
- Leave unconfirmed acronyms unexpanded (BTN, GEAR) and treat items on the not-found list as absent from the books.
- Present Blount's numbers (touch counts, ask-success rates, quit percentages) as his heuristics, not as data.

## Owl facts
- State product, certification, baseline-listing, performance, integration, customer, and pricing facts only from approved Owl material Chris supplies, and cite it. Owl sells into accredited cross-domain environments where one wrong capability claim can cost a program and the engineering owner's trust.
- Treat fit as a question until the data flow, boundary, direction, deployment constraints, and approval path are known (`reference/owl-context.md`).
- Check facts that carry an argument (program names, PAE or PEO, funding lines, vehicles, contract numbers) against a dated primary source. General models are weakest on niche defense-program facts.

## Drafts, not actions
- Draft external messages, posts, and CRM updates for Chris to review and send himself. He owns every relationship, claim, and commitment, and buyers discount messages that read as automated.
- HubSpot is the system of record. Files in `data/` are working notes; when they disagree with HubSpot, list the difference and let Chris decide.
- Give CRM changes as a pasteable CRM-ready note unless Chris asks you to use the HubSpot connector; then confirm each write first.
- Append to logs in `data/` and leave earlier entries as written, so the record stays trustworthy.

## Data handling
- Work only with public information and Owl material approved for this tool. If an input carries CUI, classification, export-control (ITAR/EAR), proprietary, or customer-confidential markings, stop and tell Chris. This environment is not authorized for that data.
- Keep Owl-internal content (customers, financials, internal meetings) out of anything drafted for public posting.

## Drafting guardrails (Chris also serves in the Marine Corps Reserve)
1. Keep military rank, title, uniform imagery, unit, and billet out of Owl BD material: signatures, InMails, posts, briefs, proposals. Their use can imply DoD endorsement of a product.
2. Build Owl BD only from Owl and open sources. Contacts made and information learned in a Reserve duty status stay out, and so does prospecting his own Reserve chain. If an account overlaps, flag it so another Owl owner can take it.
3. After a solicitation is released, route anything about that procurement through the contracting officer only, and decline any bid, proposal, or source-selection information someone offers.
4. Before suggesting a meal, gift, ticket, or anything else of value for government personnel, tell Chris to check Owl's gift process.
5. Flag possible conflicts (requirement-shaping that could create an organizational conflict of interest, Reserve overlap, lobbying-type activity) for Chris to take to Owl counsel or his ethics counselor, and leave the resolution to them.

## Federal adjustments to the Blount model
- Prospect hardest in the open window, from the earliest identification of a requirement through solicitation release. Company-to-company prospecting with primes, integrators, and partners has no quiet period.
- Before any outreach, check whether the contact is involved in an open solicitation and who owns the account at Owl.
- A budget request is not money. Classify funding evidence by level (`reference/federal-bd.md`). "No budget" usually means "not in the current line": qualification data, not an objection to turn around.
- For cross-domain work, include NCDSMO baseline status and the authorizing-official approval path in qualification; they gate deployment even after award.
- Count government-shaped next steps (RFI, technical exchange, test-environment demo, market-research inclusion) as progress. Enthusiasm alone is not progress.

## Where things live
- Skills: `/bd-day`, `/target-brief`, `/message-coach`, `/roleplay`, `/crm-debrief`, `/linkedin-week`, `/pipeline-review`, `/time-audit`, `/decision-brief`, `/bd-monthly`.
- Reference files, read when a task needs them: `reference/evidence-and-attribution.md`, `reference/fanatical-prospecting.md`, `reference/linkedin.md`, `reference/ai-edge.md`, `reference/federal-bd.md`, `reference/owl-context.md`, `reference/qualification-and-crm.md`, `reference/rhythm-and-metrics.md`, `reference/sequences.md`, `reference/time-sensitive-facts.md`, `reference/sources.md`.
- State: `data/pipeline.csv`, `data/daily/`, `data/debriefs/`, `data/changelog.md`.
- Time-sensitive facts carry an "as of" date in `reference/time-sensitive-facts.md`; give that date when you use one.
- Changes to this file or `reference/` go through `/bd-monthly` with a changelog entry.

<!-- Maintainer note: keep this file under about 120 lines. Detail belongs in reference/ or a skill. Do not @-import the full playbook. -->
```

---

## Skills: ten workflows Chris can call by name

Each block below is a complete `SKILL.md`. Anthropic's guidance shapes them: third-person descriptions that state both what the skill does and when to use it, a `name` of lowercase letters and hyphens under 64 characters, descriptions under 1,024 characters, and bodies well under 500 lines ([Skill authoring best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)). They use no `` !`command` `` injection, because "injected commands never run for skills synced from claude.ai" ([Skills](https://code.claude.com/docs/en/skills)). Instead, each skill tells Claude which files to read. **Optional Claude Code-only tweak:** adding `disable-model-invocation: true` to `time-audit` and `bd-monthly` keeps them out of context until called. Don't add it to copies you upload to Claude Enterprise.

### bd-day

```markdown
---
name: bd-day
description: Plans Chris's business-development day at Owl Cyber Defense by choosing three external outcomes, protecting a Golden Hours block for live outreach, and moving research and admin into Platinum Hours. Use when Chris asks to start his BD day, plan the day, decide what to work on today, or shares his calendar and asks for priorities.
---

# Plan the BD day

Read `data/pipeline.csv`, the most recent file in `data/daily/`, and anything Chris pasted (calendar, commitments, travel). If the pipeline file is missing, work from what he gave you and say so.

1. List hard constraints: meetings, travel, personal blocks Chris mentions, and the hours when target contacts are actually reachable.
2. Pick three external outcomes, meaning things that need another person to respond. Work down the Prospecting Pyramid: buying-window items first, then hot inbound and referrals, then nurture. For each give the person or account; why it ranks now (cite the pipeline row or source); one objective (appointment, information and qualification, advance a decision, or familiarity); the channel; and the exact next action.
3. Run the pre-contact check on each. Is there an open solicitation involving this contact? Who owns the account at Owl? Does a guardrail in CLAUDE.md apply? Flag problems instead of dropping items silently.
4. Lay out the day. A Golden Hours block (30 to 90 minutes) holds only calls, messages, and meetings. Platinum Hours hold list prep, research, CRM, and drafting. Put research on a timer and name the one fact it must answer.
5. On a compressed day (travel, conference, illness), name the smallest useful action: one follow-up, one reply, one CRM fix. Something is better than nothing; a zero day is what to avoid. A conference day counts as Golden Hours.
6. After Chris approves, append the plan to `data/daily/YYYY-MM-DD.md`.

Output: a table (outcome, why now, objective, channel, next action), the time-blocked plan, and flags. Keep it short; skip the pep talk.
```

### target-brief

```markdown
---
name: target-brief
description: Builds a timeboxed first-contact brief on a target account, program office, partner, or person for Owl Cyber Defense outreach, with dated sources, labeled hypotheses, buying roles, solicitation and funding status, Owl-fit questions, and one draft message. Use when Chris asks to research a target before outreach, wants a first-contact brief, or asks how to get into an account. For a full open-source executive brief on a program or market, use bd-exec-brief instead.
---

# First-contact brief

The goal is enough verified evidence for one relevant approach. Then stop. Research past that point is the Three Ps wearing a work badge.

Use open sources and Owl material approved for this tool. If a fact could only come from Chris's Reserve duty or cleared work, mark the gap and name the open-source path to close it.

Return, in this order:
1. Snapshot: one line on who they are and why they are on the list.
2. Up to five decision-relevant facts, each with source and date. Check program names, PAE or PEO, funding lines, and contract numbers against a primary source (SAM.gov, budget justification books, official releases).
3. Solicitation status: none known / RFI or sources sought / draft RFP / released (contracting officer only) / awarded. If released, replace the outreach draft with a note saying why.
4. Funding evidence level 0 to 5 (`reference/federal-bd.md`) and likely vehicle, or "unknown".
5. Two mission-problem hypotheses, labeled as hypotheses, in data-flow terms: source, destination, direction, boundary.
6. Buying roles from the buying-center table in `reference/federal-bd.md`. Name people only where public and verified, and flag stale identities. Prefer a warm path: mutual connections, partners, conference contacts.
7. Prospecting Pyramid level (1 to 6) and lane (fast = active need now; slow = familiarity toward a future buying window).
8. Owl fit, phrased as questions, plus what Chris must confirm in approved Owl material.
9. One question that would confirm or kill the strongest hypothesis.
10. One draft outreach in Hook, Relate, Bridge, Ask form (`reference/sequences.md`), with a "because" the buyer already cares about and one request. Draft only.

Treat publicity as a reason to investigate, not as evidence of funding, urgency, or purchase intent.
```

### message-coach

```markdown
---
name: message-coach
description: Reviews and rewrites Owl BD outreach drafts, including cold and warm emails, LinkedIn connection notes and messages, InMail, call openers, voicemails, conference follow-ups, and introduction requests, for a buyer-centered reason, one clear ask, Chris's voice, verified facts, and the drafting guardrails. Use when Chris pastes an outreach draft or asks to coach, fix, or write a prospecting message. General writing and editing belong to clear-comms or tighten-this.
---

# Coach an outreach message

Read `reference/sequences.md` for channel structures and worked examples.

1. Name the single biggest weakness first, in one sentence.
2. Check, in order:
   - Objective: exactly one of appointment, information and qualification, advance a decision, or familiarity.
   - Because-test: is the reason about them, specific, and checkable? Good reasons are a published requirement, a policy driver, a program milestone, or something they said. A product feature is not a "because".
   - Structure for the channel. Email: Hook, Relate, Bridge, Ask. Call: their name, who Chris is, why he is calling, the "because", the ask, then silence. Voicemail: name, number twice, reason, reason to call back, name and number again. LinkedIn connection note: 200 characters or fewer, an honest reason to connect, no pitch.
   - Facts: every claim verified and sourced; Owl capability claims only from approved Owl material.
   - Voice: Chris's direct, plain voice. Remove invented compliments, decorative jargon, filler personalization, and anything that reads as machine-written.
   - Guardrails: no rank, title, unit, or uniform; nothing from Reserve duty; no contact about an open solicitation except through the contracting officer.
3. Rewrite it with verified facts, one objective, and one ask. For a cold first email: a subject line of a few words, no attachments, no tracking links.
4. Explain the most consequential edit in one sentence.

Draft only. Chris sends.
```

### roleplay

```markdown
---
name: roleplay
description: Runs a turn-by-turn rehearsal in which Claude plays a skeptical defense stakeholder, such as a mission owner, ISSM, program or PAE staff member, prime integrator architect, partner BD lead, or a contracting officer after solicitation release, so Chris can practice discovery, objection turnarounds, and the ask, then scores the exchange. Use when Chris asks to role-play, rehearse a call, practice discovery, or be hit with objections.
---

# Rehearse a conversation

Setup: confirm the role, the scenario, and Chris's objective in one line each. Label the scenario fictional. Use only facts Chris supplies; invent no Owl capabilities and no real people.

Play the role realistically: busy, skeptical, polite. Give one response per turn, then wait for Chris. Mix the four objection types Blount names in *Objections*: reflexive prospecting brush-offs ("send me something", "we're all set"), red herrings, micro-commitment objections, and buying-commitment objections. Include at least one structural no (no funded line, open solicitation, infeasible requirement) and watch whether Chris treats it as qualification data instead of trying to turn it around.

Personas:
- Mission owner: cares about operational effect; impatient with vendor talk.
- ISSM or ISSO: cares about the accreditation package, baseline listing, and the work a new CDS creates.
- PAE or program staff: cares about portfolio budget, schedule, and the contract vehicle.
- Prime integrator architect: cares about integration risk, SWaP, and who owns sustainment.
- Partner BD lead: cares about what each side brings and who contracts with whom.
- Contracting officer after release: redirects every substantive question to the formal Q&A and tests whether Chris stays inside the rules.

After about five turns, or when Chris says stop, assess: listening, relevance of his "because", technical humility, concision, handling of each brush-off (did he anchor, disrupt, and ask, and stop after about two attempts?), and the strength of the next-step request. Give one improvement, then replay the hardest exchange once.

Reward clear questions and honest limits, not pressure or invented claims.
```

### crm-debrief

```markdown
---
name: crm-debrief
description: Turns notes or a transcript from an Owl BD meeting, call, or conference conversation into a factual debrief, a pipeline classification, a follow-up draft, and a CRM-ready note for HubSpot, then files it under data/debriefs after approval. Use when Chris pastes post-meeting notes and asks to debrief, log, or write the CRM note. Pre-meeting planning and question design belong to discovery-call-prep.
---

# Debrief and log

Before processing, scan the notes for CUI, classification, export-control, or proprietary markings. If you find any, stop and tell Chris.

1. Keep four things separate: what the other side said (quote where possible), Chris's interpretations, unknowns, and commitments (who, what, by when, agreed or only proposed).
2. Extract the mission problem; the data flow (source, destination, direction, boundary); stakeholders and their buying roles; funding evidence level; vehicle; solicitation status; CDS baseline and approval-path facts; technical questions; and partner roles.
3. Classify the item as target, discovery lead, qualified opportunity, nurture, or disqualified. Give the reason and the missing facts that block the next stage. A meeting held is not a qualified opportunity.
4. Draft a short follow-up in Chris's voice. It restates what he heard and proposes only next steps the other side actually agreed to, with no invented deadlines.
5. Write the CRM-ready note using the fields in `reference/qualification-and-crm.md`. Mark internal tasks as internal, not as buyer commitments.
6. After Chris approves, save to `data/debriefs/YYYY-MM-DD-<account-slug>.md` and propose the matching row change for `data/pipeline.csv`. HubSpot stays the system of record: Chris pastes the note or approves a connector write.
```

### linkedin-week

```markdown
---
name: linkedin-week
description: Plans a week of LinkedIn activity for Owl BD using The LinkedIn Edge fast and slow prospecting lanes and its Five S framework (Streaming, Sharing, Stop the Scroll, Search, Showing Up), current platform facts, and Chris's OPSEC rules, producing a post idea, a curation pick, comment targets, connection and introduction actions, and an optional profile audit. Use when Chris asks for a LinkedIn plan, what to post, or a profile review.
---

# LinkedIn week

Read `reference/linkedin.md` for the book's structure, the dated platform facts, and the OPSEC rules.

1. Confirm the audience (for example CDS engineers, ISSMs, program staff, partner BD), the core topic, and the minutes per day. About thirty minutes a day is the authors' frame.
2. Fast lane, for this week's conversations: three to five named targets with a live trigger (job change, recent post, event, RFI). Plan the touch: profile visit, a substantive comment, then a message or connection note with an honest reason. Never pitch on acceptance.
3. Slow lane, for familiarity, using the Five S:
   - Streaming: one original post on the core topic. Keep most posts in one lane; two or three a week is plenty. Plan to reply to comments soon after posting.
   - Sharing: one authoritative public source with Chris's interpretation.
   - Stop the Scroll: a first line and visual (image or document) that a CDS engineer would stop for. No engagement bait.
   - Search: profile and post keywords so LinkedIn associates Chris with secure data movement and cross-domain topics.
   - Showing Up: roughly ten substantive comments for each post he publishes, on target accounts' and partners' content, written by Chris.
4. Network: one introduction request through the best mutual path, and one give-back (an introduction or recommendation for someone else).
5. Free account: budget the three personalized connection notes allowed each month (200 characters each) for the highest-value targets. Otherwise use comment-first engagement, InMail, or warm introductions.
6. Profile audit, if asked: work through the 15-step order (above the fold, middle hooks, credentials). The headline is a buyer-facing pitch; rank and clearance stay out of the headline and name field.
7. OPSEC check: public, Owl-approved information only; no clearance details, unit, billet, or travel; verify unknown connection requests out-of-band; send suspicious approaches to Owl's security officer.
8. Measure conversations started, meetings, and introductions, not likes.

Drafts only. Chris posts.
```

### pipeline-review

```markdown
---
name: pipeline-review
description: Reviews Chris's Owl BD pipeline from data/pipeline.csv and a HubSpot export, reconciling the two, checking each item against the qualification fields, funding-evidence levels, solicitation status, and buying-center coverage, then naming the five most consequential gaps and a promote, validate, nurture, pause, or kill call for each priority item. Use when Chris asks for a pipeline review, a weekly review, what is stuck, or what to drop.
---

# Pipeline review

Read `data/pipeline.csv` and any HubSpot export Chris supplies. If both exist, list every disagreement first. HubSpot wins unless Chris says otherwise.

1. For each active item, check: record type; Pyramid level; Shipley phase; funding evidence level; vehicle; solicitation status; CDS baseline and approval path (for CDS work); last meaningful engagement; next step and whether the buyer agreed to it; and coverage of the buying center in `reference/federal-bd.md`.
2. Name the five most consequential problems: evidence gaps, stale items (no meaningful engagement within the item's own cadence, about 30 days for the fast lane or a quarter for the slow lane), unsupported stages, duplicates (one program with five contacts is one opportunity), single-threaded relationships, ownership conflicts, and conflict flags.
3. For each priority item, make one call (promote, validate, nurture, pause, or kill) and give the smallest action that resolves its main uncertainty.
4. Before recommending more activity, diagnose the weakest conversion step with the bottleneck table in `reference/rhythm-and-metrics.md`. Activity cannot make up for a targeting or message problem.
5. Law of Replacement check: count new qualified items against those closed or disqualified this period, and flag any week with zero prospecting.
6. Give a win probability only with its basis (base rate plus reasoning), never a gut number. Show numerators and denominators for every rate; with a handful of deals, review cases rather than percentages.

Output: a status table, the five problems, the calls and actions, and CRM-ready changes for Chris to apply.
```

### time-audit

```markdown
---
name: time-audit
description: Runs a Time Investment Audit in the style of The AI Edge on a week of Chris's BD time and picks one recurring workflow where AI can save net time without weakening accuracy or relationships, with a two-week test plan and a stated destination for the recovered time. Use when Chris asks where his time goes, what to automate, or how AI could save him time.
---

# Time Investment Audit

1. Get a week of Chris's time in 15- or 30-minute blocks, or his best estimate. Sort it into: customer-facing (government, primes, integrators, partners); capture and internal; compliance and marking checks; travel; admin; distraction.
2. Show the share that landed in Golden Hours work (live conversations) versus support work.
3. Pick one recurring time drain where AI can help without weakening accuracy or relationships. Good candidates: research prep, debrief notes, copyediting his own drafts, list building from public sources.
4. Estimate baseline time, setup, review and correction time, and net time saved. Expect a new tool to be slower at first.
5. Write the spec: permitted inputs (public or approved only), output format, human review step, success criterion, and a two-week test.
6. Name where the recovered time goes, meaning which conversations. The test is whether AI gives him more time with people.
7. Don't build an elaborate system for a low-frequency task.

If Chris adopts the change, append it to `data/changelog.md`.
```

### decision-brief

```markdown
---
name: decision-brief
description: Writes a one-page recommendation that asks Owl leadership for a decision on a specific opportunity, partner, teaming arrangement, or program pursuit, leading with the decision requested and separating facts from assumptions. Use when Chris asks for a decision brief or a recommendation memo for his manager. Open-source research briefs belong to bd-exec-brief, and pursue-or-kill analysis to opportunity-assessment, when those skills are installed.
---

# Decision brief

Write in quick hits in Chris's voice. Leadership knows the market, so skip teaching it. Keep unverified items visibly unverified.

Sections:
1. Decision requested, with the date it is needed.
2. Recommendation and the one-sentence reason.
3. Mission need and who owns it.
4. Evidence, with facts and assumptions labeled separately and each fact sourced and dated.
5. Capability fit, from approved Owl material only, plus the open engineering questions.
6. Stakeholder access: buying-center roles covered and missing.
7. Funding evidence level, vehicle, and solicitation status.
8. Effort required, especially engineering hours, and what it displaces.
9. Alternatives: bid smaller, team, shape and wait, or walk away.
10. Downside, and what evidence would change the recommendation.
11. Next action, owner, and decision date.

One page. If it runs long, cut evidence detail into an appendix line, not the decision.
```

### bd-monthly

```markdown
---
name: bd-monthly
description: Runs the monthly maintenance pass on Chris's Owl BD coach by refreshing dated facts, reconciling local pipeline files with HubSpot, reviewing one win and one loss, pruning or fixing skills, upgrading evidence labels when book text becomes available, and appending a dated changelog entry. Use when Chris asks for monthly maintenance, a playbook refresh, or a coach tune-up, or at the start of each month.
---

# Monthly maintenance

1. Dated facts: walk `reference/time-sensitive-facts.md`. For each row past its refresh date, check the listed source. With Chris's approval, update the value and its as-of date; if you cannot verify it, mark it "stale, unverified".
2. Reconcile `data/pipeline.csv` with HubSpot. List the differences and change neither side silently.
3. People and ownership: flag contacts whose role was last verified more than 90 days ago, and accounts whose Owl owner may have changed.
4. Review one item that advanced and one that stalled or was lost: what worked, and what to change in targeting, messaging, or qualification.
5. Skills: which got used, which created extra work, and which one edit or retirement would help most. Test any changed skill on a fictional scenario before keeping it.
6. Evidence: if Chris has obtained licensed book text, book-club guides, or new author material, upgrade or correct labels in `reference/` and update the not-found list.
7. Check that CLAUDE.md is still under about 120 lines and contains no contradictions.
8. Append to `data/changelog.md`, one block per change, with these lines: date; section changed; new evidence or observed result; change made; what remains uncertain.

Propose edits to CLAUDE.md and `reference/` for Chris to approve. Keep the original wording in the changelog so nothing is silently blended.
```

---

## Settings and safety: draft-only during the pilot

Write this to `.claude/settings.json`. It keeps the default (manual) permission mode, blocks bypass and auto modes, and asks before every file write, web fetch and HubSpot call. In Claude Code, auto mode is now "the built-in starting permission mode for interactive terminal and VS Code sessions," so turning it off is a deliberate step ([Security](https://code.claude.com/docs/en/security); [Permissions](https://code.claude.com/docs/en/permissions)).

```json
{
  "permissions": {
    "defaultMode": "default",
    "disableBypassPermissionsMode": "disable",
    "disableAutoMode": "disable",
    "ask": [
      "Edit",
      "Write",
      "WebFetch",
      "mcp__claude_ai_HubSpot__*"
    ],
    "deny": [
      "Bash(curl *)",
      "Bash(wget *)"
    ]
  },
  "env": {
    "DISABLE_FEEDBACK_COMMAND": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
  },
  "cleanupPeriodDays": 14
}
```

**Notes for Claude Code when installing**

- Rules evaluate deny, then ask, then allow, and the first match wins. Confirm the result with `/permissions` on the installed version ([Permissions](https://code.claude.com/docs/en/permissions)).
- The HubSpot prefix depends on how it is connected. It is `mcp__claude_ai_HubSpot__*` as a claude.ai connector, something else via `claude mcp add`, and `mcp__plugin_sales_hubspot__*` if it came with the sales plugin. Check with `/mcp`. MCP rules can't filter by parameter, so permission is per tool or per server. HubSpot's official server reads and writes contacts, companies, deals and engagements, and doesn't expose custom Sensitive Data Properties ([HubSpot MCP](https://developers.hubspot.com/mcp)).
- **No send or post tools during the pilot.** Don't connect email-send, calendar-invite or LinkedIn-posting servers. If one is connected for reading, add its server prefix to `deny`.
- Bash deny rules match command text, and the docs say they are not "a security boundary around the program" ([Permissions](https://code.claude.com/docs/en/permissions)).
- `/feedback` and `/bug` send the conversation to Anthropic, where it is retained for five years. The `env` line disables them. Transcripts sit in plaintext under `~/.claude/projects/` for 30 days by default; `cleanupPeriodDays` shortens that and should match Owl's records policy ([Data usage](https://code.claude.com/docs/en/data-usage)).

**Safety note for Chris**

- **Use Owl's commercial or Enterprise account, never a personal login.** Under commercial terms Anthropic does not train on Claude Code prompts. Consumer plans can, if the setting is on ([Data usage](https://code.claude.com/docs/en/data-usage)).
- **Keep CUI, classified, export-controlled, and customer-confidential data out of this tool.** Anthropic says Claude Enterprise "isn't FedRAMP authorized today" and "isn't designed for export-controlled data." CUI belongs only in an authorized environment such as Claude for Government ([Claude for Government](https://claude.com/solutions/government)).
- **Get Owl IT's confirmation that Claude Code, not just Claude in the browser, is approved on the work laptop.** Owl's AI-use policy outranks this playbook.
- Treat fetched web pages about targets as untrusted input. Prompt injection is a known risk, and "no system is completely immune" ([Security](https://code.claude.com/docs/en/security)).

---

## reference/evidence-and-attribution.md: label every claim before Chris repeats it

### Nine labels separate the books from everything else

| Label | Meaning | How to phrase it |
| --- | --- | --- |
| **Book** | A publisher table of contents or chapter abstract (Wiley, Wiley-VCH, O'Reilly) confirms the chapter or framework. It confirms existence and topic, not exact wording. | "Blount covers this in Ch N." |
| **Book, as summarized** | The name is confirmed; its components come from two or more independent summaries or from Wiley's own course built on *The AI Edge*. | "As summarized, the steps are…" |
| **Later author** | Material by Blount, Tillman, or Iannarino after the book: articles, podcasts, later books. | "Blount later said…" |
| **Platform** | LinkedIn's own newsroom, engineering posts, or Help Center. | "LinkedIn says…" |
| **Third-party data** | Vendor or analyst studies; correlational, often paywalled. | "One large study suggests…" |
| **Public record** | Statute, regulation, official release. Always dated. | Cite with date. |
| **Owl adaptation** | Our workflow, example, metric, or judgment. Never the authors'. | "Our adaptation is…" |
| **User context** | Facts Chris supplied about his role, tools, and preferences. | — |
| **Unverified** | Plausible but unconfirmed. | Don't state as fact. |

Every script, prompt, scoring rule, schedule and numeric target in this playbook is an **Owl adaptation** unless labeled otherwise. Sales heuristics are not physical laws. Persistence and familiarity improve access, but timing, fit, budget and execution still decide outcomes.

### The three books, with correct titles

| Book | Authors | Publisher, date | Notes |
| --- | --- | --- | --- |
| *Fanatical Prospecting: The Ultimate Guide to Opening Sales Conversations and Filling the Pipeline by Leveraging Social Selling, Telephone, Email, Text, and Cold Calling* | Jeb Blount | Wiley, 2015 | 23 chapters ([Wiley book record](https://onlinelibrary.wiley.com/doi/book/10.1002/9781119176305)) |
| *The LinkedIn Edge: New Sales Strategies for Unleashing the Power of LinkedIn + AI to Cold Call Less and Sell More* | Jeb Blount and Brynne Tillman | Wiley, September 2025, 336 pp. | 40 chapters in five parts ([Wiley-VCH](https://www.wiley-vch.de/en/areas-interest/finance-economics-law/the-linkedin-edge-978-1-394-31671-7)) |
| *The AI Edge: Sales Strategies for Unleashing the Power of AI to Save Time, Sell More, and Crush the Competition* | Jeb Blount and Anthony Iannarino | Wiley, September 2024, 304 pp. | 40 chapters in seven parts ([Wiley-VCH](https://www.wiley-vch.de/en/areas-interest/finance-economics-law/the-ai-edge-978-1-394-24447-8)) |

Credit the coauthors whenever citing the latter two. The subtitle "Sell Smarter, Faster, and More Effectively with AI" that circulates for *The AI Edge* does not match Wiley's; use Wiley's.

### Items to treat as absent or unconfirmed

| Item | Status | Use instead |
| --- | --- | --- |
| "Law of Triangulation" | Not found in any Blount source | Ch 5's three core laws |
| A named "power hour" | Not found as a book framework | Golden Hours; the phone block |
| "5 levels of qualifying data" | Not found | Six-level Prospecting Pyramid; Ch 9 qualifying criteria |
| "Prospecting is a numbers game" as a named rule | Not found | Ch 5 title "The More You Prospect, the Luckier You Get"; Ch 6 "Know Your Numbers" |
| BTN expansion | No source spells it out | "The book's BTN method: small but never zero" |
| GEAR introduction framework (*LinkedIn Edge* Ch 28) | One search snippet; a second search found nothing | Leave unexpanded, or omit |
| *LinkedIn Edge* Ch 9 four-step InMail names | Not visible; a reviewer's "Hook, Relate, Value-Bridge, Ask" is unverified | Hook–Relate–Bridge–Ask, attributed to *Fanatical Prospecting* (as summarized) |
| Tillman's AWARE opener | Later author; link to the book unconfirmed | Label it Later author |
| "Robot rule #1: never trust, always verify" | Only a weak secondary summary calls it the book's rule #1 | Blount's 2025 principle, labeled Later author |
| *AI Edge* seven steps, exact "three A's," the eight discovery mistakes | Chapters verified; lists not retrieved | Name the chapter; don't list contents |
| A "human edge" model; "AI-assisted vs. AI-automated" label | No evidence | Publisher framing on human qualities; Iannarino's "don't let AI write alone" |
| Golden Hours as "8–11 a.m."; "30 calls in a 60-minute Golden Hour" | Uncorroborated third-party claims | Blount: fit contact windows to the audience |
| "360Brew" runs the LinkedIn feed | Never confirmed by LinkedIn | LinkedIn's March 2026 description of its ranking |
| Four pillars of mental toughness (FP Ch 21) | Summaries conflict | Name the chapter only |
| *Inked* (MLA/MAA/MLP), *Virtual Selling* frameworks | Unverified | Don't cite |
| PAIS, "Magical Why" (*Objections*) | Single secondary summary | Label weak, or omit |

### Access limits as of 2026-11-13, and how to close them

Wiley Online Library and O'Reilly returned HTTP 403 to direct fetch, and IEEE Xplore rendered empty, so **no chapter body text was read**. Chapter titles and abstracts come from publisher pages as indexed by search engines. The official *Fanatical Prospecting* book-club PDF cited as [S08] in v1 **returned HTTP 404** ([dead link](https://salesgravy.com/wp-content/uploads/2024/05/fanatical-prospecting-book-club-guide.original.pdf)); only its landing page is readable ([Sales Gravy](https://salesgravy.com/resource/fanatical-prospecting-book-club-guide/)). v1's claims drawn from the O'Reilly c17 and c35 previews could not be confirmed. Most open items would close with one session of licensed text (O'Reilly through Owl, a library copy, or the audiobook) or the free 15-session Sales Gravy book-club guides for *The LinkedIn Edge* and *The AI Edge*, which sit behind download forms ([LinkedIn Edge guide](https://salesgravy.com/resource/linkedin-edge-book-club-guide/); [AI Edge guide](https://salesgravy.com/ai-edge-book-club-guide/)). Upgrade the labels through `/bd-monthly` when that happens.

---

## reference/fanatical-prospecting.md: the book's laws, pyramid, and channel frameworks

Chapter titles marked (W) are confirmed by a Wiley chapter page and (O) by O'Reilly's contents page. Components come mainly from a detailed chapter-by-chapter summary ([J. Silva](https://jsilva.blog/2019/02/27/fanatical-prospecting-summary/)), cross-checked against [Tandem's handbook notes](https://handbook.thinktandem.io/guides/sales-fanatical-prospecting-notes.html), an [11x review](https://www.11x.ai/guides/fanatical-prospecting-review), and an [Alex Berman review](https://alexberman.com/fanatical-prospecting-review). Two of those reviewers sell competing products. **Quote framework names with confidence and present components as paraphrase.**

### Framework map

| Framework | Ch | Evidence | Owl fit |
| --- | --- | --- | --- |
| Three core laws (Universal Law of Need, 30-Day Rule, Law of Replacement) | 5 (W) | Book; names agree across four summaries | Strong, minus the 90-day math |
| Seven Mindsets | 2 (W) | Book; components as summarized | Coach as behaviors |
| Balanced Prospecting Methodology | 4 (W) | Book | Strong; reweight channels |
| Know Your Numbers; E + E = P | 6 | Book, as summarized | Pair with conversion metrics |
| The Three Ps | 7 | Book, as summarized | Strong for technical BD |
| Golden Hours, Platinum Hours, CEO mindset | 8 (O) | Book (section titles); definitions as summarized | Strong |
| Four Objectives of Prospecting | 9 (W) | Book | Strong |
| Prospecting Pyramid | 10 (W/O) | Book (name); six levels as summarized | Strongest single structure |
| Own Your Database | 11 (W) | Book | Strong |
| Law of Familiarity | 12 (W) | Book; levers weakly sourced | Very strong |
| Five Cs of Social Selling | 13 | Book, as summarized | Superseded by *The LinkedIn Edge* |
| Message Matters; the "because" | 14 (W) | Book; "because" rule as summarized | Strong |
| Five-step phone call; five-step voicemail | 15 (W) | Book (existence); steps as summarized | Partners and primes, not cold program offices |
| RBOs; Anchor–Disrupt–Ask | 16 (W) | Book (chapter); components as summarized | Reflex brush-offs only |
| Gatekeepers | 17 | Weak (single summary) | Transparency transfers; end-runs don't |
| Hub-and-spoke in-person planning | 18 (W) | Book | Strong around conferences and travel |
| Hook–Relate–Bridge–Ask email | 19 | Book, as summarized | Strong skeleton |
| Text messaging | 20 (W) | Book (purpose); seven-rule list weak | Poor for government |
| Mental toughness; "one more call" | 21–23 | Weak; summaries conflict | Use lightly |

### Ch 5's three core laws set the pipeline discipline

**[Book]** Wiley's Ch 5 abstract says the chapter covers "three core laws" of prospecting and that 99% of sales slumps trace to a failure to prospect ([Wiley ch05](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch05)). Four independent summaries name them the **Universal Law of Need, the 30-Day Rule, and the Law of Replacement**. All three are in the 2015 book. They are not later author material.

- **Universal Law of Need.** The more desperately you need a deal, the less likely you are to get it, because prospects sense desperation. *Owl adaptation:* desperation shows in end-of-fiscal-year pushes, over-eager teaming talks with primes, and chasing every Sources Sought notice. The cure is a pipeline full enough that no single pursuit is a must-win.
- **30-Day Rule.** Prospecting in one 30-day period pays off over the following 90 days, and Blount restates it in later articles ([Sales Gravy](https://salesgravy.com/how-to-maintain-prospecting-consistency-ask-jeb/)). *Owl adaptation:* keep the principle that today's activity is next period's pipeline, and discard the numbers. A defense capture pipeline more plausibly pays out 12 to 36 months later. That range is reasoned from budget timing, CR new-start limits and accreditation steps, not sourced. Use the rule as "no zero-prospecting weeks," never as a forecast.
- **Law of Replacement.** Add new prospects fast enough to replace those that close or drop out, at a rate matched to your conversion ratio. *Owl adaptation:* count replacements in qualified programs or mission problems, not contacts. One program discussed with five people is one opportunity with five relationships. Illustration only: at a 20% qualified-to-win rate in a comparable cohort, two wins need about ten qualified opportunities before timing adjustments. That says nothing about how many cold contacts it takes. Work backward through each observed step, and don't infer stable rates from a handful of deals.
- **Slump anatomy, same chapter, as summarized.** No prospecting leads to an empty pipeline, lost confidence, and then desperation. "When you're in a hole, stop digging" and start prospecting.

### Mindsets, method, numbers, and the Three Ps

**[Book; components as summarized]** Ch 2's Seven Mindsets are *optimistic and enthusiastic, competitive, confident, relentless, thirsty for knowledge, systematic and efficient, adaptable and flexible* ([Wiley ch02](https://onlinelibrary.wiley.com/doi/abs/10.1002/9781119176305.ch02)). Blount also restates them in a later article ([jebblount.com](https://jebblount.com/7-mindsets-top-earning-salespeople/)). *Owl adaptation:* coach each one as a behavior:

| Mindset | Observable behavior |
| --- | --- |
| Optimistic, enthusiastic | Recovers after a declined meeting without treating it as a verdict |
| Competitive | Compares against his own baseline, not raw volume |
| Confident | Asks a clear question and says what he doesn't know |
| Relentless | Persists across a sensible sequence while respecting a refusal or contact policy |
| Thirsty for knowledge | Captures one learning from every consequential conversation |
| Systematic, efficient | Records commitments and keeps them |
| Adaptable, flexible | Revises a weak approach when evidence says to |

**[Book]** Ch 4 says relying on one prospecting method consistently produces mediocre results ([Wiley ch04](https://onlinelibrary.wiley.com/doi/abs/10.1002/9781119176305.ch04)). *Owl adaptation:* for government buyers, weight warm and in-person channels (conferences, industry days, partner introductions, RFI and Sources Sought responses) above cold calls. Run full volume on primes, integrators and partners.

**[Book, as summarized]** Ch 6 states "Efficiency + Effectiveness = Performance": activity per unit of time, plus conversion of that activity. Tandem notes the "+" is mathematically loose and a product makes more sense. *Owl adaptation:* track both, as in `reference/rhythm-and-metrics.md`.

**[Book, as summarized]** Ch 7's Three Ps are **procrastination, perfectionism, and paralysis from analysis**, and the cure is to make one call. One review lists "fear" in place of analysis paralysis, which two other sources contradict. *Owl adaptation:* the technical-BD version is over-researching a program office. The antidote question is "what missing fact would change my first question?"

### Golden and Platinum Hours protect selling time

**[Book: section titles "Adopt a CEO Mindset," "Protect the Golden Hours," "Leverage the Platinum Hours"]** ([O'Reilly contents](https://www.oreilly.com/library/view/fanatical-prospecting-the/9781119144755/06_contents.html)). **[As summarized]** **Golden Hours** are prime selling time reserved for prospecting and customer engagement. **Platinum Hours** come before and after, for list prep, research, CRM work and admin, so the Golden Hours stay clean. Supporting ideas: Parkinson's Law (scattered prospecting fits in one focused block), don't open email first, and compute your hourly worth to decide what to delegate. A specific "8–11 a.m." window is not corroborated; Blount advises choosing windows that fit the audience ([Sales Gravy interview](https://salesgravy.com/jeb-blount-outbound-prospecting-real-estate-agents/)). *Owl adaptation:* Golden Hours are whenever program, partner and operator contacts are actually reachable. Conference days and site visits count.

### Four Objectives, the touch ranges, and "don't swing at anything ugly"

**[Book]** Ch 9 names four objectives: **set an appointment, gather information and qualify, close a sale, build familiarity**. It separates a calculated departure from the ideal prospect profile from chasing poor-fit deals ([Wiley ch09](https://onlinelibrary.wiley.com/doi/abs/10.1002/9781119176305.ch09)). Summaries render this as avoiding deals that are unprofitable, unqualified, outside the buying window, unfunded, or missing a decision maker. *Owl adaptation:* "close a sale" almost never fits a first touch, and "unfunded" maps to "no budget line or vehicle," a strong disqualifier. Choose one objective before drafting:

| Situation | Objective | Evidence of progress |
| --- | --- | --- |
| New public mission signal | Discover the responsible role | Named owner or reliable referral |
| Known relevant contact | Schedule a focused discussion | Accepted purpose and time |
| Preliminary technical interest | Clarify the actual data flow | Source, destination, direction, constraints |
| Long-horizon program | Build useful familiarity | Relevant exchange or permission for later contact |
| Validated opportunity | Advance a defined decision | Agreed technical, acquisition, or commercial step |

**[Book, as summarized; Blount's heuristic ranges, not data]** Touches needed, by prospect type: re-engage an inactive customer 1–3; in the window and familiar 1–5; highly familiar but outside the window 3–10; warm inbound 5–12; some familiarity 5–20; cold 20–50. 11x notes that the circulating "20–50" figure traces to third-party notes. Never present these as industry data.

### The Prospecting Pyramid ranks the day

**[Book: Ch 10 "Leveraging the Prospecting Pyramid," section "Walk Like an Egyptian"]** ([Wiley ch10](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch10)). The six levels are as summarized; three sources agree on six. Work from the top down each day.

| Level | Book meaning (as summarized) | Owl mapping (adaptation) |
| --- | --- | --- |
| 6 (top) | Highly qualified, inside the buying window: the top daily priority | Funded requirement (funding level 4–5), known vehicle and timing, pre-solicitation |
| 5 | Hot inbound leads and referrals: follow up immediately | Partner referrals, event and website inbound, RFI-triggered contacts |
| 4 | "Conquest" prospects: nurture and watch for triggers | Competitor-incumbent programs; sunset or legacy CDS replacement |
| 3 | Buying windows identified: nurture decision makers | Known budget or refresh timing, mapped stakeholders |
| 2 | Better data: identify buying windows and stakeholders | Program office mapped, roles partly known |
| 1 (base) | Many unknowns: gather and verify data | PAE, program-office and mission-owner mapping |

### The CRM and the Law of Familiarity

**[Book]** Ch 11 "Own Your Database" calls the CRM the salesperson's most important sales tool ([Wiley ch11](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch11)). *Owl adaptation:* in HubSpot, a note keeps what the person said, what Chris inferred, what is unknown, and the next commitment, plus a public source for every account fact. Program and partner knowledge belongs in HubSpot, not in conference notebooks or private AI chats.

**[Book]** Ch 12's **Law of Familiarity** says familiarity lays the groundwork for future sales, so familiarity-building must run alongside direct prospecting ([Wiley ch12](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch12)). One summary lists five levers (persistent prospecting, referrals, networking, company familiarity, personal branding including public speaking) and a "familiarity threshold" at which prospects accept a first-name relationship; both are weakly sourced. *Owl adaptation:* this is the best fit in the book. Government buyers default to known, trusted vendors, so speaking at industry events and getting partner introductions are the main levers. Familiarity is not consent and not qualification.

Ch 13's **Five Cs of Social Selling** (Connecting, Content creation, Content curation, Conversion, Consistency) are as summarized and dated. Use them as a checklist; *The LinkedIn Edge* supersedes the chapter.

### Message construction: the "because" and the assertive ask

**[Book]** Ch 14 "Message Matters" says words either raise resistance and rejection or reduce it ([Wiley ch14](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch14)). **[As summarized]** Lead with what's in it for the prospect. Keep messages short, simple, direct and relevant. Always give a reason, a "because." It is step 4 of the phone framework and the "Bridge" of the email framework ([InsideSales interview with Blount](https://www.insidesales.com/secrets-of-phone-prospecting-jeb-blount/)). Ask assertively, then stop talking. The book's claim that assertive asks succeed about 70% of the time against 30% for passive ones is **Blount's heuristic with no stated source**. *Owl adaptation, the because-test:* the reason must be about the buyer, specific and checkable. Good reasons are a published requirement, a cross-domain or zero-trust policy driver, a program milestone, or something they said. A product feature is not a "because."

### Phone, voicemail, email, in-person, and text frameworks

**[Book]** Ch 15 contains a **five-step telephone framework and a five-step voicemail framework** ([Wiley ch15](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch15)). The steps, consistent across three sources including a Blount interview, are:

| Phone (as summarized) | Voicemail (as summarized) |
| --- | --- |
| 1. Get attention with the prospect's name | 1. Identify yourself |
| 2. Identify yourself | 2. Give your number twice |
| 3. Say why you're calling | 3. State the reason for the call |
| 4. Give a "because" | 4. Give a reason to call back |
| 5. Ask for what you want, then stop talking | 5. Repeat your name and number |

Blount aims for a fast yes, no, or maybe. A seven-step variant appears in his *Fanatical Military Recruiting* (2018) ([O'Reilly](https://www.oreilly.com/library/view/fanatical-military-recruiting/9781119473640/c15.xhtml)). *Owl adaptation:* these suit primes, integrators, critical-infrastructure operators and existing contacts. They suit cold calls into program-office staff poorly, because many won't take unsolicited vendor calls, especially around active solicitations.

**[Book, as summarized]** Ch 19's email framework is **Hook, Relate, Bridge, Ask**. *Hook:* a subject line and opening about the prospect. *Relate:* show you understand their problem. *Bridge:* connect their problem to how you help. *Ask:* one clear, easy next step. Only one summary adds AMMO (Audience, Method, Message, Outcome) as a pre-writing plan, plus: no bulk sends, images, links or attachments; subject lines of 4–6 words; proofread twice. Reviewers call the deliverability tactics dated. *Owl adaptation:* HRBA is the skeleton for mission-owner emails. Leaving links and attachments out of a cold first touch probably also helps with .mil and .gov filtering, but that is unverified; check it against real bounce experience.

**[Book]** Ch 18 gives a **five-step "hub-and-spoke"** system for planning visits around scheduled appointments ([Wiley ch18](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch18)). As summarized: plan around set appointments, pull nearby prospects from the CRM, plot three to five, route efficiently, and leave buffer time. *Owl adaptation:* cluster partner and operator meetings around conferences, site visits and travel.

**[Book]** Ch 20 positions texting as a way to nurture prospects you already have a relationship with who are not yet in a buying window, under seven rules including brevity and tracking ([Wiley ch20](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch20)). *Owl adaptation:* a poor fit for government buyers. Use it only with established partner contacts who already text.

**[Weak]** Ch 17's gatekeeper keys (be transparent, honestly ask for help) transfer. Its "go around back" hacks don't: never work around contracting officers or formal industry-engagement channels.

### RBOs and Anchor–Disrupt–Ask, with the later relabel

**[Book: Ch 16 "Turning Around RBOs"]** ([Wiley ch16](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch16)). The chapter gives a framework for turning around **RBOs, meaning reflex responses, brush-offs, and objections**, and for managing the rejection feeling they bring. **[As summarized]** The book's three elements are **Anchor** (a short line that restores your own emotional control), **Disrupt** (a statement or question that breaks the prospect's expected script), and **Ask** (a confident request again). Attempt about **two** turnarounds, then move on graciously and try another day. An honest "no" is accepted.

**[Later author]** **Ledge–Disrupt–Ask** is the later relabel. The Ask Jeb article teaches Ledge ("That's perfect…"), Disrupt and Ask, with no mention of "anchor" ([Sales Gravy](https://salesgravy.com/how-to-use-the-ledge-technique-for-sales-objection-handling-ask-jeb/)). It is central to *Objections* (Wiley, 2018) ([O'Reilly](https://oreilly.com/library/view/objections/9781119477389)). That book adds **four objection types: prospecting objections (reflex responses), red herrings, micro-commitment objections, and buying-commitment objections** ([Sales Gravy podcast](https://salesgravy.com/skipping-past-the-4-types-of-sales-objections-podcast/)).

*Owl adaptation:* **classify before you respond.** Use Anchor–Disrupt–Ask only on reflex brush-offs such as "send me info," "we're all set," or "I'm busy." Structural "no"s are qualification data: no funding line, an active solicitation quiet period, an infeasible technical requirement, a policy barrier. Owl's real risk is misclassifying one as the other in either direction.

### Cadence, persistence, and when to stop

**[Book, as summarized]** The book is persistence-forward: 20–50 touches for cold prospects, daily phone blocks, and "one more call" (Ch 22). Its stopping rules are soft: about two turnaround attempts, then accept an honest no. **[Later author]** Undated Sales Gravy guidance scales cadence to complexity ([Sales Gravy, sequences](https://salesgravy.com/?p=16190)). Short-cycle sequences run 10–14 touches over 10–30 days at intervals of 2–3 days, and executives get touched no more often than every 2–3 days. Large, complex accounts run up to two years with monthly or quarterly touches. Silent prospects get pulled and recycled after 90 days to six months, and going dark after a prospect replies is the key failure. Blount-affiliated quit statistics (44%, 78% and 92% of sellers quitting after 1, 2 and 4 attempts) are unsourced; never repeat them as data ([Sales Gravy](https://salesgravy.com/our-greatest-weakness-is-giving-up-too-soon/)). *Owl adaptation:* the large-complex-account cadence fits Owl. Run a slow drumbeat of value touches plus bursts around triggers such as budget releases, RFIs and conferences, and recycle silent contacts with a new trigger instead of stalking.

### Emotional control from *Sales EQ*

**[Later author]** *Sales EQ* (Wiley, 2017) says disruptive emotions such as fear, desperation and attachment cause sellers to skip or mangle process steps ([Baylor Keller Center](https://kellercenter.hankamer.baylor.edu/news/story/2018/insider-sales-eq)). *Owl adaptation:* make it the pre-call check in CLAUDE.md. It pairs naturally with the Universal Law of Need.

### Limits and the effectiveness counterweight

No rigorous or controlled evaluation of the method was found, and no source evaluates it for government sales. Practitioner critiques call the email and social tactics dated, the approach outbound and field-sales flavored, and the numbers unsourced heuristics ([Berman](https://alexberman.com/fanatical-prospecting-review); [11x](https://www.11x.ai/guides/fanatical-prospecting-review)). The sharpest counterweight comes from Blount's own *AI Edge* coauthor. Anthony Iannarino argues that leaders inflate pipeline to 300–400% of quota, that activity metrics mask ineffectiveness, and that top performers often prospect *less* because they target companies that fit: **"More isn't better than better"** ([The Sales Blog, Sep 2023](https://thesalesblog.com/blog/excessive-focus-on-cold-outreach-and-pipeline)). *Owl adaptation:* keep the pipeline discipline and familiarity-building. Measure qualified conversations and second meetings, not dials. The weakest fits for Owl are texting, gatekeeper end-runs, high-volume cold calls into program offices, the 90-day payoff math, and raw touch counts.

---

## reference/linkedin.md: two speeds, Five S, and the 2026 feed

### The book runs on two speeds across five parts

**[Book]** *The LinkedIn Edge* has 40 chapters in five parts ([Wiley-VCH](https://www.wiley-vch.de/en/areas-interest/finance-economics-law/the-linkedin-edge-978-1-394-31671-7)):

| Part | Chapters | Key chapter titles |
| --- | --- | --- |
| 1. Fast Prospecting | 1–11 | Targeting Your ICP (2); Build Prospecting Lists Fast (3); Lists from Engagement Signals (4); Job Transition Trigger Events (5); LinkedIn Search for List Building (6); Prospecting Sequences (7); Soft LinkedIn Touches and Tags (8); InMail (9); Direct Messaging (10); Messages That Break Through the Noise (11) |
| 2. Slow Prospecting | 12–17 | Familiarity (12); A Slow, Deliberate Prospecting Journey (13); The Law of Cumulative Impact (14); Slow Prospecting Plan and Metrics (15); Managing Your LinkedIn Inbox (16); The BTN Method (17) |
| 3. Your Network Is Your Net Worth | 18–28 | The Seven People You Need in Your Network (19); Always Be Connecting (21); Sending Effective Connection Requests (22); Avoid the Bait-and-Switch Connection Request (23); Rules for Accepting Requests (24); Nurture Your Network (25); Multi-threading (26); From Cold Calls to Warm Introductions (27); Social Proximity and the Best Path In (28) |
| 4. Personal Branding and the Profile | 29–33 | If You Are Not a Brand, You Are a Commodity (29); Personal Brand Audit (30); The LinkedIn Profile Makeover (31); The Middle Hooks (32); Credentials and Credibility (33) |
| 5. Differentiation, Thought Leadership, Authority | 34–40 | Socially Surrounding Targeted Prospects with the Five S Framework (35); Streaming (36); Sharing (37); Stop the Scroll (38); Search and the LinkedIn Algorithm (39); Showing Up in Comments and Conversation (40) |

Section headings inside chapters come from O'Reilly's catalog, seen only through search-engine snippets ([O'Reilly TOC](https://www.oreilly.com/library/view/the-linkedin-edge/9781394316717/)). Treat them as strong but secondhand. Body text was not accessible.

**[Later author]** Blount defines **fast prospecting** as "interrupt, engage, convert," which fills the pipeline now. **Slow prospecting** is a deliberate series of touches over time that sets up a future buying window. Running both ends the feast-or-famine cycle. He calls "pump and pounce" (connect, then pitch immediately) one of the most important habits to stop ([Construction Disruption ep. 170, Oct 2025](https://construction-disruption.com/episode/ai-and-the-linkedin-edge-with-jeb-blount)). He describes LinkedIn as a sales "Swiss Army knife" but "not a panacea," to be paired with phone, email and other channels ([Sales Gravy](https://salesgravy.com/desperate-for-attention-in-a-noisy-prospecting-world/)). Mike Weinberg's jacket blurb sums up the system as "Thirty minutes a day on LinkedIn + smart prospecting sequences" ([Sales Gravy checklist page](https://salesgravy.com/resource/linkedin-profile-checklist/)).

*Owl adaptation:* two lanes. The **fast lane** holds an identifiable need or timely trigger, a relevant owner, and a direct request. The **slow lane** holds a strategic account or partner with plausible relevance but no buying window, nurtured with useful insight. Move items between lanes when evidence changes. A job change or engagement with a post is a reason to investigate, not proof of authority or funding.

### The Five S are visibility practices, not prospect research

**[Book: chapter titles]** v1 read "Scrolling" as studying prospects and "Searching" as finding them. **The chapter titles say otherwise.** All five are authority and visibility practices for "socially surrounding" targeted prospects. Prospect research lives in Part 1 (Ch 2–6).

| S | Chapter | Meaning (book title and subheads) | Owl action (adaptation) | Avoid |
| --- | --- | --- | --- | --- |
| **Streaming** | 36 | Creating and posting original content that builds authority | One accurate post on a real secure-data-movement or cross-domain problem | Vendor promotion, unsupported operational claims |
| **Sharing** | 37 | Authority through content curation | An authoritative public source plus Chris's interpretation | Reposting without saying why it matters |
| **Stop the Scroll** | 38 | Creative content that stops the reader's scroll | A first line and visual a CDS engineer would stop for | Engagement bait, clickbait |
| **Search** | 39 | "The Two Algorithms at Play," "Know What You Want to Be Found For," "Engineering the LinkedIn Algorithm" | Consistent keywords and topics so LinkedIn ties Chris to cross-domain and one-way transfer | Topic drift |
| **Showing Up** | 40 | Comments and conversation; a "10:1 method"; avoid "post-and-ghost" | About ten substantive comments for each post; reply to comments on his own posts quickly | AI-written comments, generic praise, pitching in comments |

**[Later author]** Tillman describes the 10:1 ratio as engaging with others' content about ten times for every post you publish, or 3–5 times a day if you don't post daily ([Social Sales Link ep. 398](https://socialsaleslink.com/podcast/episode-398-establishing-a-productive-daily-routine-on-linkedin-2025/)). Blount describes showing up as regularly liking, commenting, and tagging contacts in their successes: "The more that you do that, the more familiar you get" ([Construction Disruption ep. 170](https://construction-disruption.com/episode/ai-and-the-linkedin-edge-with-jeb-blount)).

### BTN means small but never zero

**[Book subheads, secondhand]** Ch 17's sections run "The BTN Methodology," "Why Doing 'Just a Little Bit' Matters More Than You Think," "Getting Past the Mental Hurdles," "Applying BTN to Prospecting," "The Law of Cumulative Impact," "Something Is Better Than Nothing," and "Adopt a No Zeroes Mindset" ([O'Reilly c17](https://www.oreilly.com/library/view/the-linkedin-edge/9781394316717/c17.xhtml)). No reachable source spells out "BTN," so leave it unexpanded. *Owl adaptation:* on a compressed day, answer one relevant message and make one useful contribution, then resume the normal plan the next day.

### The profile is a 15-step makeover, top to bottom

**[Book subheads, secondhand]** Ch 31–33 lay out a numbered makeover. **Ch 31, "Grabbing Attention Above the Fold," steps 1–6:** save a copy first; banner; headshot; headline; name pronunciation with an elevator pitch; contact details. **Ch 32, "The Middle Hooks," steps 7–10:** About; Featured; Services; Activity. **Ch 33, "Credentials and Credibility," steps 11–15:** Experience; Education; Licenses and Certifications; Skills and Endorsements; Recommendations. **[Later author]** The companion checklist says to write the headline as a prospect-facing elevator pitch, write About to the buyer's pain rather than career history, use Featured as social proof, frame Experience as a trust builder, and treat skills as keywords indexed by search engines, AI search included ([Sales Gravy checklist](https://salesgravy.com/resource/linkedin-profile-checklist/)).

*Owl adaptation:* audit from a mission stakeholder's chair. Can a reader tell what Chris works on and why a conversation might help? Do the About section and Featured items use only public, current, Owl-approved material? Is contacting him easy? A possible headline direction, to check against approved positioning: "Business Development, Owl Cyber Defense | Secure data movement across mission and industrial boundaries." Rank and clearance stay out of the headline and name field.

### Connections, introductions, and multi-threading

**[Book: Ch 22–28 titles]** The book covers effective connection requests, avoiding the bait-and-switch request, rules for accepting, multi-threading (with Sales Navigator's Relationship Explorer), and finding the "Best Path In" through mutual connections. A "GEAR" introduction framework appears in one snippet only. **[Later author, Tillman]** Never send a blank request; a short personal note arrives as an unread message and invites conversation. Triage inbound invitations three ways: accept and welcome if you'd want a networking conversation, reply before accepting if unsure, otherwise ignore. Never pitch on acceptance. Offer content before sending it ("if you're interested, I'll send you a link") ([Social Sales Link ep. 498](https://socialsaleslink.com/podcast/episode-498-stop-the-connect-and-pitch-start-earning-conversations-2026/)).

*Owl adaptation:* before asking for an introduction, verify who knows whom and how well. Give the connector a short, forwardable note and make declining easy. Never present a mutual connection as an endorsement or use one to bypass Owl's account owner. Multi-thread across the buying center in `reference/federal-bd.md`: titles alone don't establish influence, so record each person's actual role, concern, and ability to move the work.

### Blount's three AI mistakes on LinkedIn

**[Later author, Oct 2025]** (1) AI avatars. (2) "AIing it in," meaning sending AI messages unedited; a disclosed AI summary with a human note is fine. (3) Trusting AI output: "never trust, always verify," which he illustrates with an AI that invented a source ([Construction Disruption ep. 170](https://construction-disruption.com/episode/ai-and-the-linkedin-edge-with-jeb-blount)).

### Platform facts for 2025–26, with dates and evidence strength

| Fact | Date | Evidence | What to do (Owl adaptation) |
| --- | --- | --- | --- |
| **The feed is ranked by "Generative Recommenders, augmented with large language models."** LinkedIn favors relevance to members' professional interests over popularity, reads profile signals, and is "making engagement pods ineffective" while curbing comment automation and demoting engagement bait ([LinkedIn Newsroom](https://news.linkedin.com/2026/ImprovingTheFeed)) | 2026-03-12 | **Platform** (strongest) | Stay on topic; write his own comments; no pods, no "comment to agree" |
| **"360Brew" runs the production feed** — a 150B-parameter research model evaluated offline; paper later withdrawn; never confirmed in production ([arXiv 2501.16450](https://arxiv.org/abs/2501.16450); [media-all.in](https://media-all.in/en/blog/linkedin-360brew-ai-algorithm-explained/)) | 2025-01 | **Unverified** | Don't cite as fact |
| Reach for active creators down about 60% over two years; LinkedIn has shifted from a relationship graph to an **interest graph**; keep about 80% of posts on one topic; **2–4 posts a week**; reply within about 15 minutes; newsletters "way up"; native articles about 0.4× reach (van der Blom, *Algorithm Insights 2026*, 1.3M posts) ([Creator Science ep. 307](https://creatorscience.com/podcast/richard-van-der-blom-2/)) | 2026-06 | **Third-party data** (large, correlational, paywalled) | Directional only: topic discipline, fewer and better posts, stay with each post after publishing |
| **External links:** a LinkedIn product director reportedly said "We don't intentionally limit the reach of posts with links" ([Matt Navarra](https://www.threads.com/@mattnavarra/post/DOWa_61Cown/linkedin-says-posts-with-links-are-not-intentionally-penalized-for-reachlinkedin)); third-party estimates of the penalty range from about −19% to −60% ([Forbes](https://www.forbes.com/sites/jodiecook/2026/07/30/the-linkedin-link-penalty-cutting-your-reach-by-60/)) | 2025-09 / 2026-07 | Platform statement (secondhand) vs. third-party | Reasonable hedge, not proven: link in the first comment, or a native document |
| **Non-Premium members can personalize up to three connection requests a month, 200 characters each;** Premium can personalize all, though "limits may still apply" ([LinkedIn Help](https://www.linkedin.com/help/linkedin/answer/a563153)). A weekly invitation limit exists with no published number ([LinkedIn Help](https://www.linkedin.com/help/linkedin/answer/a550555)) | ~2026-05 | **Platform** | Spend the three notes on the best targets; otherwise comment first, use InMail, or get a warm intro |
| Sales Navigator **Account IQ** (AI account summaries) on Advanced and Advanced Plus, English-only, admin-enabled ([LinkedIn Help](https://www.linkedin.com/help/sales-navigator/answer/a1655021)); Lead IQ, Relationship Map and Relationship Explorer for buying groups; agentic Sales Assistant listed as beta ([LinkedIn](https://business.linkedin.com/sell/sales-navigator/ai-for-sales)). Natural-language AI search and Message Assist are vendor-reported only ([ZoomInfo](https://pipeline.zoominfo.com/sales/linkedin-sales-navigator-features)) | 2026 | Platform; vendor for 2026 additions | Whether to buy a seat is Owl's call; the book's multi-threading chapters assume one |
| **LinkedIn uses member data to train generative AI, on by default since 2025-11-03.** Opt out at Settings → Data privacy → "Data for Generative AI Improvement"; opting out affects only future use ([TechRadar](https://www.techradar.com/pro/linkedin-set-to-expand-ai-training-on-user-profiles-heres-how-to-stop-it-using-your-personal-data)) | 2025-11 | Third-party press | Opt out |
| No authoritative InMail reply benchmark; the largest cited dataset (Belkins, ~20M attempts) gives 6.38%, secondhand ([LinkedInsider](https://linkedinsider.blog/linkedin-inmail-response-rate)) | — | Third-party, weak | Don't forecast from it |

### Three OPSEC rules for a cleared defense-BD profile

1. **No clearance details, unit, billet, schedule, or travel on LinkedIn.** A joint NCSC/FBI/DCSA advisory tells clearance holders to "be careful what you post online about your work (particularly security clearances)" ([NCSC/FBI/DCSA, Apr 2025](https://archive.dni.gov/files/NCSC/documents/products/2025-04-08-NCSC-FBI-DCSA-OnlineTargetingUSGEmployees.pdf)).
2. **Verify unknown connection requests out-of-band before accepting**, especially self-described recruiters, consultants and think tanks. The same advisory says: "Don't accept online invitations to connect with strangers unless you can validate them first through other means." Red flags are flattery, urgency, pressure to move off-platform, and requests for paid "reports."
3. **Report suspicious approaches to Owl's security officer (FSO)** and to LinkedIn. Cleared contractor employees have reporting duties for suspicious contacts ([DCSA SEAD 3 desktop aid](https://www.dcsa.mil/Portals/91/Documents/CTP/tools/SEAD3_REPORTING_DESKTOP_AID_FOR_CLEARED_INDUSTRY.pdf)).

---

## reference/ai-edge.md: AI drafts, Chris authors

### Seven parts, and half the book is sales fundamentals

**[Book]** *The AI Edge* (Wiley, September 2024, 304 pp.) has 40 chapters in seven parts: **Plugging into AI** (1–5), **Robot Rules** (6–10), **More Time to Sell More** (11–18), **Writing, Grammar, and Communication** (19–22), **Prospecting** (23–29), **Qualifying, Pre-call Planning, Discovery** (30–34), and **Close the Deal** (35–40) ([Wiley-VCH](https://www.wiley-vch.de/en/areas-interest/finance-economics-law/the-ai-edge-978-1-394-24447-8)). Chapter contents come from Wiley's own 40-module Coursera course "built on the book" ([Coursera](https://www.coursera.org/learn/wiley-the-ai-edge-unlocking-ai-for-sales-efficiency-and-growth)), labeled **Book, as summarized**. Iannarino wrote that "much of what you find here is found in AI Edge" about his June 2024 AI rules, so those rules count as the coauthor's view of the book ([The Sales Blog](https://www.thesalesblog.com/blog/rules-for-using-artificial-intelligence-in-b2b-sales)). The book was written on 2023–24 tools, before agents, so its tool advice is dated. The principles (verify, edit, protect time, keep live conversation human) recur in the authors' 2025–26 material.

### Named frameworks and their status

| Framework | Ch | Evidence | Content | Owl use (adaptation) |
| --- | --- | --- | --- | --- |
| **Four Elements of Sales Intelligence (IQ, AQ, EQ, TQ)** | 5 | Book; definitions from summaries | Innate, acquired, emotional and technological intelligence working together ([getAbstract](https://www.getabstract.com/en/summary/50361)); carried over from *Sales EQ* Ch 5 ([O'Reilly](https://www.oreilly.com/library/view/sales-eq/9781119312574/c05.xhtml)) | **AQ, acquired domain knowledge (CDS, NCDSMO and RTB, acquisition, budget), is Chris's moat.** AI feeds it and never replaces it |
| **Robot Rules** | Part 2; Ch 10 | Book (part and chapter); rule list not retrieved | Unreliable output (Ch 6 "Liar, Liar, Pants on Fire"), anthropomorphism (Ch 7), authority bias (Ch 8), Asimov framing (Ch 10) | Source, date and confidence on every AI claim. Military culture defers to authoritative-sounding briefs, so watch authority bias |
| **Me Management** | 12 | Book | Treat your time like a CEO; tools can't supply discipline | Golden Hours discipline |
| Attention control and time blocking | 13 | Book | Focus; the cost of interruptions | Outreach blocks timed to when contacts are reachable |
| **The First Seven Steps** / "three A's" | 15 | Book (chapter and term); steps not retrieved | One summary paraphrases the A's as commit, adapt, practice | Don't quote the steps |
| **Time Investment Audit** | 16 | Book; method as summarized | Log 15- or 30-minute blocks for about a week; sort into revenue work, support, and distractions ([sobrief](https://sobrief.com/books/the-ai-edge)) | `/time-audit` |
| **Practice and Prompts; sales prompt library** | 18 | Book (course readings "Practice Building a Prompt," "Build a Sales Prompt Library") | Task plus context plus format; state the purpose; save and iterate | The skills are the library; version them in the changelog |
| Writing and editing | 19–22 | Book | "If It Quacks Like a Duck" (AI writing is detectable); "The Power of Editing"; "AI Is a Faster Writer; You Are a Better Human" | **Chris is editor and author of record** |
| **The Asynchronous Seller; Synchronous vs. Asynchronous Prospecting** | 23–24 | Book | Real-time vs. delayed outreach; a cautionary rep whose whole routine was mass AI email | Synchronous: phone, shows, industry days, sponsor visits. Asynchronous: email, LinkedIn, white papers, RFI responses |
| Sequences, Targeted Lists, Message Matters | 26–28 | Book | Multichannel cadence; define the ICP before intent data and scoring; insight beats scraped flattery | Government signals replace commercial intent data |
| **Slow Prospecting** | 29 | Book | Personal brand and consistent LinkedIn content | Same idea as *LinkedIn Edge* Part 2 |
| **Eight Big Discovery Mistakes** | 32 | Book (chapter); the eight not enumerated in any source reached | Themes: self-orientation, poor listening, poor preparation (course); rigid checklists, pitching too early (summaries) | Feed `/roleplay` scoring |
| AI-powered proposals; contracts and terms | 36, 39 | Book | Personalization; spotting key clauses | Compliance-matrix help and first-pass clause spotting only. No CUI-marked RFP content or pricing in unapproved tools; contracts and legal own the review |
| AI Turns Your CRM into a Strategic Partner | 40 | Book | A CRM is only as useful as its data | With few deals, use deterministic counts |
| "Murder boarding" | Unknown | Unverified (summary only) | A team hunts for every reason a big deal could fail | Same idea as a capture black-hat review; `/roleplay` can play the competitor |

### The human/AI line: AI may draft; it never authors, sends, or speaks for Chris

Both authors have held one position since the book: **AI for preparation, research, data and editing; humans for anything that touches the buyer.** The publisher frames AI as saving time while leaving room for creativity, empathy and authenticity ([Wiley-VCH](https://www.wiley-vch.de/en/areas-interest/finance-economics-law/the-ai-edge-978-1-394-24447-8)).

**[Later author] Iannarino's five rules (Jun 4, 2024):** don't use AI to automate cold outreach; don't let AI write alone, because buyers spot AI wording; do use AI for client research (company, competitors, headwinds and tailwinds); do use it to explore deal and pipeline data and ask it to explain its reasoning; and don't rely on summaries for client research, because they drop context ([The Sales Blog](https://www.thesalesblog.com/blog/rules-for-using-artificial-intelligence-in-b2b-sales)). His **eight alternatives** to automated outreach (Aug 16, 2024) fit defense BD better than SaaS: LinkedIn introductions, client referrals, in-person visits, insight-led physical mail, networking events, industry conferences, substantive FedEx envelopes, and thank-you notes to everyone who said no ([The Sales Blog](https://www.thesalesblog.com/blog/how-to-navigate-the-ai-driven-cold-outreach-apocalypse-8-proven-strategies-for-b2b-sales-success)). In May 2025 he called replacing salespeople with AI a mistake, because AI errors are unaffordable in complex enterprise deals ([The Sales Blog](https://www.thesalesblog.com/blog/why-replacing-human-salespeople-with-ai-is-a-mistake-for-b2b-companies)).

**[Later author] Blount:** "Never let AI write emails or make calls on your behalf" and "never trust, always verify." He calls AI-built intelligent prospecting lists "the biggest opportunity" ([Sales Gravy, ~Sep 2025](https://salesgravy.com/can-ai-really-replace-salespeople-ask-jeb/)). The test of success is that **"AI should give you more time to be human."** AI cut his large-proposal prep from about half a day to about an hour, and he reinvested the time face to face ([Sales Gravy, ~Mar 2026](https://salesgravy.com/ai-will-not-kill-sales-but-it-will-punish-mediocrity-ask-jeb/)). His starter plan: pick one available tool (company-provided first), pick one recurring time drain, state the task directly, and iterate on the first output as you would coach a new hire ([Sales Gravy, ~Oct 2025](https://salesgravy.com/how-to-start-using-ai-in-sales-ask-jeb/)). The Sales Gravy dates are inferred from image paths.

*Reconciling the tension:* the book includes AI-assisted messaging and AI-drafted sequences (Ch 26–28), yet Blount says never let AI write emails. Resolve it as **AI drafts; Chris edits, owns and sends.** Never add deliberate errors to look human. Human involvement means owning the message and its claims.

### Prompt patterns worth keeping

These are Owl adaptations of Iannarino's published prompts ([The Sales Blog, Sep 2024](https://www.thesalesblog.com/blog/mastering-ai-driven-editing-and-research-prompts-a-guide-for-content-creators-and-sales-professionals)):

- **Headwinds and tailwinds:** "For [mission area or program office], list 10 headwinds and 10 tailwinds affecting cross-domain data movement, each with two dated public data points (budget justification books, GAO or IG reports, official announcements). Label anything unverified."
- **Discovery questions by role:** ten questions each for an ISSM or ISSO, a mission owner, a PM or PAE staffer, a prime's architect, and a contracting officer before solicitation. Iannarino says such lists point the right way but need tightening, and Chris tightens them.
- **Copyedit pass** on Chris's own drafts: the low-risk, high-value daily use.
- **Contract reciprocity check**, reframed as first-pass issue-spotting on flow-downs and data rights. Contracts and legal own the result.

### What independent evidence says about AI in selling

- **Buyers validate AI with people.** Gartner (May 20, 2026; 645 B2B buyers surveyed Aug–Sep 2025) found that **69% prefer to validate AI-generated insights with a sales rep**. **51% say they are more likely to meet misleading information from GenAI, and 49% from sales reps** ([Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-05-20-gartner-survey-finds-sixty-nine-percent-of-b-two-b-buyers-turn-to-sales-reps-to-validate-ai-generated-insights)). Buyers distrust both sources about equally, so a rep's edge is verifiable, sourced specifics.
- **AI fails confidently outside its frontier.** In a BCG field experiment, consultants using GPT-4 gained heavily on tasks inside AI's capability. On a task outside it, they were about 19 percentage points less likely to be correct ([Dell'Acqua et al., 2023](https://mitsloan.mit.edu/sites/default/files/2023-10/SSRN-id4573321.pdf)). Niche defense-program facts likely sit outside the frontier for general models.
- **Gains are largest for novices.** Support agents resolved 14% more issues per hour on average and about 34% more for novices, with minimal gains for the most experienced ([Brynjolfsson, Li & Raymond, NBER](https://www.nber.org/papers/w31161)). AI likely helps Chris most on BD mechanics and least on mission judgment, where his own judgment should win.
- **No rigorous study was found** comparing reply rates for AI-written and human-written B2B outreach. Claims either way come from vendors. All buyer data is general B2B, so applying it to DoD and IC buyers is an inference.

### Workflow map with a finish line

| Workflow | AI contribution | Chris's responsibility | Finished when |
| --- | --- | --- | --- |
| Account research | Organize public evidence and unknowns | Decide whether the target matters | One relevant outreach hypothesis exists |
| List preparation | Deduplicate and cluster approved records | Validate ownership and fit | A small usable batch is ready |
| Meeting preparation | Draft questions and alternative explanations | Choose the conversation objective | Chris can state what he wants to learn |
| Role-play | Simulate a skeptical stakeholder | Practice listening and clear requests | One behavior improves |
| Debrief | Structure notes and draft actions | Correct facts and commitments | A reliable follow-up and CRM note exist |
| Proposal support | Map requirements to approved evidence | Validate solution, scope, price, commitments | Review gaps are explicit |
| Pipeline review | Flag missing fields and unsupported assumptions | Decide advance, nurture, or kill | Every active item has a defensible next step |

---

## reference/federal-bd.md: prospect before the RFP, qualify on four clocks

Blount's model runs on one clock: seller activity becomes pipeline. Federal BD adds four that the seller doesn't control. They are the **communication window**, the **budget**, the **contract vehicle**, and, for cross-domain work, **baseline listing and authorizing-official approval**. Everything here is Public record or Owl adaptation, dated as of 2026-11-13. Rows marked ⟳ appear in `reference/time-sensitive-facts.md`.

### Talk freely before release; after release, only the contracting officer

**[Public record]** FAR 15.201(a): "Exchanges of information among all interested parties, from the earliest identification of a requirement through receipt of proposals, are encouraged." FAR 15.201(c) lists encouraged techniques: industry conferences, market research, one-on-one meetings with potential offerors, presolicitation notices, draft RFPs, RFIs, preproposal conferences and site visits. **FAR 15.201(f): "after release of the solicitation, the contracting officer must be the focal point of any exchange with potential offerors,"** and specific information given to one offeror must be made public ([FAR 15.201](https://www.acquisition.gov/far/15.201)). Separately, the Procurement Integrity Act bars "a person" from knowingly obtaining bid, proposal or source-selection information before award ([41 USC 2102](https://www.law.cornell.edu/uscode/text/41/2102)).

⟳ The FAR overhaul's Part 15 rewrite (FAR Case 2026-003) was proposed 2026-09-18 and was not final as of November 2026 ([Federal Register](https://www.govinfo.gov/content/pkg/FR-2026-09-18/html/2026-19162.htm)). DoD is reportedly operating under a class deviation for Part 15/215 ([Open FAR Cases, DPAP](https://www.acq.osd.mil/dpap/dars/opencases/farcasenum/far.pdf)); verify the number on acquisition.gov. Official acquisition material now also uses "Department of War" naming, so search under both names.

*Owl adaptation:* run the pre-contact check on every outreach (open solicitation? Owl owner?). After release, stop outreach on that procurement except through the contracting officer, and redirect effort to the proposal, teaming, and the next opportunity.

### Blount fits Shipley's early phases and fails its late ones

Shipley's lifecycle has seven phases separated by decision gates, and its "bid less, win more" advice says not to spend effort where you can't win ([Shipley lifecycle](https://www.shipleywins.com/tools-and-guidebooks/business-development-lifecycle-chart); [Shipley](https://www.shipleywins.com/blogs/bid-less-win-more)).

| Shipley phase | Blount fit (Owl adaptation) |
| --- | --- |
| 0 Market segmentation | ICP and targeted lists (*LinkedIn Edge* Ch 2–6; *AI Edge* Ch 27). Pyramid levels 1–2 |
| 1 Long-term positioning | **Strongest fit.** Law of Familiarity, slow prospecting, Five S, speaking at events |
| 2 Opportunity assessment | Four Objectives (information and qualification), funding levels, Pyramid levels 3–6 |
| 3 Capture planning | Multi-threading, prime and partner prospecting, RFI and draft-RFP responses. Full activity while pre-release |
| 4 Proposal planning | **Solicitation release is the switch:** outreach on this procurement goes to the contracting officer only; keep prospecting the next one |
| 5 Proposal development | Proposal support (*AI Edge* Ch 36); no relationship selling on this buy |
| 6 Post-submittal | Contracting-officer channel until award; then nurture and expand |

Phase numbering varies by source. The trigger that matters is solicitation release, not the phase number.

### A budget request is not money: six funding-evidence levels

**[Public record]** PPBE produces DoD's share of the President's Budget request, usually submitted in February ([CRS IF10429](https://www.everycrsreport.com/files/2024-12-06_IF10429_e43a53a1488617df1634ff184030ae37cbab7dde.pdf)). Continuing resolutions usually bar new starts and production-rate increases; in FY2018 DoD identified about 75 programs delayed by the new-start ban ([CRS R45870](https://www.everycrsreport.com/reports/R45870.html)).

| Level | Funding evidence | Meaning |
| --- | --- | --- |
| 0 | Interest, publicity, conference talk | Investigate, don't forecast |
| 1 | Named in a strategy, priority list, or unfunded-priorities list | Demand signal, no money |
| 2 | In the President's Budget request, with the program element or line identified in R-1/P-1 exhibits and justification books | Requested, not available |
| 3 | Authorized in the NDAA | Permitted, not funded |
| 4 | Appropriated for the full year (mark "CR-blocked" if it's a new start under a CR) | Money exists |
| 5 | Apportioned and obligated on a vehicle | Money on contract |

⟳ **As of mid-November 2026, no FY2027 defense appropriation had been enacted. DoD was running on a continuing resolution (P.L. 119-103, signed 2026-09-02) at FY2026 levels through 2026-12-11** ([CRS R49353](https://www.congress.gov/crs-product/R49353)). The CR reportedly carries the usual new-start ban ([ClearanceJobs](https://news.clearancejobs.com/2026/10/01/the-pentagon-starts-fiscal-2027-on-a-stopgap-heres-how-it-affects-defense-jobs/)). Request-level signals can be large: the FY2027 request seeks $75B for drones and counter-drone ([Defense News](https://www.defensenews.com/pentagon/2026/07/02/hegseth-creates-powerful-new-drone-office-pulling-authority-from-the-military-services/)). Still, a request is level 2. *Owl adaptation, reasoned not sourced:* a need first surfacing in late 2026 likely can't get its own line before the FY2028 budget. The near-term paths are existing lines, O&M, reprogramming and year-end money. For R-1/P-1 and justification-book work, use Chris's `budget-mining` skill if it's installed.

### The vehicle is often the real buying decision

| Vehicle | What it is and its status | BD use (Owl adaptation) |
| --- | --- | --- |
| Existing contracts, resellers, prime subcontracts | Whatever the customer can already order through | Often the fastest path; ask early |
| ⟳ **NASA SEWP VI** | Awards announced June 2026: **2,115 awards to about 1,490 vendors**; ordering period **2026-11-01 to 2036-10-31**; $20B ceiling per award; SEWP V continues through 2027-04-30; protests filed; go-live not confirmed ([Nextgov](https://www.nextgov.com/modernization/2026/06/nasa-names-2100-winners-sewp-vi/414347/); [Federal News Network](https://federalnewsnetwork.com/contractsawards/2026/06/more-sewp-for-contractors-as-nasa-expands-total-awards/)) | Check whether Owl or its resellers hold SEWP VI positions, and confirm with approved Owl material |
| **Commercial Solutions Opening (10 USC 3458)** | DoD may buy commercial products, services and nondevelopmental items through a general solicitation; it counts as competitive procedures, contracts are fixed-price, and follow-on production can be sole-source. ⟳ FY2026 NDAA §1823 struck the "innovative" limitation and the written determination for awards over $100M ([10 USC 3458](https://www.law.cornell.edu/uscode/text/10/3458)) | A fit for commercial, baseline-listed CDS |
| ⟳ **DIU CSO leading to a prototype OT (10 USC 4022)** | Solution brief, then pitch, then proposal; awards "in as few as 60-90 days, although our current average is closer to 120 days"; follow-on production possible without new competition ([DIU](https://diu.mil/work-with-us)). 2026 priorities narrowed to autonomous warfare, kill webs and "10x technologies" ([DefenseScoop](https://defensescoop.com/2026/07/06/diu-reshaping-tech-priorities-under-new-leadership-owen-west/)) | Kill webs are adjacent to Owl's space through data moving across classification levels |
| ⟳ **SBIR/STTR** | Lapsed 2025-09-30; **reauthorized through 2031-09-30** by S. 3971, signed 2026-04-13, adding a Phase II "strategic breakthrough" award up to $30M and more foreign-risk screening ([SBA](https://www.sba.gov/article/2026/04/13/administrator-loeffler-applauds-sbir-sttr-reauthorization); [Crowell & Moring](https://www.crowell.com/en/insights/client-alerts/sbirsttr-programs-reauthorized-after-six-month-lapse)) | Use if Owl or a partner qualifies; otherwise a subcontract role |

### The buyers moved: Portfolio Acquisition Executives replace PEO maps

**[Public record]** EO 14265 (2025-04-09) sets a "first preference for commercial solutions and a general preference for Other Transactions Authority" ([White House](https://www.whitehouse.gov/presidential-actions/2025/04/modernizing-defense-acquisitions-and-spurring-innovation-in-the-defense-industrial-base/)). The Secretary's 2025-11-07 memo, "Transforming the Defense Acquisition System into the Warfighting Acquisition System," reorganizes PEOs into **Portfolio Acquisition Executives** that are "held solely accountable for outcomes" and supervise contracting officers. It also sets a "two-to-production" competition standard, MOSA module-level competition, and "persistent test environments for rapid certification" ([Inside Government Contracts](https://www.insidegovernmentcontracts.com/2025/12/from-das-to-was-secretary-hegseths-acquisition-overhaul-and-what-it-means-for-industry/)). The FY2026 NDAA (P.L. 119-60, signed 2025-12-18) makes PAEs statutory in §1802, with authority over portfolio plans, budgets and execution, and directs them to prioritize prototype transactions. §1833 lets PAEs request DIU help. §1826 exempts nontraditional defense contractors from specified DFARS clauses, TINA, and FAR Part 31 ([Greenberg Traurig](https://www.gtlaw.com/en/insights/2026/2/fy2026ndaa/fy-2026-ndaa-the-substantial-impact-of-the-fiscal-year-2026-national-defense-authorization-act-on-federal-procurement-law)).

⟳ **Implementation:** the Army has six PAEs, including "Command and Control and Counter-Command and Control" ([DefenseScoop](https://defensescoop.com/2025/11/14/army-acquisition-reform-2025/)). The Navy reportedly has nine, with PAE Aviation established 2026-05-11 ([NAVAIR](https://www.navair.navy.mil/news/Navy-Establishes-Portfolio-Acquisition-Executive-Aviation/Mon-05112026-0943); [Breaking Defense](https://breakingdefense.com/2026/08/top-cover-and-clear-metrics-how-to-make-the-new-pae-structure-work/)). The Air Force finished consolidating into 17 PAE-led organizations in July 2026, including C3BM and NC3 ([DefenseScoop](https://defensescoop.com/2026/08/06/air-force-portfolio-executives-acquisition-reform/)).

*Owl adaptation:* rebuild account maps around PAEs, because maps keyed to old PEO names will decay. The commercial-first, fixed-price, OT-friendly direction favors a vendor with commercial baseline-listed products. "Two-to-production" competition makes incumbency less durable, so keep prospecting inside won accounts.

### Cross-domain sales clear a baseline gate and an approval gate

**[Public record, partly via search excerpts; verify the primary text]** NSA's NCDSMO released **Raise the Bar** in 2018 as its CDS security standard. It applies to all CDS protecting US Government classified information "and all of those sold for export" ([NSA NCDSMO](https://www.nsa.gov/Cybersecurity/Partnership/National-Cross-Domain-Strategy-Management-Office/); [Green Hills explainer](https://www.ghs.com/products/safety_critical/integrity_178_standards_raise-the-bar.html)). Under **DoDI 8540.01** (2015, Change 1 2017), operating a CDS that isn't on the baseline list requires a letter of exception, and sunset or legacy CDS must be replaced within a period the authorizing official and the DoD risk executive agree ([DoDI 8540.01](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/854001p.pdf)). NIST's glossary describes the baseline and sunset lists as NCDSMO-managed ([NIST](https://csrc.nist.gov/glossary/term/cross_domain_solution_baseline_list)). Vendors reach the baseline by passing a Lab-Based Security Assessment; recent competitor listings include Everfox MESA ([ExecutiveBiz](https://www.executivebiz.com/articles/everfox-mesa-ncdsmo-baseline-cross-domain-sharing)). Army policy says Army organizations "must only request use of CDSs approved by" NCDSMO ([Army CIO PPM-016](https://www.armyng.com/2024/04/ppm-cio-016-army-cross-domain-solution.html)). DISA's connection process covers CDS connections to the DISN ([DISN CPG](https://dl.dod.cyber.mil/wp-content/uploads/connect/CPG/ConnProcGuide.html)). Owl has publicly announced an NCDSMO baseline listing for a new version of its voice/video CDS ([Owl press release](https://owlcyberdefense.com/news/owl-cyber-defense-announces-ncdsmo-baseline-listing-for-new-version-of-v2cds/)); confirm current status with approved Owl material before citing it. The baseline and sunset lists themselves are not public.

*Owl adaptation:* the gate is both a moat and a delay. The pipeline splits into **replacement demand** from sunset and legacy lists, which is predictable, and **new-mission demand**. Even with money and a vehicle, deployment needs AO approval and connection steps, so cycle-time estimates must include accreditation.

### The CDS buying center has eleven roles

| Role | Cares about | Source |
| --- | --- | --- |
| Mission owner / operational user | The data-flow pain and operational effect; the demand signal | Practitioner |
| Program manager or PAE staff | Portfolio budget, schedule, vehicle | Public record (PAE) |
| Contracting officer | Process integrity; sole channel after release | FAR 15.201(f) |
| ISSM / ISSO | RMF package; runs the CDS request | Practitioner |
| Authorizing official and DoD risk executive | Deployment approval; exceptions; replacement timelines | DoDI 8540.01 |
| Component CDSE / CDSO | Baseline compliance; may steer to an enterprise service | Army PPM-016 |
| Enterprise CDS provider (GP-ECDSP, MS-ECDSP) | Both a competitor-substitute and a channel | [NDIA 2022](https://ndia.dtic.mil/wp-content/uploads/2022/systems/Thurs_24541_Boyd.pdf) |
| NCDSMO | Baseline listing and RTB compliance; a vendor relationship, not a sales target | NSA |
| DISA connection approval | DISN connection process | DISN CPG |
| Prime integrator | Often the actual buyer of the box inside a larger program | Practitioner |
| CDS engineers and test labs | Technical credibility, integration evidence | Practitioner |

Score stakeholder coverage against this list.

### Five places where Blount's model needs a rewrite

1. **"Ask for the meeting" during an open solicitation** is effectively prohibited, because the contracting officer is the focal point.
2. **A government contact's enthusiasm is not commitment.** Real next steps are institutional: issue an RFI, invite to an industry day, schedule a technical exchange, add to market research, request a quote for a budget estimate, sponsor an SBIR topic, write a letter of support, request a demo in a test environment.
3. **"No budget" isn't an objection to turn around.** Ask which program element or line, which POM year, whether it's on an unfunded-priorities list, and whether year-end, O&M or reprogramming money exists. Then nurture on the budget calendar.
4. **Velocity metrics need phase gates.** Track funding level, vehicle, solicitation status and CDS approval path alongside activity; see `reference/qualification-and-crm.md`.
5. **Free engineering as discovery** wastes scarce capacity and can create an organizational-conflict-of-interest risk if Owl ends up shaping a competitive spec (FAR 9.5 ([FAR subpart 9.5](https://www.acquisition.gov/far/subpart-9.5))). Flag it for counsel. Don't resolve it yourself.

### Tactics stack for a cross-domain vendor (Owl adaptation)

- **Opportunity monitoring:** watch SAM.gov sources-sought notices, RFIs and CSO calls for "cross domain," "one-way," "data diode," "CDS" (example: [SAM.gov notice](https://sam.gov/opp/55dce222b6b14bf7acb67e22629ff4fb/view)). Answer every relevant RFI; the response itself builds the relationship inside the legal window.
- **Budget mining:** use PB justification books, NDAA report language and appropriations marks to find lines touching C2, NC3, ISR, OT/ICS and enterprise network defense. Re-check when the CR resolves.
- **PAE mapping:** rebuild account maps around the new PAEs.
- **CSO, OT and DIU watch.**
- **Prime and partner channel:** the highest-yield place for Blount-style volume, because company-to-company prospecting has no FAR quiet period (teaming and NDA discipline still apply).
- **Conferences** (candidate venues, unsourced practitioner knowledge: AFCEA TechNet Cyber, AFCEA West, NDIA events, AUSA). Plan hub-and-spoke meetings around them. A USMC-focused event sits close to guardrail 2, so flag it.
- **Test events and "persistent test environments"** promised by the acquisition memo, as a way to show a baseline-listed CDS in operational context.

---

## reference/owl-context.md: qualify the data flow before the product

### Working context, and five motions to keep separate

**[User context]** Chris's themes include cross-domain solutions, one-way data movement, defensive cyber operations, tactical and enterprise environments, voice/video/data integration, and possible AI-containment applications. His stated preferences are capability fit, externally funded development, adjacent relationships, useful measurement, and protecting engineering capacity. These themes mark areas to investigate; they don't establish product availability or suitability. Historical relationship references are leads to verify, not active opportunities.

| Motion | Goal |
| --- | --- |
| Direct customer discovery | Understand a concrete mission need and its owner |
| Partner development | Establish complementary capabilities, access, responsibilities, and economics |
| Program positioning | Find requirements and decision points early enough to matter |
| Funded development | Establish a sponsor, a funding route, bounded work, and a transition purpose |
| Nurture | Maintain useful contact where timing or fit is unresolved |

### Qualification grid for a data-movement problem

Use it selectively; don't interrogate a first contact with every row.

| Dimension | Questions to resolve |
| --- | --- |
| Mission consequence | What task is impeded? Who feels it? How is it handled today? |
| Data | What must move: formats, protocols, volumes, timeliness, fidelity? |
| Boundary | Between which systems, networks, trust levels, or organizations? What may cross? |
| Direction | Is one-way enough? Are acknowledgments, control traffic, or return data needed? |
| Environment | Enterprise, tactical, industrial, platform, cloud, or mixed? Physical and operational limits? |
| Assurance | Who sets the security requirements and approval process? What evidence is needed? |
| **CDS approval** | Baseline-listed product? Letter of exception? Which AO, CDSE, or enterprise provider is involved? |
| Integration | Who owns interfaces, deployment, sustainment, and test? What existing components constrain the design? |
| Decision process | Who owns the requirement, architecture, budget, acquisition path, and final decision? |
| **Funding** | Which level, 0–5? Which program element or line? Is it CR-affected? |
| **Vehicle** | Which contract, GWAC, CSO, OT, SBIR, or prime path can the government actually use? |
| **Solicitation** | Is a solicitation open or pending? If released, the contracting officer only |
| Timing | What event creates urgency? What happens if nothing changes? |
| Owl fit | Which approved capability is relevant? What remains an engineering question or gap? |

Don't infer a classified-domain crossing just because a customer says "sharing data." Don't assume one-way enforcement alone meets a whole security or authorization requirement.

### Triage: four calls, plus an optional score

| Call | When | Equivalent in `opportunity-assessment`, if installed |
| --- | --- | --- |
| **Pursue now** | Credible need, reachable stakeholder, plausible current capability, a defined next discovery or validation step | Promote |
| **Investigate briefly** | Attractive adjacency with one or two decisive unknowns that are cheap to resolve | Continue validation |
| **Nurture** | Plausible strategic value; no current timing, sponsor, or fit evidence | Monitor |
| **Disqualify or pause** | No relevant problem, incompatible requirement, disproportionate unfunded engineering, no legitimate access, or no meaningful next step | Deprioritize or kill |

Optional comparison score: rate mission relevance, capability fit, access, timing and funding evidence, and reusable strategic value from 0 to 2 each, with a reason and confidence label beside each score. Rate engineering effort separately (low, medium, high, unknown). Never convert the total into a win probability, and never let strong scores cancel a critical technical or access constraint. For funded development, ask what the sponsor will fund, which milestone it buys, who approves the work, what Owl contributes, and how the result transitions. Expressed interest in innovation is not funding.

### Protect relationships across Owl

Before approaching a known partner or major account, identify Owl's relationship owner and current engagement, and coordinate through them. Claude can draft the internal coordination note but doesn't send it. For a partner, clarify each side's contribution (customer access, integration, product, services, certification support, deployment, sustainment), who contracts with whom, and the concrete next joint action. Don't call a friendly conversation "teaming" until responsibilities are understood.

---

## reference/qualification-and-crm.md: HubSpot fields that carry federal reality

HubSpot is the system of record. Map these fields to HubSpot deal, contact and company properties rather than building a competing system. HubSpot's official MCP server reads and writes core CRM objects and engagements ([HubSpot MCP](https://developers.hubspot.com/mcp)). The fields marked `# new` are the federal additions in v2.

```yaml
account:
  name: null
  internal_relationship_owner: null
  account_type: null            # government / prime / integrator / platform / reseller / partner / other
  pae_or_peo: null              # new: current portfolio owner; PEO-keyed maps decay as PAEs stand up
contact:
  name: null
  current_role: null
  role_verified_on: null
  buying_role: null             # new: mission owner / ISSM-ISSO / PM-PAE staff / contracting officer / AO / CDSE / ECDSP / prime architect / partner BD / other
  professional_contact_route: null
  relationship_source: null     # an Owl or public source; never Reserve duty
  communication_preferences: null
discovery:
  mission_problem: null
  customer_statement: null
  evidence_source_and_date: null   # a public or approved source for every account fact
  analyst_inference: null
  source_environment: null
  destination_environment: null
  data_and_direction: null
  operational_constraints: null
  approval_authority_or_path: null
  cds_baseline_status: unknown  # new: listed / not_listed / letter_of_exception / sunset_replacement / n_a
  ao_path: null                 # new
  current_workaround: null
  consequence_of_inaction: null
opportunity:
  record_type: discovery_lead   # target / discovery_lead / qualified_opportunity / nurture / disqualified
  lane: null                    # new: fast / slow
  pyramid_level: null           # new: 1-6
  shipley_phase: null           # new: 0-6
  sponsor: null
  decision_participants: []
  timing_trigger: null
  funding_evidence_level: 0     # new: 0-5 per reference/federal-bd.md
  pe_or_line_item: null         # new
  cr_blocked: false             # new
  vehicle: null                 # new: existing / GSA / SEWP / CSO / OT / SBIR / via_prime / unknown
  solicitation_status: none_known  # new: none_known / rfi_sources_sought / draft / released_quiet / awarded
  prime_partner: null           # new
  approved_capability_reference: null
  technical_gaps: []
  engineering_effort: unknown
  partner_roles: []
  competing_options_including_status_quo: []
  qualification_gaps: []
  conflict_flag: none           # new: none / reserve_overlap / oci_review / other (flagged for counsel)
next_step:
  action: null
  owner: null
  due_date: null
  buyer_agreed: false
  government_step_type: null    # new: rfi / industry_day / technical_exchange / demo / market_research / quote_for_estimate / sbir_topic / letter_of_support / none
  intended_learning_or_decision: null
review:
  evidence_confidence: unknown
  last_meaningful_engagement: null
  next_review_date: null
  disposition_reason: null
```

**Header row for `data/pipeline.csv`:**

```text
id,account,contact,buying_role,record_type,lane,pyramid_level,shipley_phase,funding_evidence_level,vehicle,solicitation_status,cds_baseline_status,next_action,owner,due_date,buyer_agreed,last_meaningful_engagement,evidence_gap,conflict_flag,hubspot_id,updated
```

**Rules for the record.** Use null or "unknown" honestly, and never fill an empty field with a plausible assumption. Don't create an active opportunity to satisfy a dashboard. Record which missing facts block qualification and which can stay open at an early stage. An internal research task can be a next step but is not evidence of buyer commitment, so mark the difference.

---

## reference/rhythm-and-metrics.md: count conversations and gates, not dials

### A two-week pilot rhythm built on Golden and Platinum Hours

This is an Owl adaptation, not a Blount prescription. Adjust it to travel, customer hours and conversion evidence.

| Cadence | Practice | Book anchor | Output |
| --- | --- | --- | --- |
| Daily, 10 min (Platinum) | `/bd-day`: review commitments, pick three external outcomes | Golden/Platinum Hours (FP Ch 8) | Short action list |
| Daily, 30–60 min (Golden) | Live outreach and follow-up only | Golden Hours; Balanced Prospecting (FP Ch 4) | Conversations |
| Daily, 15–30 min | LinkedIn: replies, a few substantive comments, one connection or intro action | Slow prospecting; "thirty minutes a day" | Replies, access |
| After consequential calls, 5–10 min | `/crm-debrief` | Own Your Database (FP Ch 11) | CRM-ready note |
| End of day, 5 min | Prepare tomorrow's first targets | Platinum Hours | Ready list |
| Weekly, 30 min | `/pipeline-review` | Law of Replacement (FP Ch 5) | Promote, validate, nurture, pause, or kill decisions |
| Weekly, 15 min | `/roleplay` one hard exchange | RBO turnarounds (FP Ch 16) | One improved behavior |
| Weekly, one block | One public insight or account brief | Streaming and Sharing; Law of Familiarity | Reviewed material |
| Monthly | `/bd-monthly` | — | Refreshed facts, changelog |

A conference day meets the external-engagement objective through purposeful conversations. A travel day uses the compressed routine: something is better than nothing. Track exceptions honestly, never fabricate activity to keep a streak, and resume the normal cadence promptly.

**Weekly coaching questions.** (1) Which conversations created new knowledge or an agreed action? (2) Where did a relationship become dependent on one person? (3) Which assumption changed, and what did we do differently? (4) Which promising item lacks evidence of a real need? (5) Where did research or polishing replace external action? (6) What did AI save after review and correction time? (7) Where does that time go next week? (8) What should leave the active list?

### First 30 days

| Days | Focus |
| --- | --- |
| 1–7 | Install the coach. With his manager or account owners, pick roughly 10–15 accounts (a starting hypothesis, not a quota). Split fast lane from slow lane. Audit commitments and approved capability sources. Run `/time-audit` before choosing any AI workflow |
| 8–14 | Run the daily blocks. Use one direct-outreach approach and one familiarity approach. Log outcomes accurately. Rehearse one hard opening twice. Measure the review burden of one AI workflow (for example debriefs) as well as its speed |
| 15–21 | Review which conversations revealed genuine needs. Adjust targets, seek introductions, fill missing buying-center roles, publish one insight from a real recurring question. Pause items with disproportionate effort and no evidence |
| 22–30 | Review with the manager: attempted, learned, progressed, disqualified, help needed. Revise cadence, qualification and messages. Keep the strongest skills; retire those that create work |

### Measurement definitions

| Measure | Operational definition | Interpretation |
| --- | --- | --- |
| Targeted attempt | A relevant, intentional approach to a verified person or role | Effort, not success |
| Meaningful conversation | A two-way exchange that adds material information or an agreed step | Better than counting replies |
| Meeting held | A completed meeting with a defined purpose | Separate from meetings booked |
| **Second meeting held** | A follow-on meeting with the same account on substance | Iannarino's practical filter for real pipeline |
| Qualified opportunity created | Meets the agreed qualification criteria | Requires evidence, not enthusiasm |
| Buyer-committed next step | The customer or partner agrees to a specific action (government-shaped where relevant) | Engagement, not a guaranteed win |
| **Gate progression** | Funding level, vehicle, solicitation status, or CDS approval path advances | Movement the government controls |
| Stakeholder coverage | Buying-center roles understood and appropriately engaged | Reveals single-threading |
| **Replacement rate** | New qualified items ÷ items closed or disqualified in the period | Law of Replacement check |
| Useful nurture | Relevant, proportionate contact with a reason for future relevance | Keep out of active pipeline |
| Net AI time saved | Prior task time minus AI prep, review and correction time | Estimate transparently |
| Engineering efficiency | Technical effort relative to decision value and qualified progress | Protects scarce capacity |

### Funnel arithmetic

```text
conversation_rate  = meaningful_conversations / targeted_attempts
meeting_hold_rate  = meetings_held / meetings_booked
second_meeting_rate = second_meetings / first_meetings_held
qualification_rate = qualified_opportunities / relevant_discovery_meetings
win_rate           = wins / closed_opportunities_in_comparable_cohort
```

Always show numerators and denominators. Calculate by channel, audience, and consistent cohort. Don't compare immature opportunities with closed cohorts. Define how no-decisions and disqualifications enter each denominator before interpreting a rate. With low volumes, review individual cases and rolling periods instead of weekly percentages.

### Diagnose the bottleneck before adding activity

| Symptom | Check |
| --- | --- |
| Low contact rate | Identity, reachability, channel, timing, route of access |
| Conversations without meetings | Relevance, the "because," listening, the request, and whether a meeting is even needed |
| Meetings without qualification | Targeting and the assumptions in the opening message |
| Qualified items without movement | Sponsor strength, decision process, technical fit, **funding level, vehicle, CR, solicitation timing, AO path** |
| Excessive technical effort | Tighter preliminary discovery; a decision-oriented, bounded engineering engagement |
| High LinkedIn engagement, little pipeline | Whether activity reaches the buying center and converts to real conversations |

Change one meaningful variable at a time, and record what you learn in the changelog.

---

## reference/sequences.md: outreach templates that pass the because-test

All templates are Owl adaptations built on the book frameworks named in each heading. Fill brackets only with verified facts, and never imply a recipient has a problem just because a similar organization does. The signature is "Chris Clark, Owl Cyber Defense," with no rank or title.

### Pre-contact checks

1. Who owns this account at Owl? Coordinate before contact.
2. Is this contact involved in an open solicitation? If so, contracting officer only.
3. Does any guardrail apply (Reserve overlap, gift, possible conflict)?
4. Is every fact in the message from a public or approved source, with a date?

### Two cadences

| Cadence | For | Shape |
| --- | --- | --- |
| **Fast** | Primes, integrators, partners, critical-infrastructure operators, and government contacts with a live trigger in the open window | About six touches over two to three weeks: verify target and route; one short relevant message with one request; a call through an appropriate channel; a useful LinkedIn contribution or genuine introduction; a follow-up with one new question or resource; finally ask whether to redirect, revisit at a stated time, or close the loop. Later Sales Gravy guidance runs 10–14 touches over 10–30 days for short cycles; Owl's audience warrants fewer |
| **Slow** | Program offices and mission owners without an active window | Monthly or quarterly value touches over one to two years (Later author), plus bursts around triggers such as budget releases, RFIs and conferences. After a silent sequence, pause 90 days to six months and re-enter with a new trigger |

Stop or adapt when the person replies, declines, asks for a delay, or points elsewhere. A contact policy or opt-out overrides cadence. Once a conversation starts, end the sequence: going dark after a reply is the failure, and so is continuing automated-style touches.

### Mission-owner email (Hook–Relate–Bridge–Ask, FP Ch 19)

> **Subject:** [Program or issue] — [specific data-flow question]
>
> Hi [Name],
>
> *Hook:* [Verified public source or real conversation, with date] raised [specific mission problem].
>
> *Relate:* I'd like to understand how your team moves [data] between [environments] today, and where that creates delay or integration work.
>
> *Bridge:* I ask because I work on cross-domain and one-way transfer at Owl Cyber Defense, and I'd rather learn your constraints than guess at them.
>
> *Ask:* Is this in your lane? If so, would 20 minutes [specific window] be useful?
>
> Chris Clark, Owl Cyber Defense

### Phone opener (five-step framework, FP Ch 15)

> (1) "[Name]?" (2) "Chris Clark with Owl Cyber Defense." (3) "I'm calling about [verified context: your RFI on X, your talk at Y]." (4) "I'm trying to find who owns [data flow], because [their stated problem], and I'd like to understand how you handle it today." (5) "Would 15 minutes on [day] work, or is there a better person?" Then stop talking.

When the right person engages, ask one substantive question before proposing a next step. Don't compress a technical presentation into the opening.

### Voicemail (five-step framework, FP Ch 15)

> "This is Chris Clark, Owl Cyber Defense, [number], [number]. I'm calling about [reason]. [Reason to call back: one specific question or something useful]. Again, Chris Clark, [number]."

Leave one only when it matters, and keep it short.

### LinkedIn connection note (200 characters or fewer)

> "Hi [Name], your [post/talk] on [topic] was useful. I work on cross-domain data movement at Owl and follow this space closely. Glad to connect."

No pitch on acceptance. Reply to the substance of whatever they say, and invite a business conversation only once relevance is established.

### Partner discussion

> "Your public work on [verified capability] looks adjacent to a data-movement problem we're exploring. I'd like to compare where your integration responsibilities end and where a cross-domain or one-way transfer component might fit. Could we review one concrete use case before discussing anything broader?"

### Conference follow-up

> "Good speaking at [event]. You mentioned [actual issue]. My takeaway was [brief interpretation]; please correct me if I missed it. The most useful next step seems to be a short discussion with [role] to clarify [specific unknown]. Would you be comfortable connecting us, or should I go through someone else?"

### Introduction request

> "Do you know [person] well enough to judge whether a conversation about [problem] would be useful to them? I'm exploring [specific question], prompted by [verified context]. If it fits, here's a short note you could forward. If the timing or relationship isn't right, no problem at all."

### RBO turnarounds (Anchor–Disrupt–Ask, FP Ch 16)

Use these only on reflex brush-offs. Make about two attempts, then exit gracefully.

| Brush-off | Anchor | Disrupt | Ask |
| --- | --- | --- | --- |
| "Just send me something." | "Happy to." | "So I send the right thing rather than a brochure, which data flow is causing the most friction right now?" | "If it's [X], could we take 15 minutes Thursday so I can point you to the right material?" |
| "We're all set." | "Good to hear." | "Where, if anywhere, does the current setup leave manual work or a flow you can't support yet?" | "If there's nothing, I'll leave you be. If there is, is 15 minutes worth it?" |
| "I'm busy." | "Understood, I'll be quick." | "One question: who owns [data flow] on your side?" | "Is it better to find 10 minutes next week, or should I talk to them directly?" |

### Structural "no"s are qualification data

**"We already have a solution."** → "Understood. Where, if anywhere, does the current approach leave your team with manual work or an unmet data flow? If it covers the requirement well, that's useful for me to know too." If no gap exists, close or nurture. Never invent a competitive weakness.

**"There's no budget."** (government version) → "Thanks, that helps. Is this tied to a specific program element or line? Is it on anyone's unfunded-priorities list, or something being built into a future POM? That tells me whether there's a useful step now or whether I should come back on the budget calendar." Accept that the answer may justify stopping. Discovery must not become free, open-ended engineering.

**"We can't talk, there's an open solicitation."** → "Understood. I'll send any questions through the contracting officer." Then stop. Don't push back on this one.

---

## reference/time-sensitive-facts.md: dated facts to refresh monthly

`/bd-monthly` walks this table. When a row is past its refresh date, check the source, update the value and the as-of date with Chris's approval, or mark it "stale, unverified."

| Fact | Value as of 2026-11-13 | Source | Refresh by |
| --- | --- | --- | --- |
| FY2027 defense appropriations | None enacted; CR (P.L. 119-103) at FY2026 levels through **2026-12-11**; new-start ban reportedly included | [CRS R49353](https://www.congress.gov/crs-product/R49353) | **2026-12-12**, and on any CR or appropriations action |
| FAR overhaul, Part 15 | Proposed 2026-09-18 (FAR Case 2026-003); not final; DoD class deviation reported | [Federal Register](https://www.govinfo.gov/content/pkg/FR-2026-09-18/html/2026-19162.htm) | Monthly |
| SEWP VI | Awards June 2026; ordering 2026-11-01 to 2036-10-31; go-live unconfirmed; protests; SEWP V to 2027-04-30 | [Nextgov](https://www.nextgov.com/modernization/2026/06/nasa-names-2100-winners-sewp-vi/414347/) | Monthly until go-live is confirmed |
| SBIR/STTR | Reauthorized through 2031-09-30 (signed 2026-04-13) | [SBA](https://www.sba.gov/article/2026/04/13/administrator-loeffler-applauds-sbir-sttr-reauthorization) | 2027-04 |
| CSO authority | FY2026 NDAA §1823 removed the "innovative" limit and the >$100M determination | [10 USC 3458](https://www.law.cornell.edu/uscode/text/10/3458) | 2027-01 (after the FY2027 NDAA) |
| DIU | Three portfolios (autonomous warfare, kill webs, 10x); stated 60–90 days to prototype OT, average ~120 | [DIU](https://diu.mil/work-with-us); [DefenseScoop](https://defensescoop.com/2026/07/06/diu-reshaping-tech-priorities-under-new-leadership-owen-west/) | Quarterly |
| PAE structure | Army 6; Navy 9 reported; Air Force 17 PAE-led organizations (Jul 2026) | [DefenseScoop](https://defensescoop.com/2026/08/06/air-force-portfolio-executives-acquisition-reform/) | Quarterly |
| CDS baseline, RTB, office naming | RTB 2018; DoDI 8540.01 Change 1 (2017); UCDSMO-to-NCDSMO rename not confirmed officially | [NIST](https://csrc.nist.gov/glossary/term/cross_domain_solution_baseline_list) | 2027-05 |
| LinkedIn feed ranking | LLM-augmented Generative Recommenders (2026-03-12) | [LinkedIn Newsroom](https://news.linkedin.com/2026/ImprovingTheFeed) | 2027-05 |
| LinkedIn connection notes | Non-Premium: 3 personalized notes a month, 200 characters | [LinkedIn Help](https://www.linkedin.com/help/linkedin/answer/a563153) | Quarterly |
| LinkedIn AI training | Default on since 2025-11-03; opt-out path in Settings | [TechRadar](https://www.techradar.com/pro/linkedin-set-to-expand-ai-training-on-user-profiles-heres-how-to-stop-it-using-your-personal-data) | 2027-05 |
| van der Blom figures | *Algorithm Insights 2026* | [Creator Science](https://creatorscience.com/podcast/richard-van-der-blom-2/) | When the 2027 report is out |
| Sales Navigator AI tiers | Account IQ/Lead IQ on Advanced and Advanced Plus; Sales Assistant beta | [LinkedIn Help](https://www.linkedin.com/help/sales-navigator/answer/a1655021) | Quarterly |
| Buyer attitudes to AI | Gartner: 69% validate AI insights with reps | [Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-05-20-gartner-survey-finds-sixty-nine-percent-of-b-two-b-buyers-turn-to-sales-reps-to-validate-ai-generated-insights) | 2027-06 |
| Claude Code settings keys | `disableAutoMode`, `disableBypassPermissionsMode`, skills frontmatter rules | [Permissions](https://code.claude.com/docs/en/permissions); [Skills](https://code.claude.com/docs/en/skills) | On each Claude Code update |

---

## Conclusion

The ChatGPT draft's deepest problem wasn't any single misattribution. It imported a closing-pressure model into a market where the seller doesn't control the close. Blount's system is built around the seller's activity clock. In federal cross-domain sales, the "close" is a chain of government-controlled events: a funded line, a usable vehicle, a solicitation, an award, a baseline listing, and an authorizing official's signature. That moves the coach's job upstream. It should maximize high-quality conversations inside the window FAR 15.201 opens and in the prime and partner channel, where activity scales freely, and it should treat structural "no"s as information. Blount's most transferable ideas are therefore his slowest ones: the Law of Familiarity, the Prospecting Pyramid, Golden Hours discipline, and the "because." Volume and the turnaround reflex transfer least. Iannarino's "more isn't better than better" counterweight, and the evidence that buyers now use reps to validate what AI told them, point the same way. Chris's edge is acquired domain knowledge that is verified, sourced and specific, and AI should feed it, not imitate it.

Two practical points follow. First, the evidence ceiling is low and cheap to raise. Framework names are solid, but most components rest on secondary summaries, and one session with the licensed text or the free Sales Gravy book-club guides would settle BTN, GEAR, the Robot Rules list, the seven steps, and the eight discovery mistakes. Second, Chris already has the research-brief, pursuit-decision and budget-mining instruments on the work side. This playbook doesn't replace them. It adds the missing layer: daily prospecting rhythm, outreach craft, rehearsal, debrief-to-CRM hygiene, and a monthly maintenance loop that keeps dated facts, such as the CR expiring 2026-12-11, from going stale silently.

---

## Sources

Researched 2026-11-13. This section also becomes `reference/sources.md`. Access notes: Wiley Online Library and O'Reilly returned HTTP 403, so chapter titles and abstracts come from their search-indexed pages. IEEE Xplore rendered empty. **The *Fanatical Prospecting* book-club PDF cited as [S08] in v1 returned HTTP 404.** No pirated copies were used.

**Books and publisher pages**
- [Wiley Online Library: *Fanatical Prospecting* book record](https://onlinelibrary.wiley.com/doi/book/10.1002/9781119176305) and chapter abstracts: [ch02](https://onlinelibrary.wiley.com/doi/abs/10.1002/9781119176305.ch02), [ch04](https://onlinelibrary.wiley.com/doi/abs/10.1002/9781119176305.ch04), [ch05](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch05), [ch09](https://onlinelibrary.wiley.com/doi/abs/10.1002/9781119176305.ch09), [ch10](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch10), [ch11](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch11), [ch12](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch12), [ch14](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch14), [ch15](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch15), [ch16](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch16), [ch18](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch18), [ch20](https://onlinelibrary.wiley.com/doi/10.1002/9781119176305.ch20), [ch23](https://onlinelibrary.wiley.com/doi/abs/10.1002/9781119176305.ch23)
- [O'Reilly: *Fanatical Prospecting* contents](https://www.oreilly.com/library/view/fanatical-prospecting-the/9781119144755/06_contents.html), with the Ch 8 Golden and Platinum Hours sections
- [Wiley-VCH: *The LinkedIn Edge*](https://www.wiley-vch.de/en/areas-interest/finance-economics-law/the-linkedin-edge-978-1-394-31671-7), with the full chapter list; [O'Reilly TOC](https://www.oreilly.com/library/view/the-linkedin-edge/9781394316717/) and [c17](https://www.oreilly.com/library/view/the-linkedin-edge/9781394316717/c17.xhtml), seen via search index only
- [Wiley-VCH: *The AI Edge*](https://www.wiley-vch.de/en/areas-interest/finance-economics-law/the-ai-edge-978-1-394-24447-8) and [Wiley](https://www.wiley.com/en-ca/shop/general-introductory-business-management/the-ai-edge-sales-strategies-for-unleashing-the-power-of-ai-to-save-time-sell-more-and-crush-the-competition-p-9781394244478), with the correct subtitle; [Wiley Skills Network course on Coursera](https://www.coursera.org/learn/wiley-the-ai-edge-unlocking-ai-for-sales-efficiency-and-growth); [IEEE Xplore "Practice and Prompts" record](https://ieeexplore.ieee.org/document/10950738/), not readable
- [O'Reilly: *Objections*](https://oreilly.com/library/view/objections/9781119477389); [O'Reilly: *Sales EQ*](https://www.oreilly.com/library/view/sales-eq/9781119312574/) and [Ch 5](https://www.oreilly.com/library/view/sales-eq/9781119312574/c05.xhtml); [O'Reilly: *Fanatical Military Recruiting* Ch 15](https://www.oreilly.com/library/view/fanatical-military-recruiting/9781119473640/c15.xhtml)
- Sales Gravy book-club resources: [Fanatical Prospecting landing page](https://salesgravy.com/resource/fanatical-prospecting-book-club-guide/) (its PDF is [dead, 404](https://salesgravy.com/wp-content/uploads/2024/05/fanatical-prospecting-book-club-guide.original.pdf)); [LinkedIn Edge guide](https://salesgravy.com/resource/linkedin-edge-book-club-guide/); [AI Edge guide](https://salesgravy.com/ai-edge-book-club-guide/); [LinkedIn profile checklist](https://salesgravy.com/resource/linkedin-profile-checklist/)

**Secondary summaries of *Fanatical Prospecting*** (cross-checks only, not the book)
- [J. Silva chapter-by-chapter summary (2019)](https://jsilva.blog/2019/02/27/fanatical-prospecting-summary/); [Tandem handbook notes](https://handbook.thinktandem.io/guides/sales-fanatical-prospecting-notes.html); [11x review, Aug 2026](https://www.11x.ai/guides/fanatical-prospecting-review) (vendor); [Alex Berman review, Aug 2026](https://alexberman.com/fanatical-prospecting-review) (promotional); [InsideSales interview with Blount](https://www.insidesales.com/secrets-of-phone-prospecting-jeb-blount/)

**Later author material**
- Blount at Sales Gravy: [prospecting consistency](https://salesgravy.com/how-to-maintain-prospecting-consistency-ask-jeb/); [outbound interview](https://salesgravy.com/jeb-blount-outbound-prospecting-real-estate-agents/); [Ledge technique](https://salesgravy.com/how-to-use-the-ledge-technique-for-sales-objection-handling-ask-jeb/); [four objection types](https://salesgravy.com/skipping-past-the-4-types-of-sales-objections-podcast/); [sequences](https://salesgravy.com/?p=16190); [giving up too soon](https://salesgravy.com/our-greatest-weakness-is-giving-up-too-soon/); [desperate for attention](https://salesgravy.com/desperate-for-attention-in-a-noisy-prospecting-world/); [AI will punish mediocrity](https://salesgravy.com/ai-will-not-kill-sales-but-it-will-punish-mediocrity-ask-jeb/); [can AI replace salespeople](https://salesgravy.com/can-ai-really-replace-salespeople-ask-jeb/); [how to start using AI](https://salesgravy.com/how-to-start-using-ai-in-sales-ask-jeb/); [7 mindsets](https://jebblount.com/7-mindsets-top-earning-salespeople/)
- Blount interview on *The LinkedIn Edge*: [Construction Disruption ep. 170, Oct 2025](https://construction-disruption.com/episode/ai-and-the-linkedin-edge-with-jeb-blount); [fast vs. slow prospecting podcast](https://www.audible.com/podcast/Stop-Random-Acts-of-LinkedIn-Fast-vs-Slow-Prospecting-with-Brynne-Tillman/B0GVVR1P56)
- Tillman: [Social Sales Link ep. 398](https://socialsaleslink.com/podcast/episode-398-establishing-a-productive-daily-routine-on-linkedin-2025/); [ep. 498](https://socialsaleslink.com/podcast/episode-498-stop-the-connect-and-pitch-start-earning-conversations-2026/)
- Iannarino at The Sales Blog: [excessive outreach focus, Sep 2023](https://thesalesblog.com/blog/excessive-focus-on-cold-outreach-and-pipeline); [AI rules, Jun 2024](https://www.thesalesblog.com/blog/rules-for-using-artificial-intelligence-in-b2b-sales); [cold-outreach apocalypse, Aug 2024](https://www.thesalesblog.com/blog/how-to-navigate-the-ai-driven-cold-outreach-apocalypse-8-proven-strategies-for-b2b-sales-success); [editing and research prompts, Sep 2024](https://www.thesalesblog.com/blog/mastering-ai-driven-editing-and-research-prompts-a-guide-for-content-creators-and-sales-professionals); [replacing salespeople with AI, May 2025](https://www.thesalesblog.com/blog/why-replacing-human-salespeople-with-ai-is-a-mistake-for-b2b-companies)
- [Baylor Keller Center on *Sales EQ*](https://kellercenter.hankamer.baylor.edu/news/story/2018/insider-sales-eq); [getAbstract summary of *The AI Edge*](https://www.getabstract.com/en/summary/50361); [sobrief summary](https://sobrief.com/books/the-ai-edge)

**LinkedIn platform**
- [LinkedIn Newsroom, Mar 12 2026](https://news.linkedin.com/2026/ImprovingTheFeed); [LinkedIn Help: connection notes](https://www.linkedin.com/help/linkedin/answer/a563153); [LinkedIn Help: invitation limit](https://www.linkedin.com/help/linkedin/answer/a550555); [Sales Navigator Account IQ](https://www.linkedin.com/help/sales-navigator/answer/a1655021); [LinkedIn AI for Sales](https://business.linkedin.com/sell/sales-navigator/ai-for-sales)
- [arXiv 2501.16450 (360Brew)](https://arxiv.org/abs/2501.16450); [media-all.in analysis](https://media-all.in/en/blog/linkedin-360brew-ai-algorithm-explained/); [Creator Science ep. 307 (van der Blom)](https://creatorscience.com/podcast/richard-van-der-blom-2/); [Matt Navarra on links](https://www.threads.com/@mattnavarra/post/DOWa_61Cown/linkedin-says-posts-with-links-are-not-intentionally-penalized-for-reachlinkedin); [Forbes on the link penalty](https://www.forbes.com/sites/jodiecook/2026/07/30/the-linkedin-link-penalty-cutting-your-reach-by-60/); [ZoomInfo on Sales Navigator](https://pipeline.zoominfo.com/sales/linkedin-sales-navigator-features); [TechRadar on AI training](https://www.techradar.com/pro/linkedin-set-to-expand-ai-training-on-user-profiles-heres-how-to-stop-it-using-your-personal-data); [LinkedInsider on InMail](https://linkedinsider.blog/linkedin-inmail-response-rate)

**AI-in-sales evidence**
- [Gartner, May 20 2026](https://www.gartner.com/en/newsroom/press-releases/2026-05-20-gartner-survey-finds-sixty-nine-percent-of-b-two-b-buyers-turn-to-sales-reps-to-validate-ai-generated-insights); [Dell'Acqua et al., 2023](https://mitsloan.mit.edu/sites/default/files/2023-10/SSRN-id4573321.pdf); [Brynjolfsson, Li & Raymond, NBER](https://www.nber.org/papers/w31161)

**Federal BD and cross-domain**
- [FAR 15.201](https://www.acquisition.gov/far/15.201); [FAR subpart 9.5](https://www.acquisition.gov/far/subpart-9.5); [41 USC 2102](https://www.law.cornell.edu/uscode/text/41/2102); [Federal Register, Part 15 proposed rule](https://www.govinfo.gov/content/pkg/FR-2026-09-18/html/2026-19162.htm); [Open FAR Cases (DPAP)](https://www.acq.osd.mil/dpap/dars/opencases/farcasenum/far.pdf)
- [Shipley BD lifecycle](https://www.shipleywins.com/tools-and-guidebooks/business-development-lifecycle-chart); [Shipley, bid less win more](https://www.shipleywins.com/blogs/bid-less-win-more)
- [CRS IF10429 (PPBE)](https://www.everycrsreport.com/files/2024-12-06_IF10429_e43a53a1488617df1634ff184030ae37cbab7dde.pdf); [CRS R49353 (FY2027 CR)](https://www.congress.gov/crs-product/R49353); [CRS R45870 (CR effects)](https://www.everycrsreport.com/reports/R45870.html); [ClearanceJobs on the FY2027 CR](https://news.clearancejobs.com/2026/10/01/the-pentagon-starts-fiscal-2027-on-a-stopgap-heres-how-it-affects-defense-jobs/); [Defense News on the drone request](https://www.defensenews.com/pentagon/2026/07/02/hegseth-creates-powerful-new-drone-office-pulling-authority-from-the-military-services/)
- [EO 14265](https://www.whitehouse.gov/presidential-actions/2025/04/modernizing-defense-acquisitions-and-spurring-innovation-in-the-defense-industrial-base/); [Inside Government Contracts on the acquisition memo](https://www.insidegovernmentcontracts.com/2025/12/from-das-to-was-secretary-hegseths-acquisition-overhaul-and-what-it-means-for-industry/); [Greenberg Traurig on the FY2026 NDAA](https://www.gtlaw.com/en/insights/2026/2/fy2026ndaa/fy-2026-ndaa-the-substantial-impact-of-the-fiscal-year-2026-national-defense-authorization-act-on-federal-procurement-law); PAEs: [Army](https://defensescoop.com/2025/11/14/army-acquisition-reform-2025/), [Navy](https://www.navair.navy.mil/news/Navy-Establishes-Portfolio-Acquisition-Executive-Aviation/Mon-05112026-0943), [Breaking Defense](https://breakingdefense.com/2026/08/top-cover-and-clear-metrics-how-to-make-the-new-pae-structure-work/), [Air Force](https://defensescoop.com/2026/08/06/air-force-portfolio-executives-acquisition-reform/)
- [10 USC 3458 (CSO)](https://www.law.cornell.edu/uscode/text/10/3458); [DIU: work with us](https://diu.mil/work-with-us); [DefenseScoop on DIU priorities](https://defensescoop.com/2026/07/06/diu-reshaping-tech-priorities-under-new-leadership-owen-west/); [SBA on SBIR reauthorization](https://www.sba.gov/article/2026/04/13/administrator-loeffler-applauds-sbir-sttr-reauthorization); [Crowell & Moring on SBIR](https://www.crowell.com/en/insights/client-alerts/sbirsttr-programs-reauthorized-after-six-month-lapse); [Nextgov on SEWP VI](https://www.nextgov.com/modernization/2026/06/nasa-names-2100-winners-sewp-vi/414347/); [Federal News Network on SEWP](https://federalnewsnetwork.com/contractsawards/2026/06/more-sewp-for-contractors-as-nasa-expands-total-awards/); [SAM.gov CDS notice example](https://sam.gov/opp/55dce222b6b14bf7acb67e22629ff4fb/view)
- [DoDI 8540.01](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/854001p.pdf) (via search excerpts); [NSA NCDSMO](https://www.nsa.gov/Cybersecurity/Partnership/National-Cross-Domain-Strategy-Management-Office/) (via search excerpt); [NIST baseline-list glossary](https://csrc.nist.gov/glossary/term/cross_domain_solution_baseline_list); [Green Hills RTB explainer](https://www.ghs.com/products/safety_critical/integrity_178_standards_raise-the-bar.html); [ExecutiveBiz on Everfox MESA](https://www.executivebiz.com/articles/everfox-mesa-ncdsmo-baseline-cross-domain-sharing); [Owl V2CDS baseline press release](https://owlcyberdefense.com/news/owl-cyber-defense-announces-ncdsmo-baseline-listing-for-new-version-of-v2cds/); [Army CIO PPM-016](https://www.armyng.com/2024/04/ppm-cio-016-army-cross-domain-solution.html); [DISN Connection Process Guide](https://dl.dod.cyber.mil/wp-content/uploads/connect/CPG/ConnProcGuide.html); [NDIA 2022 CDS briefing](https://ndia.dtic.mil/wp-content/uploads/2022/systems/Thurs_24541_Boyd.pdf)

**Guardrails and OPSEC**
- [NCSC/FBI/DCSA advisory on online targeting, Apr 2025](https://archive.dni.gov/files/NCSC/documents/products/2025-04-08-NCSC-FBI-DCSA-OnlineTargetingUSGEmployees.pdf); [DCSA SEAD 3 desktop aid](https://www.dcsa.mil/Portals/91/Documents/CTP/tools/SEAD3_REPORTING_DESKTOP_AID_FOR_CLEARED_INDUSTRY.pdf); [DoDI 5400.17](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/540017p.PDF); [Joint Ethics Regulation, May 2024](https://dodsoco.ogc.osd.mil/Portals/102/Documents/Issuances/JER%20and%20Directives/JER%20May%2015%202024.pdf); [5 CFR 2635.204 (gifts)](https://www.law.cornell.edu/cfr/text/5/2635.204)

**Claude Code packaging**
- Claude Code docs: [Memory](https://code.claude.com/docs/en/memory); [Skills](https://code.claude.com/docs/en/skills); [Best practices](https://code.claude.com/docs/en/best-practices); [Features overview](https://code.claude.com/docs/en/features-overview); [Permissions](https://code.claude.com/docs/en/permissions); [Security](https://code.claude.com/docs/en/security); [Data usage](https://code.claude.com/docs/en/data-usage)
- Anthropic platform docs: [Skill authoring best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices); [Prompting best practices](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices); [Claude for Government](https://claude.com/solutions/government)
- [HubSpot MCP server](https://developers.hubspot.com/mcp); [HubSpot Claude connector](https://www.hubspot.com/claude); [Anthropic sales plugin summary (secondary)](https://instagit.com/anthropics/knowledge-work-plugins/sales-plugin-capabilities)
