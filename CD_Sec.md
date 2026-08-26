# Capabilities Project — Simplified Knowledge Management Guide

## Add This to the Project Instructions

### Knowledge Management Protocol

Treat this project as a **living model of company capabilities**, not simply a document repository.

When new technical information is provided—whether from a PowerPoint, PDF, Word document, email, meeting notes, engineering discussion, architecture diagram, or other source:

1. Preserve the original source as evidence when appropriate.
2. Extract only information relevant to understanding company technologies, capabilities, architectures, constraints, differentiators, and potential adjacencies.
3. Classify important information as:

   * **CONFIRMED CAPABILITY** — sufficiently supported by authoritative evidence.
   * **CONSTRAINT** — known technical, engineering, integration, performance, accreditation, or resource limitation.
   * **HYPOTHESIS** — plausible capability or application that has not been validated.
   * **KNOWLEDGE GAP** — important unanswered technical question.
4. Distinguish what the source explicitly supports from analytical inference.
5. Do not convert technical plausibility into an asserted company capability.
6. Do not infer an engineering commitment, roadmap item, or product capability without evidence.
7. Identify whether new information changes the current understanding of an existing capability.
8. Identify contradictions with prior knowledge rather than silently reconciling them.
9. Maintain provenance: identify the source, date, and—when relevant—the authority of the source.
10. Optimize the knowledge base around the question:

> **What can the company actually do, what enables it technically, where are its boundaries, and what adjacent applications might those capabilities enable?**

---

# Keep Only Two Canonical Knowledge Artifacts

## 1. Capability Model

Maintain one living document called:

**Capability_Model.md**

This is the authoritative summary of what we currently understand about the company's capabilities.

For each major capability capture:

### Capability

Name of the underlying capability.

### What It Does

Plain-language description.

### Technical Mechanism

What enables it technically.

### Existing Evidence / Implementations

Where it has been implemented, demonstrated, tested, productized, accredited, or fielded.

### Differentiated Value

Where and why it may provide meaningful advantage over alternatives.

### Known Constraints

Technical, performance, integration, accreditation, resource, or other limitations.

### Potential Adjacencies

Possible additional applications. Clearly label these as hypotheses unless validated.

### Confidence

* High
* Medium
* Low

### Key Sources

Documents, discussions, emails, programs, or other evidence supporting the assessment.

### Last Updated

Date of most recent meaningful validation.

---

## 2. Capability Questions & Hypotheses

Maintain one second living document called:

**Capability_Questions_and_Hypotheses.md**

Use it for everything that is not yet established knowledge.

Keep two sections:

### Open Technical Questions

Examples:

* What portions of processing occur in FPGA versus ARM?
* What throughput has actually been demonstrated?
* Which protocols are currently supported?
* What portions of the architecture constitute reusable IP?
* What limits reuse in embedded applications?

### Capability Hypotheses

Example:

**Hypothesis:** Existing FPGA and filtering IP may support a high-throughput content-filtering diode outside a traditional RTB CDS.

**Why plausible:** Existing deterministic processing and filtering capabilities.

**What must be validated:** Protocol support, throughput, reusable IP, engineering effort, accreditation implications.

**Status:** Open / Strengthening / Weakening / Validated / Rejected

---

# Daily Quick Reference

Whenever new technical knowledge arrives:

### STEP 1 — Put in the source

Provide Claude the relevant:

* PPT
* Word document
* PDF
* email or email excerpt
* meeting notes
* technical notes
* architecture information
* pasted text

Keep the original source when it has lasting evidentiary value.

### STEP 2 — Ingest it

Run the **Capability Knowledge Ingest** skill.

The skill should answer:

> **What does this change about what we think the company can do?**

Not merely:

> “Summarize this document.”

### STEP 3 — Review

Quickly check Claude's extraction.

Especially verify:

* Did it mistake marketing language for engineering fact?
* Did it turn an idea into a capability?
* Did it miss an important constraint?
* Did it overstate what an engineer actually said?

### STEP 4 — Update the Model

Have Claude propose exact changes to:

**Capability_Model.md**

and/or:

**Capability_Questions_and_Hypotheses.md**

Make those changes only after review.

That's it.

---

# Skill 1 — Capability Knowledge Ingest

## Purpose

Use this whenever new technical information enters the project.

It should work regardless of whether the source is a presentation, PDF, Word document, email, notes from an engineering conversation, technical specification, architecture diagram, or pasted text.

## Suggested Skill Name

**Capability Knowledge Ingest**

## Suggested Skill Description

Analyze new technical evidence and determine how it changes the company's capability model, constraints, hypotheses, and technical knowledge gaps.

## Skill Instructions

When I provide new technical material, do not merely summarize it.

Analyze it as evidence for the company's capability knowledge base.

### Step 1 — Identify the Source

Capture:

* source title or description;
* date if known;
* source type;
* author / speaker / organization if relevant;
* approximate authority of the source.

Treat an engineering authority, test result, or technical design artifact differently from marketing material or informal speculation.

### Step 2 — Extract Relevant Knowledge

Identify:

#### CONFIRMED CAPABILITIES

What does this source credibly establish that the company can do?

#### CONSTRAINTS

What limitations, boundaries, dependencies, performance limitations, integration issues, accreditation considerations, or engineering requirements are identified?

#### HYPOTHESES

What potentially valuable applications or capabilities are suggested but not demonstrated?

#### KNOWLEDGE GAPS

What remains unclear and should be validated?

### Step 3 — Check Against the Existing Model

Determine whether the source:

* confirms existing knowledge;
* adds new capability information;
* modifies an existing capability;
* introduces a new constraint;
* strengthens or weakens a hypothesis;
* contradicts existing knowledge;
* creates a new technical question.

Do not silently resolve contradictions.

### Step 4 — Assess Evidence Strength

When useful, classify confidence as:

* **High** — demonstrated, fielded, tested, or directly confirmed by appropriate technical authority.
* **Medium** — documented by credible internal sources but not independently validated.
* **Low** — inference, informal statement, marketing claim, or technically plausible idea.

### Step 5 — Recommend Knowledge-Base Changes

Produce:

**A. What I learned**

**B. What changed in the capability model**

**C. What remains uncertain**

**D. Exact recommended edits to Capability_Model.md**

**E. Exact recommended edits to Capability_Questions_and_Hypotheses.md**

### Critical Rules

* Never convert “technically plausible” into “company capability.”
* Never infer engineering commitment.
* Never infer product or roadmap capability merely from underlying IP.
* Preserve important source provenance.
* Flag contradictions.
* Prefer explicit uncertainty to invented certainty.

---

# Skill 2 — Capability Model Curator

## Purpose

Use this periodically—not after every document—to clean up and reconcile the accumulated capability knowledge.

A weekly or biweekly cadence is sufficient during periods of active technical learning.

## Suggested Skill Name

**Capability Model Curator**

## Suggested Skill Description

Reconcile recent technical learning into the canonical capability model, identify contradictions and stale assumptions, and prioritize unanswered technical questions.

## Skill Instructions

Review recent technical evidence, conversations, and knowledge-base changes.

Do not simply summarize activity.

Determine **what changed in our understanding of company capability**.

Produce:

### 1. Newly Confirmed Knowledge

Capabilities or constraints that became materially better supported.

### 2. Changed Understanding

Existing beliefs that should be modified.

### 3. Contradictions

Evidence that does not agree and requires resolution.

### 4. Hypothesis Movement

Identify hypotheses that:

* strengthened;
* weakened;
* were validated;
* were rejected;
* remain unresolved.

### 5. Highest-Value Technical Questions

Identify the 3–5 unanswered questions whose resolution would most improve strategic BD decision-making.

### 6. Capability Adjacencies

Identify any new potential applications suggested by recent learning.

Label these clearly as hypotheses.

### 7. Canonical Updates

Recommend exact additions, deletions, or revisions to:

* **Capability_Model.md**
* **Capability_Questions_and_Hypotheses.md**

Do not change established knowledge merely to make conflicting sources appear consistent.

---

# The Whole System in One Picture

**NEW INFORMATION**

PPT / PDF / Word / Email / Engineer Discussion / Notes

↓

**Capability Knowledge Ingest Skill**

↓

Sorts into:

**Confirmed Capability | Constraint | Hypothesis | Knowledge Gap**

↓

**You Review**

↓

Updates:

**Capability Model**
*What we currently believe*

and

**Questions & Hypotheses**
*What we still need to learn*

↓

Periodically run:

**Capability Model Curator**

↓

Cleaner model + better engineering questions + new adjacency hypotheses

---

# Operating Rule

The raw documents are **evidence**.

The Capability Model is **current knowledge**.

The Questions & Hypotheses file is **uncertainty**.

The Skills are **the procedures for moving information between them**.

Do not manually build a complicated knowledge-management system beyond this unless actual use demonstrates a need for one.
