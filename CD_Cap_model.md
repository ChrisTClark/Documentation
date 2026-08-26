# Capability Model

**Project:** Capabilities, Technology & Architecture  
**Purpose:** Maintain the current best understanding of what the company can actually do, what enables those capabilities technically, where the boundaries are, and where differentiated value may exist.

> **Important:** This is a living working model, not an engineering specification or product roadmap. Only elevate a capability to "Confirmed" when supported by sufficiently authoritative evidence.

---

## Evidence & Classification Rules

For important technical claims, use one of these labels:

- **CONFIRMED CAPABILITY** — supported by authoritative technical evidence, demonstrated implementation, test evidence, or direct confirmation from an appropriate technical authority.
- **PROVISIONAL CAPABILITY** — supported by credible internal discussion or documentation, but not yet technically validated.
- **CONSTRAINT** — known technical, integration, performance, accreditation, engineering, or resource limitation.
- **HYPOTHESIS** — plausible capability or adjacent application that has not been validated.
- **KNOWLEDGE GAP** — an unanswered question that matters to technical or business-development decisions.

### Confidence
- **High** — demonstrated, fielded, tested, or directly confirmed by an appropriate technical authority.
- **Medium** — supported by credible internal documentation or leadership/technical discussion, but not independently validated.
- **Low** — inference, informal statement, marketing claim, or plausible idea.

### Capability Maturity
Use when useful:

**Concept → Prototype → Demonstrated → Productized → Accredited → Fielded**

---

# Current Working Capability Model

The entries below are a **starting point based on management/BD discussion**, not authoritative technical validation. Replace, refine, or remove them as engineering evidence is gathered.

---

## Capability: High-Assurance Cross-Domain Transfer and Filtering

### Status
**PROVISIONAL CAPABILITY**

### What It Does
Provides high-assurance mechanisms for moving data across security or trust boundaries, including sophisticated content-validation approaches.

### Technical Mechanism
**To be validated.** Current working understanding includes:
- syntactic filtering;
- semantic filtering;
- controlled transfer across security boundaries;
- high-assurance CDS engineering.

### Existing Evidence / Implementations
- Management/BD discussion indicates the company has engineered sophisticated syntactic and semantic filtering capabilities.
- Management/BD discussion also suggests that only a subset of customers require the full level of assurance provided.

### Differentiated Value
Potentially strongest where:
- security assurance is a primary buying criterion;
- customers require sophisticated content validation rather than simple data movement;
- accreditation/security requirements materially constrain alternatives.

### Known Constraints
- **CONSTRAINT:** The market for the highest-assurance implementation may be narrower than the engineering sophistication of the current solution set.
- **CONSTRAINT:** Many customers may accept simpler or less expensive alternatives when their primary requirement is simply moving data securely from A to B.
- **KNOWLEDGE GAP:** Which specific assurance mechanisms are genuinely differentiated versus competitors?
- **KNOWLEDGE GAP:** Which capabilities are reusable outside traditional Raise-the-Bar CDS implementations?

### Potential Adjacencies
- **HYPOTHESIS:** Reuse filtering or hardware-enforcement IP in lower-complexity boundary-security applications.
- **HYPOTHESIS:** Apply selected high-assurance mechanisms without requiring a full traditional CDS implementation.

### Confidence
**Medium** — based on management/BD discussion; requires technical validation.

### Key Sources
- Management/BD discussion, Aug 2026.
- Add authoritative technical sources as they are ingested.

### Last Updated
2026-08-26

---

## Capability: Voice and Video Cross-Domain Transfer

### Status
**PROVISIONAL CAPABILITY**

### What It Does
Supports cross-boundary transfer of real-time or latency-sensitive voice and video data.

### Technical Mechanism
**To be validated.**

Questions include:
- Which protocols are supported?
- What functions are implemented in hardware versus software?
- What creates the performance advantage: latency, assurance, protocol handling, architecture, or integration expertise?

### Existing Evidence / Implementations
- Management/BD discussion identifies voice/video as a primary area of company competitive strength.

### Differentiated Value
Potentially strongest where:
- real-time transfer matters;
- latency or protocol handling is difficult;
- existing alternatives are operationally inadequate;
- high assurance must be maintained without materially degrading mission performance.

### Known Constraints
- **KNOWLEDGE GAP:** Demonstrated throughput and latency.
- **KNOWLEDGE GAP:** Supported voice/video protocols and formats.
- **KNOWLEDGE GAP:** What is product-specific versus reusable technical IP?
- **KNOWLEDGE GAP:** Accreditation and integration boundaries.

### Potential Adjacencies
- **HYPOTHESIS:** Embedded or platform-specific secure voice/video boundary functions.
- **HYPOTHESIS:** Tactical or mission-partner architectures where low latency and specialized protocol handling matter.
- **HYPOTHESIS:** Nontraditional CDS applications where real-time media is the hard problem.

### Confidence
**Medium** — based on management/BD discussion; requires technical validation.

### Key Sources
- Management/BD discussion, Aug 2026.
- Add product, architecture, test, and engineering evidence as available.

### Last Updated
2026-08-26

---

## Capability: Hardware-Based / FPGA-Oriented Security Processing

### Status
**HYPOTHESIS / UNDER INVESTIGATION**

### What It Might Enable
Potential use of hardware-based processing, including FPGA-oriented architectures, for deterministic transfer, filtering, isolation, or specialized boundary-security functions.

### Technical Mechanism
Not yet established in this model.

Potential areas to understand:
- FPGA processing;
- ARM-based processing;
- hardware-enforced policy;
- deterministic processing;
- separation of control-plane and data-plane functions;
- reusable hardware or firmware IP.

### Existing Evidence / Implementations
- Management discussion highlighted interest in using FPGA-based approaches in new ways.
- A content-filtering diode was discussed as an example of a possible adjacent application.
- This does **not** yet establish a specific engineering capability or product.

### Differentiated Value
Potentially attractive if hardware-based approaches can provide:
- high throughput;
- deterministic behavior;
- reduced attack surface;
- compact/embedded form factors;
- specialized boundary enforcement;
- lower-complexity alternatives to a full traditional CDS.

### Known Constraints
- **KNOWLEDGE GAP:** What FPGA/ARM capabilities exist today?
- **KNOWLEDGE GAP:** What IP is reusable?
- **KNOWLEDGE GAP:** Which functions are implemented in hardware versus software?
- **KNOWLEDGE GAP:** Demonstrated performance limits.
- **KNOWLEDGE GAP:** Engineering effort required for adjacent applications.

### Potential Adjacencies
- **HYPOTHESIS:** Content-filtering diode.
- **HYPOTHESIS:** High-throughput hardware-enforced transfer.
- **HYPOTHESIS:** Embedded/platform-specific isolation or transfer function.
- **HYPOTHESIS:** Boundary-security applications outside a traditional Raise-the-Bar CDS.

### Confidence
**Low** — conceptually supported by management discussion; technical capability requires validation.

### Key Sources
- Management/BD discussion, Aug 2026.

### Last Updated
2026-08-26

---

# Capability Entry Template

## Capability: [Name]

### Status
**CONFIRMED CAPABILITY / PROVISIONAL CAPABILITY / HYPOTHESIS**

### What It Does
[Plain-language explanation]

### Technical Mechanism
[What enables it technically]

### Existing Evidence / Implementations
- [Product / program / prototype / test / fielded example]
- [Source]

### Differentiated Value
[Where and why this capability matters relative to realistic alternatives]

### Known Constraints
- **CONSTRAINT:** [...]
- **KNOWLEDGE GAP:** [...]

### Potential Adjacencies
- **HYPOTHESIS:** [...]

### Confidence
**High / Medium / Low**

### Capability Maturity
**Concept / Prototype / Demonstrated / Productized / Accredited / Fielded**

### Key Sources
- [Source, date, owner/authority]

### Last Updated
YYYY-MM-DD

---

# Update Rule

When new technical evidence is added to the project:

1. Determine whether it **confirms, changes, constrains, or contradicts** this model.
2. Do not convert a plausible idea into a company capability without evidence.
3. Preserve significant contradictions until resolved.
4. Update the capability entry only after review.
5. Move unresolved items into `Capability_Questions_and_Hypotheses.md`.
