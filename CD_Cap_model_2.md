# Capability Questions and Hypotheses

**Project:** Capabilities, Technology & Architecture  
**Purpose:** Maintain the technical questions, capability hypotheses, and unresolved assumptions that should **not yet be treated as established company capability**.

> This document is the uncertainty layer of the capability knowledge base.

---

# Priority Open Technical Questions

## 1. FPGA / ARM / Hardware Architecture

- What FPGA capabilities does the company possess today?
- What functions are implemented in FPGA versus ARM processors or general-purpose software?
- Which hardware, firmware, or software elements constitute reusable company IP?
- What performance characteristics have actually been demonstrated?
- What are the principal throughput and latency constraints?
- Which protocols or data types are currently supported?
- How portable is the underlying architecture across products or form factors?
- What engineering work would be required to reuse these capabilities in adjacent applications?
- Which aspects are commercially configurable versus bespoke engineering?

## 2. Voice / Video

- What specifically creates the company's voice/video advantage?
- Is the differentiation primarily latency, throughput, protocol handling, security assurance, synchronization, architecture, accreditation, integration expertise, or something else?
- Which voice/video protocols and formats are currently supported?
- What performance has been demonstrated?
- Which capabilities are reusable outside current products?
- What parts of the solution are hardware-enforced?
- Where do competitors or architectural workarounds fail?
- Which mission problems value this capability enough to influence a buying decision?

## 3. Filtering / Content Validation

- What syntactic filtering capabilities are implemented today?
- What semantic filtering capabilities are implemented today?
- Which data types and protocols can currently be filtered?
- How are policies expressed and maintained?
- What portions of filtering capability are reusable IP?
- What performance impact does filtering impose?
- Which capabilities require a full Raise-the-Bar CDS architecture?
- Which could be reused in a lower-assurance or specialized boundary-security product?
- How does the company's filtering approach differ materially from realistic alternatives?

## 4. Data Diodes / Transfer / Isolation

- What one-way transfer capabilities are available today?
- What does the company mean technically by bidirectional hardware-based transfer or diode architectures?
- Which functions can be enforced in hardware?
- What protocol handling is required on each side of a hardware-enforced boundary?
- What form factors exist or are feasible?
- What is the maximum demonstrated throughput?
- Which use cases require sophisticated filtering versus simple deterministic transfer?
- What accreditation implications arise when capabilities are repackaged or integrated differently?

## 5. Reusable IP and Product Boundaries

- Which capabilities belong to reusable technical IP versus a specific product implementation?
- Which capabilities are current, configurable, integration work, committed roadmap, adjacent application of existing IP, or net-new engineering?
- What capabilities can be exposed as components, modules, embedded functions, or OEM offerings?
- Where would reuse create meaningful technical debt or accreditation burden?
- What capabilities are constrained primarily by engineering capacity rather than technical feasibility?

---

# Capability Hypotheses

## H-CAP-001 — Content-Filtering Diode

### Hypothesis
Existing hardware-processing and filtering expertise may enable a content-filtering diode or similar specialized boundary-security device that does not require the full complexity of a traditional Raise-the-Bar CDS.

### Why Plausible
- Management discussion identified this as an example of a possible adjacent application.
- The company appears to possess sophisticated filtering expertise.
- Hardware-based / FPGA approaches are of strategic interest.

### What Must Be Validated
- Existing reusable hardware/firmware IP.
- Supported protocols and data types.
- Throughput and latency.
- Required filtering complexity.
- Engineering effort.
- Accreditation implications.
- Customer problem and willingness to pay.
- Competitive alternatives.

### Status
**Open**

### Confidence
**Low**

### Next Best Validation
Technical discussion with FPGA / filtering engineering authority.

---

## H-CAP-002 — FPGA/ARM-Based High-Throughput Boundary Device

### Hypothesis
An architecture combining FPGA-based deterministic processing with ARM-based control or protocol functions may enable differentiated high-throughput boundary-security applications.

### Why Plausible
- Market discussion identified growing interest in hardware-based approaches using FPGAs and ARM cores.
- Management is interested in exploring capabilities beyond the traditional product suite.

### What Must Be Validated
- Whether the company already possesses relevant FPGA/ARM IP.
- Division of functions between FPGA, ARM, and software.
- Demonstrated performance.
- Security benefits versus software-heavy architectures.
- Integration and engineering burden.
- Applicable customer/mission problems.

### Status
**Open**

### Confidence
**Low**

### Next Best Validation
Map current hardware architecture with an appropriate engineer.

---

## H-CAP-003 — Voice/Video as a Broader Strategic Adjacency

### Hypothesis
The company's voice/video expertise may create strategic opportunities beyond traditional CDS products in architectures where real-time, latency-sensitive, or specialized protocol transfer is difficult to solve with generic guard or data-transfer solutions.

### Why Plausible
- Management/BD discussion identifies voice/video as a primary competitive strength.
- Real-time media can create technical problems that differ from generic structured-data transfer.

### What Must Be Validated
- Exact technical source of differentiation.
- Relevant protocols.
- Demonstrated performance.
- Portability of the capability.
- Mission architectures where the difference is meaningful.
- Competitive substitutes.
- Acquisition and accreditation implications.

### Status
**Open**

### Confidence
**Medium-Low**

### Next Best Validation
Technical deep dive on voice/video architecture and customer use cases.

---

## H-CAP-004 — High-Assurance IP Reused Outside Full RTB CDS

### Hypothesis
Selected high-assurance mechanisms or IP may create value in customer problems that do not require a complete Raise-the-Bar CDS implementation.

### Why Plausible
- Management believes many customers do not require the full level of engineering currently offered.
- Management also sees potential in CDS-adjacent applications of existing IP.

### What Must Be Validated
- Which high-assurance mechanisms are modular/reusable.
- Which capabilities can be separated from the current product architecture.
- Security/accreditation implications.
- Engineering effort.
- Customer problems where partial reuse provides meaningful value.
- Whether commercial alternatives already solve the problem adequately.

### Status
**Open**

### Confidence
**Medium-Low**

### Next Best Validation
Architecture decomposition discussion with senior technical lead.

---

# Hypothesis Template

## H-CAP-XXX — [Short Name]

### Hypothesis
[What might be possible]

### Why Plausible
- [Evidence or reasoning]

### What Must Be Validated
- [Technical question]
- [Performance question]
- [Engineering question]
- [Customer / mission question if relevant]

### Status
**Open / Strengthening / Weakening / Validated / Rejected**

### Confidence
**High / Medium / Low**

### Next Best Validation
[Cheapest credible next action that would materially reduce uncertainty]

### Supporting Sources
- [Source, date]

### Last Updated
YYYY-MM-DD

---

# Question Triage

When preparing for an engineering discussion, prioritize questions that will:

1. determine whether a hypothesized capability is actually feasible;
2. distinguish reusable IP from net-new development;
3. clarify a material performance or integration constraint;
4. determine whether a technical advantage is meaningful to a customer;
5. prevent BD from making an unsupported commitment.

---

# Update Rule

After new technical evidence is reviewed:

- Move validated knowledge into `Capability_Model.md`.
- Keep unresolved questions here.
- Strengthen, weaken, validate, or reject hypotheses explicitly.
- Do not delete rejected hypotheses when the lesson is strategically useful; mark them **Rejected** and capture why.
- Add new questions only when resolving them would materially improve technical or BD decision-making.
