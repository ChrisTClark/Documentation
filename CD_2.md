# Cross-Domain Security — A Technical Primer

*General industry reference compiled from public sources. Covers the problem cross-domain security exists to solve, the mechanisms used, how requirements are segmented, and how such systems are evaluated and fielded in US government environments. No vendor, product, program, or organization-specific content.*

---

## 1. The problem

Organizations routinely operate networks at different levels of trust or classification that **must not be directly connected**. A classified network and an unclassified one. An operational-technology network running physical plant and the corporate IT network. A national network and a coalition partner's. A production enclave and an analytics environment.

Keeping them separate is the easy part. The difficulty is that **missions require information to move between them anyway** — a sensor on a lower network feeding a decision-maker on a higher one, telemetry from a plant floor reaching a cloud analytics service, intelligence being shared with a partner nation under releasability rules.

That produces a narrow, awkward requirement: *permit exactly the intended information to cross, in exactly the intended direction, and nothing else — with enough assurance that the claim survives adversarial scrutiny.*

**The default alternative is manual transfer.** Someone copies data to removable media and physically carries it across. This is slow, error-prone, unauditable, and introduces its own risks — but it is free, requires no approval, and is the incumbent solution in most environments. **Any cross-domain proposal competes primarily against "keep doing it by hand," not against another product.**

---

## 2. The two mechanisms

Two distinct controls do the work. They solve different problems and are frequently combined.

### 2.1 Direction enforcement — the data diode

A **data diode** enforces one-way flow using a **physical or electrical property** rather than software configuration. A common implementation uses an optical link with a transmitter on one side and a receiver on the other, and no return path present in the hardware at all.

The security argument is unusually strong and unusually simple: **there is no return channel to compromise, because none was built.** A misconfiguration cannot create one. A software vulnerability cannot create one. The property is structural.

The trade-off is equally structural. With no return path there is no acknowledgement, so ordinary bidirectional protocols do not function across a diode. Transfer software must handle reliability without feedback — typically through forward error correction, redundant transmission, or protocol proxies that terminate the session on each side.

A useful distinction in the market: a **basic diode** moves bytes one way and is indifferent to their meaning. A **protocol-aware diode** understands the specific protocol crossing it and can validate structure at line rate. The second is meaningfully harder to build and correspondingly more defensible.

### 2.2 Content control — guards and filters

Direction alone is insufficient when the concern is *what* is inside the payload. Data moving from a higher classification to a lower one may contain material that must not cross regardless of direction. Data moving upward may carry malicious content.

A **guard** (or **cross-domain solution**, in the narrower sense) inspects, validates, transforms, and conditionally forwards content according to policy. Techniques include:

- **Whitelisting against a closed grammar** — the strongest available filtering, viable only where the data format is fixed and non-extensible
- **Schema validation** — checking structured data conforms to a declared schema
- **Content Disarm and Reconstruction (CDR)** — rebuilding a file to a known-good specification rather than attempting to detect what is bad. The only sound posture for complex formats, because detection-based approaches fail against novel content
- **Dirty-word and pattern search** — weak on its own, useful as an additional layer
- **Label and marking validation** — checking classification or releasability markings before permitting a crossing

### 2.3 How they compose

A common architecture uses **hardware to enforce direction and software to enforce content policy**. The hardware guarantee is simple enough to be argued convincingly to an evaluator; the content policy is where the mission-specific complexity lives. Neither substitutes for the other.

---

## 3. Segmenting the requirement — two questions

Almost any cross-domain requirement can be located with two questions. Together they form a useful grid.

### Question 1 — What crosses? *(dataflow tier)*

| Tier | What it is | Why it matters |
|---|---|---|
| **Fixed / structured** | Closed, non-extensible grammars — tactical message formats, structured telemetry, fixed binary records | **Fully whitelistable.** Every valid message can be enumerated, so filtering can be positive rather than negative. Fast enough for hardware implementation |
| **Streaming** | Voice, video, VTC, continuous telemetry | Latency-sensitive and bandwidth-heavy. Filtering must keep up in real time or the boundary becomes the bottleneck |
| **Complex** | Files, documents, office formats, archives | **Hardest by a wide margin.** Open, extensible, deeply nested grammars with embedded content and free text. Cannot be exhaustively whitelisted, which is why CDR exists |

⚠️ **"Fixed format" and "structured" are not synonyms**, and conflating them causes real errors. *Fixed format* means a closed, non-extensible grammar — whitelistable. *Structured* means it has *a* schema, which may be open, extensible, nested, or contain free-text fields. **All fixed-format data is structured; most structured data is not fixed-format.** An extensible markup format has a schema and is still enormously harder to filter than a fixed binary message.

**A technique worth knowing:** rigid binary formats can be formally described so they can be losslessly lifted into a structured representation while still being treated as a closed grammar. This is what allows semantic-level filtering of binary data rather than treating it as opaque bytes.

### Question 2 — What is being built? *(deployment model)*

| Model | Shape | Buyer |
|---|---|---|
| **Point-to-point** | One program solves one boundary. Owns its own accreditation. Often embedded or ruggedized | A program manager |
| **Enterprise** | A shared, multi-tenant crossing service used by many consumers | A service provider organization |

These are **different sales, different economics, and different buyers.** A useful diagnostic for whether an enterprise requirement is real: *"what happens to that crossing when the shared service is unreachable?"* A program that has not considered degraded or disconnected operation usually has a point-to-point requirement it has not recognized yet.

Another quantifying probe: *"how many separate cross-domain authorizations does your organization carry today?"* Consolidation pain becomes concrete when it has a number attached.

### The composed grid

|  | Point-to-point | Enterprise |
|---|---|---|
| **Fixed** | One program's message feed crossing one boundary; often embedded | Shared structured-message crossing serving many consumers; releasability at a hub |
| **Streaming** | One video downlink or one conferencing suite at the edge | Multi-domain media hub serving many users — the consolidation play |
| **Complex** | One program's file boundary; frequently still manual | Enterprise file-transfer service — **the hardest cell**: largest filtering and accreditation burden, highest leakage risk |

---

## 4. Where boundaries structurally appear

Certain architectural patterns *require* a domain crossing rather than merely benefiting from one. Recognizing them is more useful than searching for stated requirements, because the crossing often exists before anyone has named it.

- **Classification boundaries** — data moving between networks at different classification levels
- **Coalition and releasability** — national systems sharing with partners under release rules; the policy question ("who may see this") becomes a technical enforcement question
- **IT / OT convergence** — operational technology feeding analytics, monitoring, or cloud services, where any two-way link is an attack path into physical infrastructure
- **Cloud and enclave proliferation** — each new enclave or impact level creates new boundaries by construction
- **Zero Trust segmentation** — micro-segmentation multiplies the number of internal trust boundaries
- **AI and autonomy** — models require training and inference data from sensitive sources; the feed must not become a two-way door
- **Tactical edge** — disconnected, intermittent, low-bandwidth operation where reachback to a central service cannot be assumed

⚠️ **A structural observation worth carrying:** architectural trends that *multiply* trust boundaries increase cross-domain demand mechanically, whether or not anyone writes a requirement for it. Meanwhile, consolidation initiatives push the opposite direction. Both dynamics are real and they coexist — a market view that accounts for only one will be wrong.

---

## 5. Evaluation and authorization (US government context)

This is where cross-domain differs most from ordinary security products, and it is a substantial barrier to entry.

### The layers

- **Common Criteria / NIAP** — internationally recognized product evaluation. Assurance expressed as an Evaluation Assurance Level (EAL). Establishes that a product's security claims were independently examined
- **Product baseline listing** — the national cross-domain authority maintains a list of assessed cross-domain products. Being listed is effectively a precondition for deployment in many environments
- **Raise the Bar (RTB)** — a body of hardened design requirements that cross-domain solutions must meet. It substantially raised the engineering floor and, incidentally, the cost of entry
- **Lab-Based Security Assessment (LBSA)** — a deep product assessment conducted once, in an approved laboratory, typically over many months
- **Site-Based Security Assessment (SBSA)** — assessment of a specific deployment in its actual environment. Every fielding requires one
- **Authorization to operate** — the decision that a specific system may run. For cross-domain there is a dedicated authorization track with its own boards and review bodies, distinct from ordinary system authorization

### Why this shapes the market

**A meaningful change to an evaluated product can require re-assessment measured in many months.** This has several consequences worth understanding:

1. **It is a genuine moat.** The cost and duration of assessment deter casual entrants and make incumbency durable
2. **It is also a constraint on the incumbent.** Product velocity is structurally slow, which creates room for adjacent products that solve real problems without being full cross-domain solutions
3. **Certification is a repeatable organizational process, not a one-time event.** An organization that can carry successive product generations through evaluation demonstrates something an individual certificate does not
4. **Schedules are predictable.** Because each boundary type maps to a known authorization track, timelines can be estimated — which matters to whoever owns the schedule

### A frequent confusion

**Commercial Solutions for Classified (CSfC) is not cross-domain.** CSfC is a program permitting layered commercial encryption to protect classified data in transit. It addresses confidentiality across an untrusted transport. Cross-domain addresses *controlled transfer between security domains*. They are complementary and regularly conflated, including by informed people.

---

## 6. Relationship to Zero Trust

Zero Trust and cross-domain security are often positioned as alternatives. They are better understood as operating at different layers.

Zero Trust assumes each entity can assert an identity, run an enforcement agent, and emit telemetry that feeds policy decisions. **Large populations of real devices cannot do any of these things** — legacy industrial controllers, embedded sensors, purpose-built platform equipment. They have no identity to present, cannot host software, and generate no logs.

For those devices, enforcement must move **off the device and onto the boundary**. Hardware-enforced one-way transfer is a limiting case of "never trust, always verify": a diode does not need to authenticate return traffic because no return path exists to authenticate.

Read this way, **boundary enforcement is the tier of Zero Trust that operates below the floor software-based Zero Trust can reach** — not an exception to it, and not a legacy approach it replaces.

---

## 7. Form factors and integration

Cross-domain products appear across a wide physical range, and form factor frequently determines whether a product is viable for a given program.

- **Rack-mounted / enterprise** — data centers and fixed facilities. Power and cooling are available; size is not a constraint
- **Ruggedized** — vehicles, aircraft, shipboard, forward-deployed. Environmental and shock standards apply, and thermal design becomes a first-order problem
- **Embedded / card-level** — the function delivered as a card inside a host system rather than as a standalone box

### Open architecture

Defense platform integration increasingly proceeds through **modular open systems approaches**, which specify standard mechanical, electrical, and software interfaces so components from different suppliers can interoperate.

Relevant families include open backplane standards for card-based systems, service-domain-specific implementations layering on those standards for ground vehicles and airborne platforms, and software-level architecture standards defining component interfaces.

**Why this matters commercially:** where a platform has committed to an open architecture, a compliant card can be designed into the platform's standard configuration. That converts a per-program integration sale into something closer to a catalog position — a materially different business.

---

## 8. Adjacent concepts

| Concept | What it is | Relationship |
|---|---|---|
| **Content Disarm and Reconstruction** | Rebuilds files to a known-good specification rather than detecting badness | The sound approach for the complex tier; often a filtering component within a guard |
| **Data-centric security** | Attribute-based access control applied to the data object itself, via labels | Complements boundary enforcement; does not replace it. Requires labels to be trustworthy |
| **Multi-level security** | A single system handling data at multiple classifications with mandatory access control | Older architectural approach; largely displaced by separate systems plus controlled transfer |
| **Air gap** | Complete physical separation with no connection | Both the baseline being improved on and the primary competitor, since manual transfer is the fallback |
| **Removable-media sanitization** | Scanning and cleaning media before it enters a protected environment | Addresses the case where someone physically hands over a drive — a real and under-served gap |

---

## 9. Sizing the market

Cross-domain rarely appears as its own budget line. It is a component inside host programs — a platform's integration line, a network modernization program, an intelligence system, or sustainment funding.

A bottom-up estimate therefore takes the form:

> **(number of crossing points) × (revenue per crossing point)**

Both terms are hard. Crossing points must be inferred from architecture rather than counted from a list. And in defense specifically, **any figure derived from public budget documents is a floor, not an estimate** — significant demand sits in classified annexes and intelligence budgets published only in aggregate. Presenting a public-source number as market size is an error a knowledgeable customer will notice immediately.

---

## 10. Public sources worth knowing

- **National cross-domain authority publications** — design requirements, assessment process descriptions, and the product baseline concept
- **Department-level policy directives** governing cross-domain support and the authorization process
- **Security control catalogs and overlays** — including the overlay specific to cross-domain systems
- **Common Criteria portal** — evaluated product listings and published security targets
- **Published budget justification documents** — narrative program descriptions where cross-domain functionality is described even when not named
- **Federal contract award data** — what has actually been bought and sustained
- **Independent test and evaluation annual reports** — where interoperability and boundary problems surface candidly
- **Open architecture standards bodies** — specifications and adopter lists

---

*Compiled from public sources as general reference. Contains no vendor, product, program, organization, or individual-specific information.*
