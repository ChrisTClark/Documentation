# Cross-Domain & Defense Acquisition — Glossary

*General industry acronym reference compiled from public sources. Companion to the Cross-Domain Security Technical Primer. Contains no vendor, product, program, organization, or individual-specific entries.*

---

## Cross-domain core

- **CDS — Cross Domain Solution.** A controlled interface enabling data transfer between security domains at different classification or trust levels.
- **Data diode.** A device enforcing one-way data flow through a physical or electrical property rather than software configuration. No return path exists in the hardware.
- **Guard.** A system that inspects, validates, transforms, and conditionally forwards content across a boundary according to policy.
- **Filter.** The component enforcing content policy — whitelisting, schema validation, pattern matching, or reconstruction.
- **Protocol-aware diode.** A diode that understands the specific protocol crossing it and validates structure, as opposed to passing opaque bytes.
- **CDR — Content Disarm and Reconstruction.** Rebuilding a file to a known-good specification rather than attempting to detect malicious content. The sound approach for complex formats.
- **MLS — Multi-Level Security.** A single system handling multiple classification levels under mandatory access control. Largely superseded by separate systems plus controlled transfer.
- **MSL — Multiple Single Levels.** Separate systems each operating at one level, with controlled transfer between them. *(Note: in platform documents this abbreviation usually means Mean Sea Level instead.)*
- **Sanitization.** Removing or masking content so data may cross to a lower level.
- **Downgrade.** Moving data from a higher classification to a lower one, requiring review or transformation. *(Also used non-technically to mean a capability reduction.)*
- **Air gap.** Complete physical separation between networks, with no connection at all.
- **Sneakernet.** Manual transfer via removable media carried by a person. The default incumbent solution and the real competitor to most cross-domain proposals.

## Dataflow and format

- **Fixed format.** A closed, non-extensible grammar. Every valid message can be enumerated, making positive whitelisting possible.
- **Structured data.** Data with *a* schema — which may be open, extensible, nested, or contain free text. **Not** a synonym for fixed format.
- **Complex format.** Files and documents with open, extensible, deeply nested grammars. The hardest filtering problem.
- **Streaming.** Continuous latency-sensitive data — voice, video, conferencing, telemetry.
- **Schema validation.** Confirming structured data conforms to its declared schema.
- **Whitelisting.** Permitting only explicitly allowed content. Viable only against a closed grammar.
- **Format description language.** A formal means of describing rigid binary formats so they can be losslessly represented in a structured form while remaining a closed grammar.

## Evaluation, authorization and governance

- **NIAP — National Information Assurance Partnership.** US body overseeing Common Criteria evaluation.
- **Common Criteria.** International standard for security product evaluation.
- **EAL — Evaluation Assurance Level.** Numeric depth-of-evaluation rating under Common Criteria.
- **Protection Profile.** A standardized set of security requirements for a product category, against which products are evaluated.
- **RTB — Raise the Bar.** Hardened design requirements for cross-domain solutions, which substantially raised the engineering floor for the category.
- **Product baseline list.** The set of assessed cross-domain products maintained by the national cross-domain authority; effectively a precondition for deployment in many environments.
- **LBSA — Lab-Based Security Assessment.** Deep product assessment in an approved laboratory. Conducted once per product; typically many months.
- **SBSA — Site-Based Security Assessment.** Assessment of a specific deployment in its actual environment. Required per fielding.
- **ATO — Authority to Operate.** The decision permitting a system to run on a network.
- **CDSA — Cross Domain Solution Authorization.** The cross-domain-specific authorization decision, distinct from an ordinary ATO.
- **SABI / TSABI — Secret-and-Below / Top Secret-and-Below Interoperability.** The two authorization tracks, split by classification level. Not legacy processes; both are current.
- **RMF — Risk Management Framework.** The overarching US federal process for assessing and authorizing information systems.
- **Security control overlay.** A tailored control set for a specific system type; a cross-domain-specific overlay exists.
- **CSfC — Commercial Solutions for Classified.** A program permitting layered commercial encryption to protect classified data in transit. ⚠️ **Not cross-domain** — addresses confidentiality across untrusted transport, not controlled transfer between domains.
- **APL — Approved Products List.** A catalog of products approved for connection to a given network infrastructure.

## Networks, domains and sharing

- **Enclave.** A bounded network environment under one security policy.
- **Security domain.** A set of systems operating under a common security policy and classification level.
- **Coalition information sharing.** Providing information to partner nations under release rules.
- **Releasability.** Whether and to whom information may be disclosed; the policy question that boundary enforcement implements technically.
- **Mission partner environment.** A shared information environment enabling operations with partners.
- **Impact level.** A tiering scheme for cloud environments by data sensitivity.
- **DDIL — Denied, Degraded, Intermittent, Limited.** Operating conditions at the tactical edge where reachback cannot be assumed. The key test of whether an enterprise service model is viable for a given requirement.
- **Zero Trust.** A security model removing implicit trust based on network location, requiring continuous verification. Has a structural floor at devices that cannot hold identity, run agents, or emit telemetry.
- **Micro-segmentation.** Dividing a network into small isolated zones; multiplies internal trust boundaries by design.

## Platform, form factor and architecture

- **MOSA — Modular Open Systems Approach.** Designing systems around standard interfaces so components from different suppliers interoperate.
- **Open backplane standards.** Specifications for card-based systems defining mechanical and electrical interfaces, widely used in rugged and embedded computing.
- **Service-specific open architecture families.** Implementations layering on open backplane standards for particular platform types — ground vehicle and airborne variants exist.
- **Software architecture standards.** Specifications defining software component interfaces for portability across platforms.
- **Design-in.** Being selected into a platform's standard configuration rather than sold per-program — converts integration revenue toward catalog revenue.
- **Ruggedization.** Engineering for environmental extremes, shock, and vibration per applicable military standards.
- **Form factor.** Physical configuration — rack-mounted, ruggedized chassis, or embedded card.
- **Line rate.** Processing at the full speed of the network link, without becoming a bottleneck.

## Acquisition and business development

- **TAM / SAM / SOM.** Total Addressable / Serviceable Addressable / Serviceable Obtainable Market — successively narrower market-sizing measures.
- **TRL — Technology Readiness Level.** A 1–9 scale describing technology maturity from basic principles to proven operational use.
- **PE — Program Element.** The primary identifier for research and development budget lines.
- **BLI / P-1 Line Item.** The primary identifier for procurement budget lines. ⚠️ A different key system from program elements; conflating them loses data.
- **RDT&E — Research, Development, Test and Evaluation.** The appropriation category funding development.
- **O&M — Operations and Maintenance.** The appropriation category funding sustainment.
- **Justification books.** Published budget documents explaining requested funding, containing narrative program descriptions.
- **Program of record.** A formally established, funded program.
- **IDIQ — Indefinite Delivery, Indefinite Quantity.** A contract vehicle with a ceiling under which task orders are issued. ⚠️ **The ceiling is not revenue** — obligations may be a small fraction of it.
- **Sole source.** An award made without competition, generally requiring justification.
- **CRAD — Customer-funded research and development.** The customer pays to modify an existing product for a specific requirement; the result may then be commercialized more broadly.
- **Capture.** The pre-solicitation discipline of shaping a requirement and positioning to win it.
- **Bid / no-bid gate.** The formal decision point on whether to pursue an opportunity.
- **Pwin — Probability of win.** A calibrated estimate of winning a given pursuit.
- **Black hat review.** A structured exercise analyzing an opportunity from competitors' perspectives.
- **Incumbent.** The supplier currently holding the work. Displacing an incumbent is a fundamentally different approach from greenfield pursuit.

## Message formats and standards *(public)*

- **Tactical data link message formats.** Standardized fixed-format military message standards for exchanging track and command information. Closed grammars, therefore whitelistable.
- **Cursor-on-Target.** A small fixed XML schema used as a common language for position and event data in situational-awareness tooling. Fixed format, fully whitelistable.
- **Situational awareness toolkits.** Open-source-derived mapping and coordination applications used across military and civil-response settings; federation between instances at different classification levels creates a cross-domain requirement.

---

*Compiled from public sources as general reference. Contains no vendor, product, program, organization, or individual-specific information.*
