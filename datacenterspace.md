# Orbital Compute — Data Centers in Space

*OSINT / learning reference · Sep 8, 2026. Fourth in the foundational set, after [[Cybersecurity & AI — The 2026 Landscape]], [[AI Infrastructure — The Physical Value Chain]] and [[The Energy System — The Invisible Machine]]. This one asks whether AI data centers can move to orbit — and lands on an answer with a **direct, specific consequence for cross-domain solutions.***

*Source: `2_Working Tools/BD Signal Digests/space data center visuals.pdf` — 62 pages, image-only, created 28 Aug 2026, evidence dated **August 2026**. Same house style as the Cybersecurity and Energy decks; no named author, no copyright notice. **Reviewed end to end** — the deck develops each argument across two or three consecutive slides, and every section and claim below is drawn from slides read directly. ⚠️ Figures are as the deck states them, **not independently verified**; it attributes to IEA, Google research, and company filings.*

---

## ⭐ The one-line answer

**"Data center in space" is two completely different businesses wearing one name**, and the deck's central move is to separate them:

| | **Compute FOR space** | **Compute FOR Earth** |
|---|---|---|
| Where the data originates | **In orbit** | On Earth — uploaded, processed, returned |
| Purpose | **Process before downlink** | Replace ground compute |
| Workload | Smaller, specialized | Potentially data-center scale |
| Status | ✅ **Already useful today** | ❓ **Not proven commercially** |

> *"Detecting a wildfire in orbit does not prove that hyperscale AI belongs in space."*

**The industry has reached real engineering demonstrations. It has not reached recurring commercial service.**

**⭐ And the half that is real today — processing data in orbit and downlinking only the result — is, for a defense or intelligence customer, a cross-domain problem wearing a bandwidth costume.** That is the finding that matters for Owl, and the deck states every element of it without ever naming it.

---

## Why anyone is asking

The premise chains off the previous two notes. **Data centers have become power-system projects** — global data-center electricity ~485 TWh (2025) heading to ~950 TWh by 2030 (IEA), AI-focused capacity up ~50% in 2025, and one campus now drawing **100 MW – 1 GW+**. *"At 100 megawatts, the data center and the power system become one project."*

Four bottlenecks stand between more chips and more usable compute: **dependable 24/7 power · grid access (a multi-year interconnection queue) · heat removal · time** — *"three chip generations can arrive before one grid project is finished."*

> *"AI demand can grow in months. The infrastructure around it can take years."*

So the orbital pitch begins as a **location** problem, not an energy shortage: power exists, but not where the computers are. *"Space is not the easy option. Earth has become difficult enough to make it worth studying."*

---

## The physics, honestly handled

The deck's strength is refusing the easy version of every space claim.

### Sunlight — better, not free
~**1,361 W/m²** reaches orbit, and a dawn–dusk orbit collects for far more hours with no clouds. Google's estimate: **up to 8× the energy** — *"energy collected over time, not 8× the instantaneous panel output."* But **1,361 W/m² is solar energy, not electrical output**, and an H100 at up to 700 W needs continuous power alongside CPU, HBM, networking, power electronics and cooling. *"Orbit improves solar utilization. It does not eliminate the power system."*

### ⭐ Cooling — the counterintuitive one
**Space is cold, but vacuum is a terrible coolant.** Heat has three paths: conduction, convection, radiation. **In vacuum, the first two are unavailable** — only radiation works. *"Space is not a freezer. Thermally, it behaves more like a vacuum bottle."* On Earth the environment carries heat away; in orbit the spacecraft must radiate it as infrared, which means large radiator panels and mass.

Starcloud-1 (one H100 in orbit) used **phase-change material as a thermal battery** — absorb heat, then cool down. **Absorbing heat ≠ rejecting heat continuously.** A real data center needs 24/7 rejection with no cool-down pause, *"not yet demonstrated economically at megawatt scale."*

### Radiation — survival is only the first requirement
Two different phenomena share the word: **cumulative dose** (years of gradual degradation) and **single-event effects** (one particle flips a bit). The failure modes: bit flip · reset · permanent damage · and ⚠️ **silent error — "7 × 9 = 62", an incorrect result without a crash.**

Protection costs the same resources the system is trying to save: shielding (mass) · error-correcting memory · **redundant computation** · checkpointing · spare hardware.

> *"A cloud customer needs more than a chip that survives: it needs correct results, uptime and a replacement plan."* Ground beam tests are encouraging but *"are not a service-level agreement."*

### Repair — *"On Earth, repair takes a technician. In orbit, it may take a rocket."*
Routine replacement in orbit does not yet exist at data-center scale. And the timelines are mismatched: **spacecraft design life ≈ 10 years vs. AI accelerator economic life ≈ 3–4 years.** *"A chip can become economically obsolete long before the spacecraft fails."* The sensible architecture — keep the solar arrays, radiators, structure and comms; swap the compute module — is **not yet demonstrated.**

### Networking — *"1,000 satellites can be 1,000 computers, or one poorly connected supercomputer"*
The dividing line is **synchronization**. Independent workloads (image processing, independent inference, Monte Carlo) divide easily. **One shared training job** requires continuous exchange of gradients and activations; *"fast processors + slow links = low utilization."* Google's Project Suncatcher targets **~10 Tbps per inter-satellite link**; its published lab demonstration was **800 Gbps each way** — a real gap, and *"one fast lab link ≠ a complete multi-satellite network."*

> *"The question is not whether space can compute. It is which jobs fit the architecture."*

---

## Where the programs actually stand — August 2026

The deck's **eight-rung evidence ladder** (a better-calibrated TRL for commercial claims):

`1 Announcement → 2 Funding/regulatory filing → 3 Ground test → 4 Hardware in orbit → 5 Real workload in orbit → 6 Networked multi-node prototype → 7 Recurring paid service → 8 Competitive operation at scale`

| Program | Rung | Note |
|---|---|---|
| **HPE / ISS Spaceborne Computers** (2017, 2021) | 5 | Real workloads on commercial hardware — but **ISS-supported, not free-flying** |
| **Starcloud-1** | 5 | One H100, free-flying, **limited operation** |
| **China — three-body computing constellation** | **6** | **12-satellite networked orbital edge computing on space-generated data.** The only program at rung 6 |
| **Google / Project Suncatcher** | 3 | Ground laser + radiation tests; two-satellite mission targeted early 2027 |
| **SpaceX / Starmind** | 2 | FCC application + AI1 design; **AI1 has not flown** |
| **Rungs 7 and 8** | — | **Empty. No program.** |

⚠️ **"The same rung can mean different things":** ISS-supported ≠ free-flying · space-generated data ≠ Earth-serving cloud · engineering milestone ≠ commercial business.

**SpaceX's ambition vs. evidence** is the sharpest example: an FCC filing for up to **1,000,000 satellites** and a stated **1 GW/year by late 2027 scaling to 100 GW/year by 2030** — against an AI1 (≈70 m wingspan, 150 kW peak / ~120 kW average) that **has not flown**, continuous cooling of a ~120 kW payload never demonstrated, and 1 GW/year implying roughly **6,700 AI1 satellites annually**. *"SpaceX may be best positioned to attempt the system. That does not mean the system has been proven."*

**And the scale problem is brutal:** an illustrative 1 GW orbital system at ~40 kg/kW is **~40,000 metric tons ≈ 95× the mass of the ISS**, or **~400 fully loaded 100-tonne flights** — before operational margins, replacements, failures and in-orbit assembly. *"Cheap, rapidly reusable heavy-lift launch is part of the data-center architecture."*

⚠️ **On the $/kg numbers:** ~$7,000/kg (current rideshare price, transport only) · $250–1,000/kg (one analysis's all-in build+launch competitive envelope) · below ~$200/kg (Google's orbital-power benchmark vs. terrestrial electricity, mid-2030s). **These are three different questions and are not interchangeable prices.** Always ask *"per kilogram of what?"*

---

# ⭐ What this means for Owl — hardware-enforced CDS and diodes

## 6a. 🔴 The headline: onboard AI converts an unfilterable firehose into a filterable trickle

**This is the most directly actionable technical insight in any of the four decks.**

The deck's opening market slide — *"The satellite can see more than it can send home"* — presents onboard processing as a **bandwidth** fix:

> **Traditional:** capture thousands of raw images → wait for a downlink window → transmit everything → search on Earth. *The warning waits for the data.*
> **Onboard AI:** capture → **process in orbit** → transmit only *"fire detected + location + relevant images."* *The answer arrives before the raw data.*
> **"Find the needle in orbit instead of sending the entire haystack."**

**For a defense or intelligence customer, that same pipeline is a cross-domain downgrade.** The sensor collects at one classification; the derived product — a detection, a track, a coordinate, a confidence score — is frequently releasable lower, or to a coalition partner. **Process high, release low** is exactly what a guard with a filter does.

**And here is the part that matters technically.** Per [[Dataflow Types — Fixed, Streaming & Complex]], raw imagery is the **complex** tier — the hardest possible case for a filter, where the only sound posture is CDR or human review. A structured detection message — *type, lat/long, timestamp, confidence, optional chip* — is the **fixed** tier: a closed, non-extensible grammar, **fully whitelistable and hardware-fast.**

> ⭐ **Onboard AI moves the cross-domain problem from the tier that is nearly unsolvable to the tier that is solved.** The bandwidth argument and the cross-domain argument are the same argument, and the space industry is building the enabling half of it for its own reasons.

**That is a genuinely new framing** and it belongs in front of a space/ISR customer. It is also a *reason to want* onboard AI that has nothing to do with bandwidth — which is a strong position, because the customer is already sold on the premise.

## 6b. Defense is explicitly named as a first market — twice

Not inference. The deck names it:

- **"Where space may win first"**: data generated in space · **specialized science and defense work** · independent AI inference · workloads where deployment speed has unusually high value.
- **"Who benefits first"** from orbital edge computing: Earth observation · scientific spacecraft · communications satellites · **defense + autonomy — "local detection, decisions without waiting for Earth."**

> *"The first orbital computing business will process data that is already in space."*

**"Decisions without waiting for Earth" is an autonomy claim, and autonomy at the edge is precisely where a hardware-enforced boundary earns its place** — because there is no operator in the loop to catch a bad release. → [[Zero Trust & CDS — The Boundary Argument]]

## 6c. ⭐ The radiation-integrity problem converges on RAIN

The deck's silent-error finding — *"7 × 9 = 62, an incorrect result without a crash"* — is an **integrity** problem, and it has a specific consequence for any guard sitting downstream of an orbital processor: **a well-formed but wrong message passes a syntactic filter.** Correct format, wrong content.

Its list of protections is: shielding · error-correcting memory · **redundant computation** · checkpointing · spare hardware.

**That is Raise the Bar's RAIN — Redundant, Always-invoked, Independent, Non-bypassable — arrived at independently from radiation physics rather than from adversary modelling.** → [[CDS Governance — CNSS, National Manager & the Authority Chain]]

**Why this is useful:** it is a second, non-security argument for the same architecture. In front of a spacecraft engineer, *"redundant and independent because a particle can flip a bit"* lands where *"redundant and independent because NCDSMO requires it"* does not — and they produce the same design. **Two independent derivations of one architecture is the strongest kind of technical argument.**

## 6d. The nearer opportunity is the ground segment, not the spacecraft

⚠️ **Be honest about sequencing.** A space-qualified CDS is a long, expensive engineering program, and this deck's own evidence ladder says the orbital market is at rung 5–6 with no recurring commercial service. **The nearer money is on the ground.**

More onboard processing means **more small, structured, high-value products crossing more boundaries more often** — from commercial constellations into classified analysis, from national systems to coalition partners, from mission ops into tactical networks. That volume grows whether or not a single orbital data center ever flies, and it lands in **ground stations, mission-operations centres and downlink processing** — environments that exist today and already have accreditation regimes.

**The orbital piece is the seed. The ground segment is the pipeline.** → [[Seams & the Two Spines — Where CDS Is Structurally Required]]

## 6e. China at rung 6 is a threat-narrative hook

**China's 12-satellite networked orbital edge computing constellation is the only program the deck places at rung 6** — networked multi-node, focused on **space-generated data**, explicitly *not* Earth-serving hyperscale. That is the **militarily relevant** version of this technology, and an adversary is furthest along in it.

For a defense audience that is a legitimate, sourced talking point — used carefully, and without overstating what a 12-satellite demonstration means. ⚠️ Verify independently before putting it in anything customer-facing.

## 6f. ⚠️ Apply the deck's own discipline to this opportunity

The deck ends with five gates before believing any orbital-computing story — **contract · materiality · moat · financing · valuation** — and a list of **what does not count as proof**: concept rendering · regulatory filing · technology partnership · funding round · large addressable-market claim.

> *"Capabilities create possibility. Contracts, margins and cash flow create investment returns."*
> **The missing link it names: "technology relevance ≠ customer order."**

**Turn that on Owl.** A space CDS is exactly the adjacency where *"our technology is obviously relevant"* gets mistaken for *"there is a customer."* Today this has: no named customer, no contract, no program of record identified, and no verified requirement.

**→ It is an Opportunity Garden seed, not a pipeline item.** Recording it that way is the discipline the deck is teaching. → [[BD Opportunity Garden]]

## 6g. Two tools worth stealing

- **The eight-rung evidence ladder** is better calibrated than TRL for judging *commercial* claims, because it separates engineering milestones from recurring revenue. Pairs with [[TRL — Technology Readiness Levels]].
- **The bottleneck test** — *"who controls what every operator must buy?"*: **essential input? few alternatives? slow capacity expansion? attractive margins?** A four-question VRIO screen. *"The winner could be the operator — or the supplier every operator needs."* **Owl is always a supplier in these stacks, never an operator** — so this is the right screen to run on itself. → [[Owl — Core Capability Evidence]]

## ⚠️ Limits

1. **The deck has no security content whatsoever** — no cross-domain, no classification, no CDS, no NERC/NCDSMO analogue. Section 6 is entirely additive.
2. **The orbital-hyperscale thesis is unproven and the deck says so repeatedly.** Do not build anything on rungs 7–8.
3. **Space qualification is a different engineering bar** from rugged-tactical. ⚠️ Whether Owl has any credible path to a space-qualified or rad-tolerant form factor is **unknown and should not be assumed** → [[Rugged Embedded Form Factors — VPX, XMC, Chassis]].
4. **Every figure is single-sourced and unverified**, from an unattributed deck dated Aug 2026.
5. **Section 6a is an argument, not a customer.** It is a strong technical framing that still needs a requirement, a program and a buyer.

---

## ⚠️ Sourced vs. inferred

- **Sourced (the deck):** the compute-for-space vs. compute-for-Earth split · all power, thermal, radiation, mass, $/kg and bandwidth figures · the eight-rung evidence ladder and program placements · the China 12-satellite constellation · SpaceX AI1 and Suncatcher details · Starcloud-1's phase-change thermal design · the silent-error failure mode and protection list · the five investment gates and the bottleneck test · every quoted line.
- **Inferred (mine, Sep 8 2026):** **all of section 6** — in particular the claim that onboard AI moves cross-domain from the *complex* tier to the *fixed* tier (6a), the RAIN convergence (6c), the ground-segment-first sequencing (6d), and the application of the deck's own gates to Owl (6f).
- **Absent from the deck:** cross-domain, classification, CDS, guards, filters, coalition release, NCDSMO — any security framing at all.

## Open questions

- Is there an existing **cross-domain requirement in any space ground segment** — SDA, Space Force, NRO, commercial-imagery-to-classified pipelines — and who owns it?
- Does Owl have **any** credible path to a space-qualified or rad-tolerant product, or is the spacecraft side permanently out of scope?
- When onboard AI produces a **structured detection product**, who today decides its releasability, and is that decision made in orbit, at the ground station, or in the mission system?
- Does the **"decisions without waiting for Earth"** autonomy case create a requirement for release authority *on board* — and if so, what does a guard look like when there is no operator?
- Is the **China orbital-edge-computing** development already reflected in any US program requirement, or is it still ahead of the requirements process?

---

## Related
[[Cybersecurity & AI — The 2026 Landscape]] · [[AI Infrastructure — The Physical Value Chain]] · [[The Energy System — The Invisible Machine]] · [[Dataflow Types — Fixed, Streaming & Complex]] · [[Seams & the Two Spines — Where CDS Is Structurally Required]] · [[Zero Trust & CDS — The Boundary Argument]] · [[CDS Governance — CNSS, National Manager & the Authority Chain]] · [[Rugged Embedded Form Factors — VPX, XMC, Chassis]] · [[TRL — Technology Readiness Levels]] · [[Owl — Core Capability Evidence]] · [[BD Opportunity Garden]] · [[Glossary — Acronyms & Terms]]
