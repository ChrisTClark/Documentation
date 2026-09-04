# AI Infrastructure — The Physical Value Chain

*OSINT / learning reference · Sep 4, 2026. The companion piece to [[Cybersecurity & AI — The 2026 Landscape]]: that note covers **how AI changes security**; this one covers **the physical plant AI runs on** — power, heat, wiring, memory, and where the money actually sits. Built from a 24-page investor-oriented deck in `2_Working Tools/BD Signal Digests/AI ecosystem visual.pdf`.*

## ⭐ The one-line answer

Scaling laws turned intelligence into something you can **buy** rather than invent — which converted AI from a research problem into a **capital-expenditure problem**, and turned software into **heavy industry**. Software's historic escape from the physical world has reversed: the frontier is now measured in megawatts, cooled with water, and poured in concrete.

**And the consequence that matters for Owl:** the binding constraints on the AI buildout are no longer algorithmic. They are **electrical power, heat rejection, and the electrical room** — physical, safety-critical, legacy-OT-shaped infrastructure. That is precisely the terrain [[Janitza — Data-Center OT Power Monitoring (BD Thesis)]] already sits on, and this deck is the macro brief behind it.

---

## Part 1 — Why it happened: scaling laws made intelligence a capex line

The organizing analogy is that **an AI data center is a factory**: electricity in, words out. Three terms carry it — the **token** (the product, ~¾ of a word, and the unit revenue is priced in), the **FLOP** (the labor, hundreds of billions of them per token), and the **training/inference split** (building the factory once vs. running it billions of times a day).

The pivotal discovery, around 2020: make the model bigger, give it more data, spend more compute — and error drops **predictably**. On a log chart it is nearly a straight line. Each 10× of compute buys a steady drop in error and costs exponentially more.

**Why that changed the industry's shape:** for fifty years, better software meant hiring smarter programmers and hoping. Scaling laws made capability **purchasable** — and big companies know exactly how to compete on capital expenditure. *Outspend everyone.* Hence roughly **$750B a year** now going into a thing nobody needed to spend it on before.

Two structural notes the deck draws, both useful beyond investing:

- **Inference, not training, is the ongoing cost.** Roughly **two-thirds of all AI compute in 2026** is inference — every question manufactures its answer from scratch, every time, even if a million people asked the same thing. (Deck's illustrative figure: an OpenAI inference bill ≈**$14B** in 2026.)
- **Cheap AI is a software achievement, not just a chip one.** Serving engines make inference viable through **batching, KV caching, and quantization** — the deck credits these with **3–10× lower cost from software alone**, which is why API prices can fall ~80% in a year.

---

## Part 2 — The four physical constraints

### 1. Power density exploded — 60–100× in under a decade

| Rack generation | Draw |
|---|---|
| Traditional server rack (last 20 yrs) | **5–10 kW** |
| Nvidia flagship AI rack (today) | **120 kW** |
| Nvidia Vera Rubin rack (coming) | **~600 kW** |

A large AI campus wants **a gigawatt or more** — roughly one full-sized nuclear reactor, enough for ~1M homes. Data centers went from **4–5% of US electricity** before the boom to a projected **9–17% by 2030**.

### 2. The grid physically cannot say yes

Built for **1–2% annual demand growth**; AI arrived asking for tens of gigawatts immediately.

- **Interconnection queue:** 4–5 year wait to connect. In ERCOT alone, **410 GW** of large projects queued, **87% of them data centers** — roughly **5× the entire Texas grid's peak demand**, waiting in line. (Much is speculative — companies file in multiple states and take whichever connects first — but even a fraction is staggering.)
- **Transformer bottleneck:** the large power transformer went from **~1 year** to **2.5–4 years** lead time with an **~80% price increase**. *Chips in six months; the gray box that powers them, 2029.*

**So demand is going around the grid: behind-the-meter power** — generating on-site or next door, never touching the public queue. That decision, made by thousands of companies at once, revalued the boring industrial power sector: nuclear restarts (Microsoft/Constellation and Three Mile Island's undamaged **835-MW** unit, ~$1.6B, targeted 2H 2027, with Microsoft buying every megawatt for 20 years), gas turbines (GE Vernova sold out through the end of the decade), fuel cells, and SMRs — which the deck is careful to call **an option on the 2030s, not a business yet.**

⚠️ **And the political constraint, which is the one closest to home.** In the PJM market (13 states), data-center demand added **>$9B** to the latest capacity auction, translating to **$16–18 more per month on residential bills in parts of Ohio and Maryland.** Moratoriums are being proposed; public pushback is growing. **This is a genuine political risk to the buildout — and Ohio is on the list.**

### 3. Heat: cooling stopped being a support function

Every watt in becomes heat out. A flagship AI chip puts out **>1,000 W** — a space heater, from something postcard-sized. A 120-kW rack is ~80 space heaters in a cabinet you could hug.

**Air cooling worked to roughly 30–50 kW per rack. That line is now permanently crossed** — you would need hurricane-force wind through the servers. Liquid carries heat ~3,000× more effectively per unit volume. The ladder: rear-door heat exchangers (transitional) → **direct-to-chip, the 2026 mainstream** → immersion (the extreme). Nvidia's flagship racks don't offer liquid as an option; **they require it.**

Two vocabulary items: **PUE** (total power ÷ power reaching the computers; old ~2.0, modern liquid-cooled ~1.1) and **water**, which is becoming a permitting and political fight in dry regions and increasingly **decides where facilities get built**.

**Market:** liquid cooling ~**$5B (2025) → $15–27B (early 2030s)**. The deck's "clearest picks-and-shovels lane," because it doesn't care which chipmaker wins. Both Schneider Electric (Motivair) and Eaton (**Boyd Thermal, ~$9.5B**) bought into the same niche within months of each other.

### 4. ⭐ The electrical room — the layer BD should care about most

Between the substation and the chips sits **switchgear, busways, and UPS** — plus rows of Caterpillar/Cummins backup generators idling for the one hour a year the grid fails. **Three companies own this layer: Vertiv, Schneider Electric, Eaton.** Vertiv's backlog more than doubled to ~$15B; Eaton's electrical backlog grew 48% YoY.

**This layer is the whole reason this deck matters to Owl.** It is industrial power equipment — metered, monitored, networked, safety-critical, and long-lived — sitting inside a facility that is fast becoming *de facto* critical infrastructure. It is an OT environment by any honest definition. And it is exactly what the Janitza thesis instruments.

### Supporting constraints worth knowing

- **Networking is ~40–60¢ of spend for every $1 of GPU.** A frontier model doesn't fit on one chip, so it's sliced across thousands that must exchange intermediate results constantly; a network 10% slower can idle billions of dollars of silicon. **By early 2026, ~2/3 of new AI cluster networking is Ethernet** rather than InfiniBand — open standards, given time, usually win.
- **Memory is the hidden bottleneck.** The math is fast; moving data is slow. HBM costs 5–6× conventional memory for 5–6× the bandwidth and is one of the largest costs inside an AI chip. **Only three companies make it** — SK hynix (~60% share), Samsung, Micron (2026 sold out).
- **Storage got resurrected.** AI hoards data — training sets, checkpoints every few hours, outputs retained indefinitely. Seagate and Western Digital sold their entire production into 2027.

---

## Part 3 — Where the profit actually sits

### The margin ladder — the single most transferable lesson in the deck

| Tier | Gross margin |
|---|---|
| Nvidia (chips & software) | **~75%** |
| Component suppliers (power, cooling, chassis, cables, connectors) | ~10–20% |
| Branded server integrators (Supermicro, Dell, HPE) | ~6–10% |
| ODMs (Foxconn, Quanta, Wiwynn, Celestica) | ~4–7% |
| Logistics & manufacturing services | ~1–3% |

> **The lesson, in the deck's words: profit lives in whatever is scarce. Chips and software are scarce. Assembly is not.**

Note where **component suppliers** sit — *above* the branded integrators who assemble the finished racks. Specialized hardware components out-earn system integration. That is a hardware-company lesson with a direct read for Owl in Part 5.

### The moat is not the silicon

Nvidia's ~75% hardware margin isn't explained by the chip. It's **CUDA** — twenty years of software every AI developer was trained on. Nvidia sells the only complete factory-floor system the world's engineers already know how to operate; buying a competitor's chip means retraining your workforce and risking a $100M training run.

> **The moat is not the silicon. It is the muscle memory of millions of engineers.**

⚠️ The bear case is in the deck too: ~40% of Nvidia's revenue comes from four customers — **all four building their own chips to replace it** — with Broadcom quietly co-designing most of those custom chips and dominating the switch silicon on both sides of the networking war.

---

## Part 4 — ⚠️ The circularity risk

The deck's closing move is to draw the arrows of who pays whom, and finding that **they form a circle**: Nvidia invests in neoclouds and labs → neoclouds buy Nvidia chips → hyperscalers sign contracts with neoclouds → labs sign compute deals with hyperscalers → labs sell products to end users → and **only that last arrow brings fresh money into the loop.**

**~$725B annual spend against a combined top-two-lab revenue run-rate of ~$70B+.** The deck's framing: real infrastructure and real products, but the loop ultimately depends on end-user demand, and the whole machine is a bet that the small corner grows faster than the big circle spins.

**Keep this.** Any BD thesis keyed to data-center buildout inherits this risk. It doesn't invalidate the thesis — power, cooling and electrical gear get built either way, and the installed base still needs monitoring — but it caps how confidently anyone should extrapolate the buildout curve.

---

# Part 5 — ⭐ What this means for Owl

## 5a. This is the market brief behind the Janitza thesis — and the timing is immediate

[[Janitza — Data-Center OT Power Monitoring (BD Thesis)]] is built on structural market logic rather than a deal to ride, with the explicit open question of **whether secure data-center customers require one-way OT isolation, and what they use today.** This deck supplies the *why now* underneath it, in the customer's own vocabulary:

| What the deck establishes | What it does for the Janitza conversation |
|---|---|
| Power density 5–10 kW → 120 kW → ~600 kW/rack | Power quality and residual-current monitoring go from useful to **load-bearing** — GPU power volatility is exactly what Janitza's Class A meters and RCM exist to catch |
| Grid can't connect them; behind-the-meter generation is the workaround | **The data center is becoming its own power plant.** That is a genuine ICS/OT environment, not a facilities annex |
| Vertiv / Schneider / Eaton own the electrical room, backlogs doubling | Names the incumbents Janitza sells alongside — and the integrator channel that specs both |
| Liquid cooling mandatory at flagship density; ~$5B → $15–27B market | A **second** safety-critical OT loop (water, at pressure, next to energized equipment) arriving in every new build |
| PJM data-center demand → residential bill increases → moratoriums | Political scrutiny drives **metering, reporting and proof of consumption** — a monitoring tailwind, not just a cost |

**⭐ Actionable:** per the existing thesis, Janitza's US CEO is a close friend and **Chris sees him in Austin Sep 11–13** — a week out. This note is the market context for that conversation. The deck's power/cooling/grid numbers are the shared language; the thesis file already holds the questions worth asking.

## 5b. Data centers are becoming critical infrastructure — which merges this with the cybersecurity note

Read alongside [[Cybersecurity & AI — The 2026 Landscape]], the two notes close a loop:

1. The collective-cyberdefense letter names **critical infrastructure** as the priority and asks governments to fund its defense. AI data centers are on a fast path to being classified that way — they are already a grid-scale, politically visible load.
2. Their OT is **new**: on-site generation, switchgear, UPS, and now pressurized liquid-cooling loops. New OT built at speed, by contractors, under schedule pressure.
3. That OT needs to send telemetry **out** — to vendor monitoring, to an AI-driven operations centre, to the utility, to a regulator — without acquiring an inbound path into a facility where a cooling failure is a physical event.

**That is opportunity #2 from the cybersecurity note — one-way telemetry egress — with a named channel and a warm introduction already in the vault.** The two theses were developed independently and point at the same door.

## 5c. The scarcity lesson, turned on Owl

The margin ladder is the sharpest input this deck offers to the pending Phase 3 VRIO / extinction test in [[Owl — Core Capability Evidence]]. **Profit lives in whatever is scarce; assembly is not scarce.** So the question to put to Owl's own position is uncomfortable and worth asking plainly:

- **Is the scarce asset the box?** If so, the deck's lesson is that hardware assembly commoditizes toward single-digit margins, and specialized *components* out-earn integrated *systems*.
- **Or is it the CUDA-shaped thing** — the accreditation, the installed base, the operator familiarity, the authority chain in [[CDS Governance — CNSS, National Manager & the Authority Chain]]? Nvidia's moat is switching cost measured in retraining and risk, not silicon.

**If the second, that reinforces the warning already recorded in [[Cybersecurity & AI — The 2026 Landscape]]:** in non-RTB commercial markets, the CUDA-equivalent doesn't exist. There is no accreditation gate, no installed baseline, no trained operator population. **You would be selling into the margin ladder's middle rungs on product merit alone.** Both notes reach that conclusion by different routes, which is a reason to take it seriously.

## 5d. Sovereign and defense AI — the thinner thread

HPE is described as riding supercomputing and **sovereign-AI deals** with strength in government infrastructure. Defense and IC AI enclaves face identical power, cooling and density physics, plus classification boundaries. **Unverified and undeveloped here** — flagged as a thread, not a thesis. Any classified AI enclave is an NSS environment, which puts it back inside the RTB gate rather than outside it.

## ⚠️ Risks before acting on any of this

1. **The circularity risk in Part 4** caps extrapolation of the buildout curve.
2. **The political risk is real and local** — moratoriums and Ohio bill increases could slow siting in exactly the region Chris sits in.
3. **This is an investor's map, not an operator's.** It is organized around who makes money, not around how a facility is engineered or procured. Useful for context and vocabulary; **not** a source for technical specification.
4. **Every figure is single-sourced and unverified**, from a deck dated July 2026 in a fast-moving market.
5. **Owl has no evident position in this value chain today.** The deck names no security vendor anywhere in the electrical, cooling or networking layers — which is either whitespace or an indication that facility owners don't currently buy security at that layer. **That ambiguity is the thing to resolve**, and it is resolvable in one conversation.

---

## ⚠️ Sourced vs. inferred — keep the line clean

- **Sourced (Cui deck, July 2026 — unverified by me):** all power, grid, thermal, market-size, margin, backlog and revenue figures · the scaling-law framing · the factory analogy · the CUDA-moat argument · the circularity diagram and the $725B vs ~$70B comparison · the PJM/Ohio bill figures.
- **Inferred (mine, Sep 4 2026):** the entire Part 5 · the claim that behind-the-meter generation makes a data center an ICS/OT environment · the merger of this with the cross-domain thesis in [[Cybersecurity & AI — The 2026 Landscape]] · the application of the margin ladder to Owl's own VRIO question · the reading of political scrutiny as a metering tailwind. **None of this is the deck's argument** — it is an investor explainer with no defense or security content whatsoever.
- **Not in the deck at all:** cross-domain, diodes, OT security, defense, government procurement. The security angle is entirely additive.

## Open questions

- Do secure or government-adjacent data-center builds currently specify **one-way isolation** for power/BMS/cooling telemetry, or is that boundary handled with firewalls and VLANs today? *(The single highest-value unknown, and answerable conversationally.)*
- Does the arrival of **liquid cooling** create a second monitored OT loop with its own vendor-telemetry egress problem, or does it fold into existing BMS?
- Where does **behind-the-meter generation** put a data center in regulatory terms — does operating its own generation pull it under any existing critical-infrastructure or utility monitoring regime?
- If facility owners don't buy security at the electrical layer today, **who would have to** — the operator, the integrator, the equipment OEM, or the insurer?
- Does Owl's product portfolio have anything that fits a **commercial facility** price point and form factor, or is this a market that would require new development? → [[Rugged Embedded Form Factors — VPX, XMC, Chassis]]

---

## Related
[[Cybersecurity & AI — The 2026 Landscape]] · [[Janitza — Data-Center OT Power Monitoring (BD Thesis)]] · [[Zero Trust & CDS — The Boundary Argument]] · [[Owl — Core Capability Evidence]] · [[CDS Governance — CNSS, National Manager & the Authority Chain]] · [[Peer Capability Evidence — Everfox, Waterfall, Advenica, Garrison]] · [[BD Opportunity Garden]] · [[TAM, SAM & SOM — Market Sizing for BD]] · [[Owl Partner & Ecosystem Map — Commercial & International]] · [[Glossary — Acronyms & Terms]]
