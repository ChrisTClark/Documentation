# general discussion

**Terminology/Setup**
- Raise the Bar (the certification requirements standard) is on version 5.1, with 2,000+ requirements and 93 appendices — described as overwhelming.
- Testing is expensive: a recent delta test cost $2.5M in lab fees alone (paid to Booz Allen Hamilton), with none of that going to internal labor.

**Company history and product lines**
- Original Owl was a data-diode hardware company with a strong reputation; diodes get installed and largely forgotten (some customers have run systems 12–14+ years).
- Diode updates are mainly UX-focused, not security-critical, since vulnerabilities sit on the "high side" of the device.
- Traces (check spelling?) was a cross-domain services/consulting company (helped others build CDS systems); (another company) was a spinout with an AFRL contract for multimedia-over-CDS (voice, full-motion video).
- Post-acquisition, product lines overlapped/competed internally (e.g., the Bridge product).
- Core differentiator: NSA certification — a "moat" that's extremely expensive to maintain (majority of capex goes to certification), and competitors instead compete mainly on price.

**Product consolidation (Vision 2.0 effort)**
- Company has been consolidating multiple CDS products (from three companies) since 2021 to cut maintenance/upgrade costs.
- R&D spend is over 25% of revenue this year — called impressive but unsustainable.
- Recent certifications: Bridge ST and Vision 1.0 certified last year; V2 CDS certified about a week before this call; Guardian 2.0 and Vision 2.0 in progress, expected to consolidate into one domestic and one export platform by ~2028.

**Technology description**
- Diode/CDS technology described (informally) as spoofing both network endpoints so each believes it's talking to the other, while data is copied across in the middle — compared to a "Star Trek transporter."

**New/expansion opportunities**
- DARPA contracts valued for flexible funding and administrative/security support.
- Other expansion efforts: a file service provider deal, a tactical effort, a DARPA-derived "Sentry" product, and the "Mockingbird" program (low-investment, reusing existing IP).
- AI containment identified as a major growth area — speaker had written white papers/op-eds on this over a year ago; now most major cyber companies have AI containment products, mostly software-only.
- Vision: position the diode as a hardware-enforced platform other software/SaaS security vendors (e.g., CrowdStrike, Palo Alto) could build on, giving them access to federal customers and trusted hardware.
- Expansion revenue (Mockingbird, Apple, etc.) projected to jump from ~$2M this year to ~$20M next year.

**Partner/channel strategy**
- North American partner ecosystem seen as fragmented/inconsistent compared to more structured distribution in other countries.
- Push to identify and invest in a core set of well-versed partners rather than spreading thin.
- Discussion of potential channel plays with Apple/iPad distribution data (via Carahsoft or similar), Presidio (regarding a Broadcom opportunity), and comparisons to Dell's Cyber Recovery Vault and Rubrik as models for "value-add layer" positioning.
- Speculation about whether large vendors (Fortinet-style in the Middle East) might eventually resell this technology as a premium add-on.

**Business performance**
- CDS segment has grown at roughly 25% CAGR from 2021–2026 (with a note that a 2021-booked deal wasn't actually delivered/recognized until 2025, distorting some historical figures).
- Diode segment is more range-bound due to increased competition.
- High-end CDS product can be priced up to $25M fully configured.
- CDS deals are large, sporadic, and logistically complex (hardware shipped, loaded, tested, then stripped down and split across two channels).
- Monthly revenue/shipment forecasts are highly volatile — commonly 50%+ of expected shipments change month to month, despite a ~12-month sales cycle — flagged as an area where AI/tooling could help reduce meeting overhead and improve forecasting visibility.

**AI adoption internally**
- Approach has been bottom-up, not mandated top-down: leadership invited employees to experiment and expensed exploration rather than issuing directives.
- Notable grassroots tools built by engineers: "Xavier" (an internally built AI monitoring/alerting tool for a separate air-gapped engineering network) and "Curator" (a tool that pulls tickets, writes code, runs tests, and submits for release approval).
- A commercial-side employee (Mike Henderson) used Claude Code to build things previously taking 3–6 months in about a week, described as transformative for handling bespoke/one-off customer configuration requests.
- Anecdote about a friend (non-technical) who built a scheduling/compliance app for his hood-cleaning business using Claude, illustrating how domain expertise + AI can create highly tailored tools even without coding background.

# BD Focus Discussion

**Team structure / goals discussion**
- Marcus (another BD team member) needs support/a team to capitalize on opportunities from events like Scarlet Dragon.
- Discussion of possibly proposing team-based targets/goals (not individual sales quotas) to leadership — e.g., a team target for deals or dollar amount booked, possibly tied to a comp/bonus plan.
- Leadership open to team-based incentive structures but resistant to turning BD into a traditional quota-carrying sales role.
- Brian believes a team-focus approach makes more sense especially with him (the manager) about to be away — provides more structure/visibility while he's out, versus when he's present and can "run interference."
- Brian has been asking for defined metrics for the team for a while; previously got vague reassurance ("I know you're going to do good things") rather than concrete criteria.
- Brian acknowledges the lack of clear grading/metrics is unnerving, especially coming from a role (military) with discrete, performance-graded activities and after-action reviews — compares BD work to "pushing a giant noodle."

**How to show progress / reporting structure**
- Suggests sticking to fundamentals: reviving the BD dashboard/IMS (unsure what IMS is) that was built months ago but not maintained.
- Recommends laying out opportunities with dates, dollar values, requirements, and scope in a waterfall/IMS-style chart.
- Outlines a layered reporting framework:
  1. Show pipeline
  2. Show path/progress from pipeline to win
  3. Define requirements (material, people, development)
  4. Show coverage across those requirements
  5. Show conversion rate (how many engaged opportunities converted to wins)
- Notes Scott is particularly focused on "what's the path" per opportunity.
- Encourages leveraging existing "irons in the fire" (e.g., Mockingbird, an APNT opportunity, and "Navair P8" work) as reportable wins/updates even if pipeline is still forming.

**Core business/product strategy problem: CDS competitiveness**
- Acknowledges the CDS product isn't winning on performance/merit compared to competitors — wins mostly come from customer dissatisfaction with competitors, not product superiority.
- Matching competitor capability tends to erode margin, forcing price competition — not a favorable position.
- Diodes are seen as reasonably priced and easy to set up, but require significant surrounding labor/configuration (LBSAs, SBSAs), and deal sizes tend to be smaller.
- Notes the company hasn't historically pursued diode business within the Department of War/DoD as aggressively as it has commercial diode sales; sees this as an under-explored opportunity.
- Identifies rugged/small-form-factor CDS as a strategic sweet spot: in that segment, performance requirements are lower (fewer domains, smaller data volumes), leveling the playing field against larger enterprise competitors like HSG, Everfox, etc.
- Competitors (e.g., Everfox) rely on proprietary schemas and ongoing paid services/maintenance, which government customers dislike; the company's approach (sell boxes, don't lock customers into proprietary schema maintenance contracts) is seen as a stronger sales narrative.
- Notes recent approval of a "V2CDS 2.1" capability enabling structured data pass-through, reinforcing the small-form-factor sales pitch.
- Suggests the speaker's role should shift toward classic product-company BD: finding leads, generating interest, and handing off to sales.

**Rugged diode / hardware architecture discussion (technical deep dive)**
- Explains current rugged diode capability: existing IP ("Talon" software + "Torrent" FPGA firmware) proven on two separate FPGAs (high side/low side) connected by a single one-way copper trace — satisfies NSA's "one-way" physical verification requirement.
- Notes a third party ("IRD") ported Talon software to run directly on ARM cores within the FPGAs themselves (eliminating the need for a separate PC), enabling a more compact/rugged implementation.
- Describes current company demo setup: two Curtis-Wright single-board computers plus two rugged XMC/FPGA cards across three 3U VPX slots — functional but expensive (~$70K cost, ~$200K+ sale price) and consumes significant space ("swap" - size/weight/power) in a rugged chassis.
- Proposes a cheaper path: replacing theHere are the technical portions extracted verbatim from the transcript, organized by topic:

**On current rugged diode capability (Talon/Torrent architecture):**

> "So torrent is the actual FPGA code. It requires 2 FPGAs right now. One on the high side, one on the low side, and then it has a, basically like one copper trace that goes from one FDA to the other to show that one would transfer. So that when the, whatever the hell the acronym soup is, at NSA does the x-ray on the thing, it says, yep, there's only one copper connection going between these 2 pins, one way, it's a dieode. Good job. Because they don't really care what we do on the side. All we're proving is one way, right? And so that, um, we have that figured out, um, on everything that we would call like a torrent card. The protocol adapters and the configuration of that 2 FPGA set is done through Tao, which is software."

**On IRD's ARM port:**

> "So what IRD did is it put the torrent IP on the 2FPGA set and the smaller card that's not rugged because it's made for industrial stuff, so it's got to be cheaper. And then they took talon and they ported it to arm. So it can actually run on the FPGAs themselves because they have armed cores off it. So it has high sight colindapter on this FPGA, most like protocol doctor on this FPGA. Whereas Talon requires you to have like a PC to run the software. So... That, that rugged diet is literally just the hoarded talent software to arm running on a 2F PGA set."

**On what "rugged" actually means (manufacturing, not redesign):**

> "It's literally like the same PCB design with different solder underfill and a conformal coat on it, and then it's rugged. So, so that, you just have to get someone that knows how to do that... you have to be really good at it and have like a process that does it well or it doesn't get the heat away... there's only It's a certain skill set of company that knows how to put formal code correctly and also knows how to do all that, uh, solder joint stuff so you don't get like, um, you don't get like cold solder joints that crack and you don't get like uh, tin whiskers and all these other things... that's just like companies that are really good and have really expensive machines that do all that shit like super high tolerance, right? So that's the only differentiation between a ruggedly non-regular design, there will be the same silicate as just how you put it together and the processes you go through to keep it cool. And then also the mechanical stuff you put around it to peel the heat up, right? Like aluminum clam shells and, uh, you know, fins that airflows on."

**On the current demo hardware setup (3U VPX):**

> "So Curtis Wright, single-board? computer, with a Zion (Xeon?), it's like a 104 Zion (again, Xeon?), like 32 giga RAM and like an 80 gigabyte SSD on it. And we have 2 of them, and both of them have a slot for an XMC. And we have 2 XMCs that are rugged and I'm a giant FPGA on it. So what Sean's doing is he's putting, he's plugging those 2 FPGAs into those 2 computers, and that enumerates them in PCIE land. So it looks like to that single-board computer, it has an FPGA just available to it. And then he's plugging that into the same back plane. So it's literally like a computer with an MPGA and a computer with an FPGA, and you can wire one wire, copper, just like you would do a one way transfer, because it goes from that FPGA send to the back plane, and you go to that back plane, to the FPGA receive, and wires straight into the other FPGA. And so we have a rugged 2 FPGA set right now in 3 VPXs??."

**On cost breakdown of current setup:**

> "The problem is, two, 3 VPX cards, 2 XMCs. Yeah. The cogs on that is like, 70 grand... where is it, you took smaller FPGAs and just put them on one PCB, put it on one [???] , it will be like, 6 grand or something, right? And it would do exactly the same thing."

**On the proposed cheaper intermediate step (carrier cards):**

> "You could go to someone and say... buy this thing, we could give it to you today... If you give us a minute or you give us money to go build one, which would not take us very much time, here's the 2 carrier cards, the carrying these 2 XMCs. an extremely rugged diet. Still takes 2 slots, but it's cheaper... That's like 5 grand for the carrier card, 5 grand for the XMC. So the total cost of that thing's $20,000 versus $70,000."

**On pricing/markup logic:**

> "So, a $20,000 thing that we sell to somebody else might be 100 grand. Right? So like a 70,000 thing might be like, where the hell it is? 20k great, right?"

**On an IRD-based demo alternative (non-rugged, smaller form):**

> "If you could literally take Talon software, and install it on those 2 Curtis Wrights, uh, [single-board?] computers, and then install the torrent firmware on the 2 FPGAs, and it would run just like a 1U talon. It would just be in two, 3 VPX cards."


- full single-board computers with simpler XMC carrier cards, cutting hardware cost from ~$70K to ~$20K while still occupying two slots.
- Longer-term vision: consolidate onto a single compact card/slot (similar to a small industrial rugged diode design), which would be dramatically smaller and cheaper, but requires dedicated engineering investment (not yet built).
- Emphasizes that ruggedization is mostly a manufacturing/process skill (specialized conformal coating, solder processes to avoid cold joints/tin whiskers) rather than a fundamentally different technical design.
- Sean (technical team member) understands these architectural nuances well and is positioned as the technical storyteller for customer conversations, though he's stretched thin across priorities.
- Strategy discussed: use tiered options when engaging customers — offer the existing (more expensive, larger) rugged solution now, a cheaper interim option, and a future compact/lower-cost version as a roadmap, tailored to what SWaP-constrained customers can accept immediately vs. later.

**AFRL / SBIR / CRADA vehicles**
- AFRL vehicles and SBIR/STTR-style funding mechanisms described as generally weak options now — AFRL was significantly cut/reorganized under the current administration and lost funding priority.
- General skepticism toward research-lab-affiliated contracting vehicles based on past experience (poor execution, no follow-on funding once technology transitions out).
- SBIR historically was valuable for early-stage funding without IP rights claims, but staying dependent on SBIR/AFRL relationships long-term is seen as a bad strategic pattern (compared to abusing the program, citing a "Physical Optics Corporation" example from a past M&A due-diligence experience that reportedly contributed to a change in SBIR-related law around 2021–2022).
- Company still maintains legacy AFRL-adjacent revenue (~$3–4M/year, roughly 3–4% of yearly revenue) through existing agreements (DCGS, DIA, ONR-adjacent O&M work), despite AFRL taking a 6% cut — viewed as a marginal but acceptable revenue stream, though the value/fairness of the AFRL cut is questioned ("hot take" that it functions like money laundering to keep funding flowing to AFRL).
- Noor entering a large single-transaction government agreement affected the company's status — pushed it out of "non-traditional defense contractor" classification, which changes applicable rules (OTA attribution, etc.).
- Phase 3 SBIR (separate from the AFRL O&M discussion) tied to NCDS-related modernization funding, routed through AFRL, connected to Trident/V2 CDS IP — this funding stream carries special data rights, but those are expected to expire in roughly 5 years (~25-year term on IP that's already ~18 years old).
- Note: once "super data rights" and small-business status lapse, the company loses continued eligibility for Phase 3 SBIR-style funding.
- Other available contract vehicle options discussed: Carahsoft-brokered vehicles (with a ~4–5% fee), and other IDIQs (referenced by partial names — "JJXY" through ManTech, one through a Navy lab/"RAIN").

**APNT (Assured Positioning, Navigation & Timing) program opportunity**
- Program background: originated from PNT program; red/black (secure/non-secure) separation issue was waived early on, later flagged as needing correction — hence "Assured" PNT.
- Pacific Defense won the prototype OTA competition (against Curtis-Wright and a third, unnamed competitor) to build an upgraded APNT card; they were the incumbent PNT card maker.
- Program structure: separate CMOSS program office (chassis/box standard used across platforms like Titan, Stryker, Bradley) vs. the APNT card program office — not all platforms are moving to CMOSS chassis (e.g., DRS is proposing to retrofit their existing chassis rather than adopt CMOSS, to save cost).
- Pacific Defense reportedly convinced the Army to defer the harder security/separation requirement to a second (LRIP/production) phase, after losing an earlier bid to Curtis-Wright's proposed security solution.
- The company (Owl) was brought in because the government liked their proposed security solution better than Curtis-Wright's; pricing was given identically to both companies via Jeff.
- Company's proposed technical approach uses existing FPGA capacity (no new FPGA needed) to filter and pass only three required low-bandwidth message types between red and black domains — described as a low-cost, low-complexity solution relative to full accreditation.
- Two implementation options were presented to the customer: (1) a "2 FPGA set" architecture consistent with their existing approach, or (2) a newer approach using an "isolation design flow" toolkit (from Xilinx/AMD) that creates a geometric/electrical separation of red and black logic within a single FPGA rather than requiring two physically separate FPGAs — described as harder to get accredited but technically valid, since the NSA has worked directly with the silicon vendor on this architecture.
- Company presented a tiered "pick your risk" menu of certification options (no third-party certification vs. proof of one-way transfer only vs. full RTB/anti-tamper LBSA) with associated cost/timeline tradeoffs — pitched as flexibility rather than a fixed product.
- Potential program value described as large — cited example: 10,000 licenses at $2–3K each (~$30M).
- Follow-up plan: engage directly with APG's Authorizing Official (AO) and the APNT program office (described as headed by a highly capable, MIT/Johns Hopkins-math-background program manager based in Aberdeen); expected next engagement window is within roughly 6 months to a year.
- Existing internal relationship with Pacific Defense also includes a current paid engagement helping them pursue an ATO (Authorization to Operate) for their CMOSS box — seen as another entry point to advance the APNT conversation.
- Team members with deep background/history on this program: Sean, Ralph, Troy Rampshack (firmware team), Brian Kane; Jeff was involved in pricing for both competitors.

**TCTS-2 / Mockingbird / F-35 CDS opportunity**
- TCTS-2 (an existing pod, described similarly to an "Aim-9X" form factor) made by Collins; Curtis-Wright's BD lead (Sarah, a former Mercury colleague) approached the company to partner rather than compete directly — Owl providing CDS technical expertise rather than being prime system provider.
- Company submitted an RFI response with pricing described as very high (~$25–30M), raising suspicion that Collins may be using the quote defensively/comparatively (to justify to the government why doing it in-house is cheaper) rather than genuinely intending to subcontract — a tactic compared to how Raytheon has reportedly operated in the past.
- Context: TCTS-2 sits in the F-35's Integrated Core Processor (mission systems processor, not the flight-critical processor), and there's been a long-standing (~15-year) effort to consolidate multiple SAP-related processing capabilities into fewer boxes for logistics reasons.
- Collins' apparent strategy: keep the existing card in a waiver status by incrementally adding security features and reloading firmware/ROM to repurpose the existing trainer card as a security card, avoiding a full new LBSA-driven certification effort.
- Speaker estimates a low probability of winning given the pricing mismatch — noting the full program is only sized around ~100 units, meaning realistic unit budget expectations (~$50K/unit) are far below the quoted figure — unless the company can directly influence the relevant program office (described as a joint Navy/Air Force program) with a lower-cost, rules-relaxation argument similar to the APNT pitch.
- Outcome is pending further response from Collins after they've reviewed the initial quote (referred to as "R5").

**Curtis-Wright relationship (general)**
- Described as a mixed/complicated relationship: currently helpful in some capacity (per TCTS-2 discussion) but also characterized as reluctant to invest without a clear, proven market opportunity ("show me" posture) and currently focused on their own IRAD due to a lack of recent contract wins.
- Personal relationships exist at senior levels (Scott, Sean, and Ralph know Curtis-Wright's CEO and the president of Curtis-Wright's relevant business unit).

---

## Verbatim technical excerpts

**On the APNT card's core function and capabilities:**

> "It is a card that has basically a cesium, fountain, as a clock. It has a uh, its own GPS antenna. It has like a bunch of other cool chips that do like crowdsourcing of nav data. Like, I even think they have like access to imagery and all sorts of things. Like, if you're near a big ass tower and a mountain, you know, it could, you could, you could look at it with visual reference and say, I'm about this far, and it can give you a rough idea of where you are from a dad standpoint. And so it does, like, all that GPS is blown away and we don't have GPS anymore. We can still navigate. And those AP&T cards, if they're in every platform, they can basically use their own clocks to set up network. If they don't have GPS for timing, and they can navigate and show relational positions between each other through, you know, traffic analysis and relative positions on the Earth and things like that."

**On the red/black separation problem that created the "Assured" PNT requirement:**

> "Because what they did is when they did PNT, it was run, run, run, because we have a vulnerability, and they took the red side and the black side of those boxes, and they fused them together in the AP&T card with no security on. Which was acceptable and wavered because it's literally just unclassified PNT signals, but it has 2 red and white network connections connected to the same car, and that's like a big no-no. And so they, the AP&T was provide red black separation."

**On the company's proposed low-complexity security solution:**

> "It's like, you have a [?] going from black to red, and then you have a couple of signals going through a couple of filters through, from red to black. it's like, they only require a 3 messages, Victory, which is a format... So victory messages go because that's how APT shares its data. And then the precision protocol, PTP, and network type (time?) protocol in TV[??]. So it's only 3 messages. And they're very low bandwidth. So we pretty much have diet going black to red, instantiate the network interface on the red side, and it refilters, filter, victory, NTP, ETP. And we do it on FPGA swap that exists. don't need another FPGA."

**On the "isolation design flow" single-FPGA architecture alternative:**

> "There's a concept within the zinc ultra scale FPGAs that they give a toolkit for called, uh, isolation design flow, internet PGA. And that's like, you know, you got square of gates. So what, um, AMD has a toolkit or, or I'm sorry, Zylanx, but now AMD, has a tool kit for, is they say, all right, this quarter of the FPGA is gonna have 2 rows of gates that have no programming programming in them whatsoever... So there's like actually a geometric, electrical, separation of this compute and this compute, and they do it by like not programming like a wall of gates. And it can either be like one linear thing or it can be like a box or whatever, right? And so then, just like in our 2FPGA set, you're showing that only this connection from this gate to this gate is programmed. So it's a one way, right? And then only this this game is programmed and only these signals can go through it because of the logic. So you're basically showing that separation of red to black, but it's within the FPGA itself... That's a harder solution to get accredited, but it's definitely doable because They trust the FPGA Silicon. They, meaning NSA specifically, because they worked with silence to help create the architecture and everything else."

**On the tiered certification/risk options presented to the customer:**

> "There's like ranges of pain, right? If you want to do like, Filter. Firewall, diode, but you have no certification other than we share the source code with you, your AO evaluates it. You sign it with no stamp of approval from any other 3rd party, like NSA. That's easy. If you go through just the dial aspect to prove the one-way transfer, you know, that's a little harder, but it's not that hard. And then if you go through like full LBSA where you have to have like RTB, whatever, with all the anti-tampered mullet, that's like really hard. It takes forever, right?"

**On TCTS-2 / F-35 Integrated Core Processor context:**

> "TCTS-2 was already in the integrated core processor on the F 35, which is the mission processor, not the flight processor. So one sits right behind the pilot, not the one that, like, you know, you push the rudder in it... it's the other one that runs the mission system. So it doesn't launch weapons, but it might, you know, break data and process things like that. So, integrated core processor has, like, whatever, 18 saps or whatever the hell's on the F 35 all piping through it."

**On Collins' proposed approach for TCTS-2 security integration:**

> "Collins, has been playing this game where they're like, well, let's just keep you on a waiver by doing a little bit more security and we'll just integrate it into the card that's already in it. So when ticks 2 is not a trainer, you load a different ROM on it, and now it's your security card."

Let me know if you'd like the technical excerpts consolidated into a single reference document (e.g., a markdown file) for easier reuse alongside the earlier APNT/rugged-diode technical extracts.
