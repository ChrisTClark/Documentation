Description

Find cross-domain and boundary-security demand inside published DoD budget
justification documents. Use for questions about program funding, budget
lines, where cross-domain money sits, program element or line-item research,
J-book analysis, or sizing demand from public budget data. Includes the
search lexicon, the false-positive traps, and the graded discriminator.

Instructions

THE CORE REFRAME
Cross-domain is almost never its own budget line. There is no "CDS"
appropriation - it sits inside host programs (a platform's C4ISR line, a
network-modernization PE, an intel program, O&M sustainment). So the task is
NOT "find the CDS line." It's FIND THE HOST PROGRAMS, THEN INFER THE CDS
CONTENT - a bill-of-materials inference against someone else's budget.

EXHIBITS
R-2/R-2A: RDT&E narrative - richest prose, where functional language appears
P-40: procurement narrative - intent and quantity rationale
P-5: cost analysis - SUB-LINE ITEMS AND UNIT COSTS, where a CDS surfaces as
     a discrete priced element (the most valuable rows)
P-3a: individual modification - retrofits, often where CDS gets added
O-1/OP-5: O&M detail - sustainment, accreditation, support tails

SEARCH IN LAYERS - functional terms out-yield explicit ones, because a
program office describes what a thing DOES more often than it names the
acquisition category.
Tier 1 explicit: cross-domain, CDS, cross domain solution
Tier 2 functional (HIGHEST YIELD): data diode, one-way transfer/gateway/link,
  unidirectional, multi-level security, MLS, sanitize, downgrade, domain
  transfer, releasability, content filter, guard
Tier 3 governance: NCDSMO, Raise-the-Bar, RTB, CDSE, CDSO, 8540.01,
  CNSSI-1253, SABI, TSABI, CDTAB, DSAWG, CDSA, LBSA
Tier 4 boundary: enclave, security domain, coalition information sharing,
  Mission Partner Environment, MPE, NOFORN, REL TO, SIPR, NIPR, JWICS,
  IL5/6/7, air gap
Tier 5 platform/MOSA: SOSA, CMOSS, OpenVPX, MOSA, VICTORY, 3U VPX

FALSE-POSITIVE TRAPS - these matter more than the lexicon
- "CDS" = Common Display System (Navy combat display) - THE BIGGEST NOISE
  SOURCE. Suppress if "Common Display System" or "Common Processor System"
  appears on the page
- "CDS" = Curriculum Data System (Navy training)
- "CDs" = Capability Drops - matches only if searching case-insensitively.
  MATCH "CDS" CASE-SENSITIVELY
- "cross-domain" in the OPERATIONAL sense (cross-domain warfighting/fires/
  effects) = multi-domain operations, NOT a security boundary
- "guard" = overwhelmingly National Guard. Blank that out first
- "MSL" = Mean Sea Level. "RTB" = Return To Base
- "downgrade" also means capability reduction - enrichment only, never a trigger

GRADE, DON'T GATE
Requiring co-occurrence of an explicit term with a governance term was TESTED
AND REJECTED - on 4,794 real pages it returned 7 hits and discarded ~30
genuine references including a priced procurement line. The real problem is
acronym collision, not weak context.
STRONG: the explicit phrase "cross domain solution/enterprise solution" -
  near-zero false positives, auto-promote
LIKELY: case-sensitive CDS with no collision term on the page
TRIAGE: generic cross-domain, no ops-sense match - human read required
Suppress: collision term present, or ops-sense with no explicit phrase

ATTRIBUTION - the trap that cost two rebuilds
RDT&E is keyed by PROGRAM ELEMENT; procurement is keyed by P-1 LINE ITEM.
Mixing them silently deletes half the data. KEY OFF THE RUNNING HEADER ON
LINE 2 - it exists on every page of both book types including P-5
continuation pages. Never attribute evidence to every PE mentioned on a page;
narratives cite other PEs and this manufactures fake findings.

WHAT THIS IS FOR - state this honestly
It's a WEAK lead-generation tool for greenfield BD. A published budget line
means the requirement was shaped and awarded years earlier. Most of any
register built this way is capture/displacement terrain, not new business.
Genuinely good for: sizing (a defensible number instead of an assertion) /
DISQUALIFICATION (knowing a boundary is incumbent-held stops wasted effort -
negative information that prevents work is worth real money) / first-
appearance signal (future-tense language in a program's first year is
genuinely pre-award, but rare) / timing / credibility (quoting a customer's
own justification back to them).

CLASSIFY EVERY ENTRY - never present a flat list, which reads as a target
list and invites the wrong conclusion:
Emerging / Forward-scaling / Incumbent-held / Dormant

LIMITATIONS
Unclassified budget books systematically undercount cross-domain spend -
much sits in classified annexes and the intel budgets. ANY PUBLIC NUMBER IS
A FLOOR, NOT AN ESTIMATE. Budget documents describe intent, not outcome -
pair with execution data (USASpending, FPDS) before treating as demand.



