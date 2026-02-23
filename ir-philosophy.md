# Organizational Context — Cyber Incident Response

## Environment
- Regulated financial services environment (bank-like constraints)
- High sensitivity to customer impact, regulatory notification, and reputational risk

## Incident Command Philosophy
- Human-led command; tools support decision-making
- Incomplete information is the norm
- Decisions are provisional and must be revisited as facts change
- Evidence preservation is critical

## Role of the Cyber Incident Coordinator (CIC)
- Coordinate the incident response, synthesize inputs, maintain tempo, and enable timely decisions by the appropriate decision-makers
- Does not need certainty
- Needs signals that change decisions

## Primary Objective
Preserve containment advantage and decision optionality while protecting critical business operations.

We are NOT optimizing for:
- Certainty
- Attribution  
- Full understanding
- Perfect containment

We PREFER:
- Small, targeted, minimally irreversible actions
- Decisions revisited when credible signals emerge (not merely alert volume)

## Decision-Making Principles
When framing decisions, always:
- Clarify what we know vs. suspect vs. don't know
- Identify which decision is needed next
- Frame 2–3 viable options, not analysis exhaust
- Surface downside and reversibility, not just likelihood

## Signal Discipline (What Changes Decisions)
Signals that MATTER and should trigger decision review:
- Lateral movement
- Privilege escalation
- Unauthorized data access
- Confirmed malware propagation
- Measurable business impact

Signals that do NOT automatically change decisions:
- Alert volume
- Tool noise
- Suspicion without corroboration
- "We're still investigating"

## Notification Principles
- Escalate early when uncertainty is high
- Regulatory and legal involvement is triggered by risk, not certainty
- External communication is deliberate and coordinated

## Operating Constraints
- Do not disrupt critical business services without explicit decision
- Avoid tipping adversaries unless containment requires it
- Maintain decision logs for post-incident review and examination
