# Ideal State and State Management

Miessler’s core idea is powerful and, importantly, **you can implement most of it with browser Claude even without Claude Code**.

The simplest way to say it is:

> **Don’t make Claude remember your work. Make the state of your work explicit.**

Miessler increasingly frames AI work as **state management**: understand the *current state*, articulate the *ideal state*, then use AI to close the gap.

His newer **Ideal State Artifact** idea goes further: instead of scattering requirements across prompts, plans, specs, and conversations, maintain an explicit artifact describing what “done” looks like. Those criteria then become the basis for verification.

---

## The Mental Model

Think of Claude this way:

> **Claude's memory = cache**  
> **Your artifacts/documents = source of truth**

Chats are disposable.

If you have a brilliant 90-minute conversation with Claude and the important decisions exist **only inside that conversation**, you've built fragile state.

Instead, the conversation should continuously produce or update things like:

- What we know
- What we've decided
- What we're trying to accomplish
- What remains uncertain
- What “good” looks like

Miessler's own PAI architecture uses persistent files specifically because conversations are ephemeral; **structured work state survives across sessions**.

---

# My Recommendation for Your Setup

Don't try to replicate Miessler's elaborate Claude Code PAI system. You don't have the filesystem integration that makes that architecture elegant.

Build a **PAI-lite for Claude browser**:

- **Project Instructions** → how Claude works
- **Current State** → where things stand
- **Ideal State** → what you're trying to make true
- **Knowledge** → durable things you've learned
- **Decisions** → choices + rationale
- **Open Questions** → unresolved uncertainty
- **Artifacts** → actual work products
- **Chats** → disposable reasoning sessions

That is enough.

And I'd make **`IDEAL_STATE.md`** the center of gravity, not `MEMORY.md`.

That gets to Miessler's deeper argument:

> **The scarce capability isn't getting the AI to remember more. It's getting humans to articulate clearly enough what they actually want.**

---

# Example: Ideal State for an Executive Presentation

## Ideal State

After reading this presentation, an executive who knows nothing about the opportunity understands within five minutes:

- Who the customer is
- What consequential problem they have
- Why it matters now
- Why Owl is positioned to help
- What we know versus infer
- What we don't know
- The specific decision or action we're recommending

No slide exists merely to provide background.

**Every slide advances the argument.**

Before creating the deck, translate this ideal state into criteria you can use to evaluate the finished presentation.

---

# Example: Ideal State for a Business Development Opportunity

## Intent

Determine whether **Program X** deserves concentrated BD effort during the next **12–24 months**.

## Ideal State

At completion:

- Customer and decision authority are known
- Mission problem is clearly understood
- Funding source is identified
- Acquisition vehicle/path is understood
- Program timing is known
- CDS requirement is supported by evidence
- Existing Owl adjacency is understood
- Competition/incumbency is understood
- Product fit is separated from required engineering
- Key relationships are identified
- Major assumptions are explicit
- Top information gaps are prioritized
- Recommended next action is clear
- A kill/deprioritize threshold exists

---

# Example: Ideal State for an AI-Enabled BD Team

## Ideal State

Our BD team consistently spends human attention on **judgment, relationships, strategy, and persuasion**—not repetitive synthesis and information manipulation.

## Criteria

- Meeting preparation requires minutes rather than hours
- Important information from QBRs can be synthesized across quarters
- Account knowledge isn't trapped in individual heads
- Initial proposal structure doesn't start from a blank page
- Opportunity research has a repeatable method
- Technical material can be rapidly translated into BD-level understanding
- Leadership presentations follow consistent Owl branding
- Evidence and inference remain distinguishable
- Sensitive information stays within approved environments
- Reusable workflows exist for recurring work
