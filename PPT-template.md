Attached is Kickoff_Template.pptx again.

From the earlier inspection, this file has TWO slide masters:
- masters[0] -> theme1, generic Office (Calibri, blue/orange) - used by all
  the content slides
- masters[1] -> theme2, Owl branded (navy/red/teal, IBM Plex Sans Condensed /
  Red Hat Display) - used only by the title slide

I want all future decks built on the BRANDED master. Two deliverables:

1. VERIFY, THEN BUILD A TEST DECK
   - First, print both masters with their layout names so we confirm which
     index is actually branded. Don't take my numbering on faith.
   - Then build a 4-slide test deck: open the template file itself as the
     Presentation object (not a default template), clear the existing slides
     while keeping masters and layouts, and use layouts from the branded
     master only:
       Slide 1 - title slide: "Capability Terrain Review" /
                 subtitle "Test build - branding check"
       Slide 2 - the overview layout, 4 short bullets
       Slide 3 - the two-content / comparison layout, 3 bullets each side
       Slide 4 - a section header / divider
   - Address placeholders by .idx, NEVER by .name - the two-content layout
     has two placeholders both named "Content Placeholder 2".
   - Don't type slide numbers, footers, or dates. The layouts carry those.

2. A COMPRESSED BUILD SPEC - about 15 lines, for me to save into project
   knowledge and reuse. Include: file name, branded master index, slide size,
   the 6-8 layout names I'd actually use and what each is for, and the
   specific traps. Leave out the forensic detail from the full inspection.

If a layout you expect isn't there, or a placeholder doesn't behave, STOP and
tell me rather than substituting something that looks close.
