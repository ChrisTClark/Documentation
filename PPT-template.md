I've attached our company PowerPoint template. Using python-pptx, inspect it
and produce a reference sheet:

1. Every slide layout: index, exact name, and for each one its placeholders
   (idx, type, name, position and size).
2. The theme colors - all twelve slots (dk1, lt1, dk2, lt2, accent1-6,
   hlink, folHlink) as hex. Read them from ppt/theme/theme1.xml.
3. Theme fonts - major (headings) and minor (body).
4. Slide dimensions (13.333x7.5in widescreen, or 10x7.5in 4:3).
5. Any slides already in the file - are they examples to delete, or
   content to keep?

Output as a markdown reference sheet. Flag anything unusual: custom layouts,
non-standard placeholder arrangements, or purpose-built layouts (comparison
slides, quad charts, section dividers).
