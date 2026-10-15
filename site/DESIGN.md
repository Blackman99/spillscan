# spillscan design language (v2, 2026-10-15)

**Reference object:** a hazmat spill-response kit — the grey quilted polypropylene absorbent pad thrown over a leak, the white absorbent sock (boom) that rings a spill, and fluorescent leak-tracer dye on a hazard-yellow spill-kit bin.

**Concept:** an absorbent pad laid over a real agent transcript; fake secrets bleed fluorescent dye through it, and wiping, tapping or scrolling soaks each one into the pad as `[REDACTED:<rule>]`, which is exactly what `spillscan redact` writes.

| Axis | Choice |
|---|---|
| Base | Hazard spill-kit yellow `#f2d20c` (saturated, light-mid) |
| Palette | `#f2d20c` hazard yellow · `#14130f` drum black · `#e3e6ea` pad grey · `#c3c8cf` dimple/quilt grey · `#e4007c` leak-tracer dye (live secret) · `#b79bc6` soaked dye |
| Fonts | **Bowlby One** (display) + **Instrument Sans** 400/600 (body) + **Sono** 400/600 (transcript, commands), self-hosted |
| Texture | Polypropylene pad: 12px dimple dot lattice + diagonal quilting + dashed stitched hem; sock boom = knit stitch dashes |
| Render | Liquid stains: SVG blobs warped by `feTurbulence` + `feDisplacementMap`, `mix-blend-mode: multiply` into the pad weave |
| Layout | Huge h1 whose "leaking" drips onto a full-bleed, tilted (−1.1°) pad that IS the hero demo; sections separated by a wavy absorbent-sock boom; procedure = Contain / Survey / Rotate / Absorb with outline numerals |
| Motion | Dye blooms from each token (2.6s expo-out), drips scale down from letters; soak = char-scramble to `[REDACTED:rule]` + stain shrinks and turns lavender; pointer gets a scrap of pad (blotter). `prefers-reduced-motion` shows final bloom, no blotter |
| Logo | Tilted quilted pad square with a magenta drop and lavender soak halo, black redaction bar; transparent BG |
