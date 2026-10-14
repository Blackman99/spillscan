# spillscan design language

**Reference object:** Cold-war hand-held Geiger contamination survey meter — analog needle dial, bakelite handle, yellow/black accent stripe.

**Metaphor:** spilled secrets = contamination in the transcript; scan = survey sweep; redact = decontaminate.

## Axes (registered in `/workspace/oss-factory/design/registry.md`)

| Axis | Choice |
|---|---|
| Base | Olive drab instrument panel `#2f3a28` |
| Palette | `#2f3a28` olive · `#c4b896` dial cream · `#e8a020` needle amber · `#1a1f16` deep olive ink · `#8b9a4a` phosphor green (clean) · `#c45c2a` contamination orange (finding) · `#5a4030` bakelite brown |
| Fonts | **Teko** 500/600/700 (display/dial) + **Nunito Sans** 400/600 (body) + **JetBrains Mono** 400/500 (commands) |
| Texture | Fine engraved panel lines + subtle concentric dial ticks (SVG) |
| Render | Flat instrument SVG + CSS needle rotate |
| Layout | Full-bleed meter as hero; h1 = nameplate "SPILLSCAN — CONTAMINATION SURVEY"; findings as dial readouts; docs as stacked instrument panels |
| Animation | Needle sweeps while scanning sample transcript, spikes + visual click on each finding, settles; phosphor green → contamination orange; `prefers-reduced-motion` → final state |
| Logo | Front view of dial, needle mid-scale, custom tick arc (no ISO radiation trefoil); transparent BG |

## Diff self-check vs every existing project

- vs toolsmoke: not paper/red-ink/typewriter; olive instrument vs warm paper report
- vs agentckpt: not pharmacy pink / pill box
- vs certfan: not near-black generative fan; olive + needle dial
- vs linelore: not white Swiss grid
- vs runbill: not isometric city / concrete
- vs actnode: not highway green MUTCD
- vs drainready: not port fog / containers
- vs postsleuth: not lilac metro map
- vs rackhands: not brass vault
- vs packfence: not navy X-ray CRT (closest "security instrument" — packfence is monitor+scanlines; spillscan is hand-held analog meter, warm olive, needle rotate)
- vs renewhunt: not Solari flip-board / blue-charcoal
- vs wheelripe: not orange cheese wedge
- vs cronlag: not walnut cuckoo clock (closest "dial" — cronlag is wood + polar day rings; spillscan is olive metal panel + single survey needle)

Hex/fonts unused before registration. No SaaS 3-column cards, gradient glow, glassmorphism, left-copy/right-card.
