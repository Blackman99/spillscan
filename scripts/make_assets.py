#!/usr/bin/env python3
"""Generate logo-512, og.png, social-preview.png, demo.gif."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import math

ROOT = Path("/workspace/oss-factory/spillscan/site")
OLIVE = (47, 58, 40)
CREAM = (196, 184, 150)
AMBER = (232, 160, 32)
INK = (26, 31, 22)
PHOS = (139, 154, 74)
CONTAM = (196, 92, 42)
BAKE = (90, 64, 48)

TEKO = "/usr/share/fonts/truetype/sand-box/google/Teko/Teko-VariableFont_wght.ttf"
MONO = "/usr/share/fonts/truetype/sand-box/google/JetBrains Mono/JetBrainsMono-VariableFont_wght.ttf"
SANS = "/usr/share/fonts/truetype/sand-box/google/Nunito Sans/NunitoSans-VariableFont_YTLC,opsz,wdth,wght.ttf"

def font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()

def draw_meter(draw, cx, cy, r, needle_deg=-30, face=PHOS, label=True):
    # outer
    draw.ellipse([cx-r, cy-r, cx+r, cy+r], fill=OLIVE, outline=INK, width=max(2, r//40))
    draw.ellipse([cx-int(r*0.88), cy-int(r*0.88), cx+int(r*0.88), cy+int(r*0.88)], fill=BAKE)
    draw.ellipse([cx-int(r*0.78), cy-int(r*0.78), cx+int(r*0.78), cy+int(r*0.78)], fill=face)
    draw.ellipse([cx-int(r*0.72), cy-int(r*0.72), cx+int(r*0.72), cy+int(r*0.72)], fill=CREAM)
    # ticks
    for ang in range(-90, 91, 30):
        rad = math.radians(ang - 90)  # 0 at top... wait use standard
    for i, ang in enumerate(range(-120, 121, 30)):
        rad = math.radians(ang - 90)
        x1 = cx + int((r*0.55) * math.cos(rad))
        y1 = cy + int((r*0.55) * math.sin(rad))
        x2 = cx + int((r*0.68) * math.cos(rad))
        y2 = cy + int((r*0.68) * math.sin(rad))
        draw.line([x1, y1, x2, y2], fill=INK, width=max(2, r//50))
    # needle: 0 deg = up, positive clockwise-ish via our mapping
    # Map needle_deg: -90 left ... 0 up ... +90 right of arc used by CSS rotate from up
    rad = math.radians(needle_deg - 90)
    nx = cx + int((r*0.58) * math.cos(rad))
    ny = cy + int((r*0.58) * math.sin(rad))
    draw.line([cx, cy, nx, ny], fill=AMBER, width=max(3, r//25))
    hub = max(4, r//20)
    draw.ellipse([cx-hub, cy-hub, cx+hub, cy+hub], fill=INK)

def logo512():
    s = 512
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    # panel
    d.rounded_rectangle([40, 48, 472, 464], radius=16, fill=OLIVE, outline=INK, width=4)
    # stripe
    d.rectangle([40, 48, 472, 68], fill=AMBER)
    for x in range(60, 460, 32):
        d.rectangle([x, 48, x+16, 68], fill=INK)
    draw_meter(d, 256, 250, 160, needle_deg=25, face=PHOS)
    f = font(TEKO, 42)
    d.text((256, 430), "SPILLSCAN", fill=CREAM, font=f, anchor="mm")
    im.save(ROOT / "logo-512.png")
    # also copy as logo for avatar convenience
    im.save(ROOT.parent / "logo-512.png")
    print("logo-512.png")

def og(w=1200, h=630, path="og.png"):
    im = Image.new("RGB", (w, h), OLIVE)
    d = ImageDraw.Draw(im)
    # engraved lines
    for y in range(0, h, 4):
        d.line([(0, y), (w, y)], fill=(42, 52, 36))
    # stripe top
    d.rectangle([0, 0, w, 18], fill=AMBER)
    for x in range(0, w, 36):
        d.rectangle([x, 0, x+18, 18], fill=INK)
    draw_meter(d, 280, 330, 200, needle_deg=55, face=CONTAM)
    f1 = font(TEKO, 72)
    f2 = font(TEKO, 36)
    f3 = font(SANS, 28)
    d.text((560, 180), "SPILLSCAN", fill=CREAM, font=f1, anchor="lm")
    d.text((560, 250), "CONTAMINATION SURVEY", fill=AMBER, font=f2, anchor="lm")
    d.text((560, 330), "Secrets in agent transcripts.", fill=CREAM, font=f3, anchor="lm")
    d.text((560, 380), "One command. Scan. Scrub. Backup.", fill=PHOS, font=f3, anchor="lm")
    # readout boxes
    for i, (lab, val, col) in enumerate([("CPS", "84", CONTAM), ("CONTAM", "7", CONTAM), ("FILES", "3", CREAM)]):
        x0 = 560 + i * 160
        d.rectangle([x0, 440, x0+140, 540], fill=INK, outline=CREAM)
        d.text((x0+70, 465), lab, fill=PHOS, font=font(TEKO, 22), anchor="mm")
        d.text((x0+70, 510), val, fill=col, font=font(TEKO, 48), anchor="mm")
    im.save(ROOT / path)
    print(path)

def demo_gif():
    frames = []
    w, h = 720, 400
    mono = font(MONO, 18)
    lines_seq = [
        ["$ spillscan scan"],
        ["$ spillscan scan", "SPILLSCAN  files=3 findings=0  …"],
        ["$ spillscan scan", "SPILLSCAN  files=3 findings=0  …", "SURVEYING claude-code …"],
        ["$ spillscan scan", "SPILLSCAN  files=3 findings=7  2026-10-14T02:04:00Z",
         "RULE          PREVIEW    AGENT",
         "aws-akia      AKIA…MPLE  claude-code",
         "github-pat    ghp_…ABCD  claude-code"],
        ["$ spillscan scan", "SPILLSCAN  files=3 findings=7  2026-10-14T02:04:00Z",
         "RULE          PREVIEW    AGENT",
         "aws-akia      AKIA…MPLE  claude-code",
         "github-pat    ghp_…ABCD  claude-code",
         "openai-sk     sk-p…2345  claude-code",
         "anthropic-sk  sk-a…ABCD  claude-code",
         "stripe-live   sk_l…wxyz  codex",
         "",
         "Rotate, then: spillscan redact --write"],
        ["$ spillscan redact --write",
         "REDACT (write)  files=3 replaced=7",
         "  bak …/session.jsonl.bak",
         "",
         "$ spillscan scan",
         "CLEAN — no secret-shaped contamination."],
    ]
    for lines in lines_seq:
        im = Image.new("RGB", (w, h), INK)
        d = ImageDraw.Draw(im)
        d.rectangle([0, 0, w, 28], fill=OLIVE)
        d.text((12, 6), "spillscan — contamination survey", fill=CREAM, font=font(TEKO, 22))
        y = 48
        for ln in lines:
            col = PHOS if ln.startswith("$") else CREAM
            if "AKIA" in ln or "ghp_" in ln or "sk-" in ln or "findings=7" in ln:
                col = CONTAM
            if "CLEAN" in ln:
                col = PHOS
            d.text((16, y), ln, fill=col, font=mono)
            y += 28
        frames.append(im)
    # hold last
    frames.append(frames[-1])
    frames[0].save(
        ROOT / "demo.gif",
        save_all=True,
        append_images=frames[1:],
        duration=[800, 700, 700, 900, 1600, 2000, 1200],
        loop=0,
    )
    print("demo.gif")

if __name__ == "__main__":
    logo512()
    og(1200, 630, "og.png")
    og(1280, 640, "social-preview.png")
    # also alias og-image.png for consistency with other projects
    og(1200, 630, "og-image.png")
    demo_gif()
