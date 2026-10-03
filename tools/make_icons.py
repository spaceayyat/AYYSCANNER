#!/usr/bin/env python3
"""Regenerate the launcher icons from the logo geometry (development tool; needs Pillow).

    pip install pillow && python tools/make_icons.py

Writes ayyscanner/assets/ayyscanner.png (Linux), ayyscanner.ico (Windows) and ayyscanner.icns (macOS).
The mark is the same one as assets/logo.svg (64x64 viewBox), placed on a dark rounded tile so it stays
legible at 16 px on both light and dark desktops. The generated files are committed, so users never need Pillow.
"""

from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).resolve().parent.parent / "ayyscanner" / "assets"
RED, TILE = (215, 38, 61, 255), (12, 15, 19, 255)
S = 2048  # master size, drawn large and downscaled for clean edges


def master() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, S - 1, S - 1), radius=int(S * 0.22), fill=TILE)
    inner = 0.70  # the mark fills 70% of the tile
    k = S * inner / 64.0
    off = S * (1 - inner) / 2

    def P(x, y):
        return (off + x * k, off + y * k)

    def rect(x0, y0, x1, y1):
        d.rectangle((*P(min(x0, x1), min(y0, y1)), *P(max(x0, x1), max(y0, y1))), fill=RED)

    w = 3  # half of the 6-unit stroke
    # corner brackets: M6 24V6h18 / M40 6h18v18 / M58 40v18H40 / M24 58H6V40 (stroke 6, butt caps, mitre joins)
    rect(6 - w, 6 - w, 6 + w, 24); rect(6 - w, 6 - w, 24, 6 + w)
    rect(40, 6 - w, 58 + w, 6 + w); rect(58 - w, 6 - w, 58 + w, 24)
    rect(58 - w, 40, 58 + w, 58 + w); rect(40, 58 - w, 58 + w, 58 + w)
    rect(6 - w, 58 - w, 24, 58 + w); rect(6 - w, 40, 6 + w, 58 + w)
    d.polygon([P(32, 19), P(45, 32), P(32, 45), P(19, 32)], fill=RED)  # diamond
    t = 2.5  # ticks: stroke 5
    rect(32 - t, 9, 32 + t, 16); rect(32 - t, 48, 32 + t, 55); rect(9, 32 - t, 16, 32 + t); rect(48, 32 - t, 55, 32 + t)
    return img


def main() -> None:
    m = master()
    ASSETS.mkdir(parents=True, exist_ok=True)
    m.resize((256, 256), Image.LANCZOS).save(ASSETS / "ayyscanner.png", optimize=True)
    sizes = [(s, s) for s in (16, 24, 32, 48, 64, 128, 256)]
    m.resize((256, 256), Image.LANCZOS).save(ASSETS / "ayyscanner.ico", sizes=sizes)
    m.resize((1024, 1024), Image.LANCZOS).save(ASSETS / "ayyscanner.icns")
    for name in ("ayyscanner.png", "ayyscanner.ico", "ayyscanner.icns"):
        print(name, (ASSETS / name).stat().st_size, "bytes")


if __name__ == "__main__":
    main()
