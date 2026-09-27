#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Create a synthetic JPEG test pattern of the size used by the face fixture."""

from __future__ import annotations

import io
from pathlib import Path

from PIL import Image, ImageDraw


TARGET = 9667
OUTPUT = Path(__file__).resolve().parents[1] / "vectors" / "twic" / "synthetic" / "common" / "test-face.jpg"


def main() -> None:
    image = Image.new("RGB", (274, 364), "#d8e4f2")
    drawing = ImageDraw.Draw(image)
    drawing.rectangle((25, 40, 249, 324), outline="#17324f", width=5)
    drawing.ellipse((75, 110, 199, 250), outline="#17324f", width=5)
    drawing.text((118, 337), "TEST", fill="#17324f")
    for quality in range(25, 96):
        stream = io.BytesIO()
        image.save(stream, "JPEG", quality=quality, optimize=True, subsampling=0)
        encoded = stream.getvalue()
        if len(encoded) <= TARGET - 4:
            break
    else:
        raise RuntimeError("test pattern cannot fit target size")
    # A JPEG comment carries deterministic padding while keeping the image valid.
    padding = TARGET - len(encoded)
    assert 4 <= padding <= 65537
    comment = b"\xff\xfe" + (padding - 2).to_bytes(2, "big") + b"T" * (padding - 4)
    encoded = encoded[:2] + comment + encoded[2:]
    assert len(encoded) == TARGET
    with Image.open(io.BytesIO(encoded)) as check:
        check.load()
        assert check.size == (274, 364)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(encoded)


if __name__ == "__main__":
    main()
