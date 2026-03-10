#!/usr/bin/env python3
# generate_slide_translations.py — Extract translatable strings from slides.json
# for Qt lupdate. Generates a C++ file with QT_TR_NOOP() markers.
#
# Usage: python3 generate_slide_translations.py <slides.json> <output.cpp> <context>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import json
import sys

TRANSLATABLE_FIELDS = [
    "tag",
    "title",
    "description",
    "description_sub",
    "body_text",
    "button_label",
    "url",
]


def extract_strings(slides_path):
    """Return deduplicated translatable strings preserving first-seen order."""
    with open(slides_path, encoding="utf-8") as f:
        data = json.load(f)

    seen = set()
    strings = []
    for slide in data.get("slides", []):
        for field in TRANSLATABLE_FIELDS:
            value = slide.get(field, "")
            if value and value not in seen:
                seen.add(value)
                strings.append(value)
    return strings


def generate_cpp(strings, context_class):
    """Return C++ source with QT_TRANSLATE_NOOP() for each string.

    The code is wrapped in #if 0 so it compiles to nothing — lupdate
    still extracts the strings regardless of preprocessor state.
    """
    lines = [
        "// Auto-generated from slides.json \u2014 do not edit manually.",
        "// This file exists only so lupdate can extract slide strings for translation.",
        "// The #if 0 block is intentional: lupdate scans the source text directly",
        "// and does not require the code to be compilable.",
        "#if 0",
        "#include <QCoreApplication>",
    ]
    for s in strings:
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'QT_TRANSLATE_NOOP("{context_class}", "{escaped}")')
    lines.append("#endif")
    lines.append("")
    return "\n".join(lines)


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <slides.json> <output.cpp> <context>",
              file=sys.stderr)
        sys.exit(1)

    slides_path, output_path, context = sys.argv[1], sys.argv[2], sys.argv[3]
    strings = extract_strings(slides_path)
    cpp = generate_cpp(strings, context)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(cpp)

    print(f"Generated {len(strings)} translatable strings in {output_path}")


if __name__ == "__main__":
    main()
