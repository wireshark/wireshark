#!/usr/bin/env python3
# generate_json_translations.py — Extract translatable strings from JSON
# data files for Qt lupdate.  Generates a C++ file with QT_TRANSLATE_NOOP()
# markers.
#
# Usage:
#   python3 generate_json_translations.py <input.json> <output.cpp> <context> \
#       --extract <array_key:field1,field2,...> [--extract ...]
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import json
import os


def parse_extract_spec(spec):
    """Parse an 'array_key:field1,field2,...' string into (key, [fields])."""
    if ":" not in spec:
        raise argparse.ArgumentTypeError(
            f"Invalid extract spec '{spec}' — expected array_key:field1,field2,..."
        )
    array_key, fields_csv = spec.split(":", 1)
    fields = [f.strip() for f in fields_csv.split(",") if f.strip()]
    if not fields:
        raise argparse.ArgumentTypeError(
            f"No fields specified in extract spec '{spec}'"
        )
    return array_key, fields


def extract_strings(json_path, extract_specs):
    """Return deduplicated translatable strings preserving first-seen order."""
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    seen = set()
    strings = []
    for array_key, fields in extract_specs:
        for item in data.get(array_key, []):
            for field in fields:
                value = item.get(field, "")
                if value and value not in seen:
                    seen.add(value)
                    strings.append(value)
    return strings


def generate_cpp(strings, context_class, input_basename):
    """Return C++ source with QT_TRANSLATE_NOOP() for each string.

    The code is wrapped in #if 0 so it compiles to nothing — lupdate
    still extracts the strings regardless of preprocessor state.
    """
    lines = [
        f"// Auto-generated from {input_basename} \u2014 do not edit manually.",
        "// This file exists only so lupdate can extract strings for translation.",
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
    parser = argparse.ArgumentParser(
        description="Extract translatable strings from a JSON data file "
        "and generate a C++ file with QT_TRANSLATE_NOOP() markers."
    )
    parser.add_argument("input", help="Path to the input JSON file")
    parser.add_argument("output", help="Path to the output C++ file")
    parser.add_argument("context", help="Qt translation context class name")
    parser.add_argument(
        "--extract",
        action="append",
        required=True,
        metavar="ARRAY:FIELDS",
        help="Extraction spec in the form array_key:field1,field2,... "
        "(may be repeated)",
    )

    args = parser.parse_args()

    extract_specs = []
    for spec in args.extract:
        extract_specs.append(parse_extract_spec(spec))

    strings = extract_strings(args.input, extract_specs)
    cpp = generate_cpp(strings, args.context, os.path.basename(args.input))

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(cpp)

    print(f"Generated {len(strings)} translatable strings in {args.output}")


if __name__ == "__main__":
    main()
