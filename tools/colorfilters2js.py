#!/usr/bin/env python
#
# Copyright 2022 by Moshe Kaplan
# Based on colorfilter2js.pl by Dirk Jagdmann <doj@cubic.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later


# Python script to convert a Wireshark color scheme to javascript
# code. The javascript function should then be inserted into the
# pdml2html.xsl file.
#
# run this as: python tools/colorfilters2js.py colorfilters


import argparse
import io
import re
import sys

js_prologue = """\
function set_node_color(node, colorname)
{
  if (dojo.isString(node))
    node = dojo.byId(node);
  if (!node) return;
  var fg;
  var bg;
"""

js_color_entry = """\
  {7}if (colorname == '{0}') {{
    bg='#{1:02x}{2:02x}{3:02x}';
    fg='#{4:02x}{5:02x}{6:02x}';
  }}\
"""

js_epilogue = """
  if (fg.length > 0)
    node.style.color = fg;
  if (bg.length > 0)
    node.style.background = bg;
}
"""


def generate_javascript(colorlines):
    output = [js_prologue]
    else_text = ""
    for colorline in colorlines:
        colorvalues = colorline[0], int(colorline[1])//256, int(colorline[2])//256, int(colorline[3])//256, int(colorline[4])//256, int(colorline[5])//256, int(colorline[6])//256, else_text
        output += [js_color_entry.format(*colorvalues)]
        else_text = "else "
    output += [js_epilogue]
    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(description="Convert a Wireshark color scheme to javascript code.")
    parser.add_argument("files", metavar='files', nargs='+', help="paths to colorfiles")
    parsed_args = parser.parse_args()

    COLORLINE_PATTERN = r"\@(.+?)\@.+\[(\d+),(\d+),(\d+)\]\[(\d+),(\d+),(\d+)\]"
    colorlines = []

    # Sample line:
    # @Errors@ct.error@[4626,10023,11822][63479,34695,34695]

    # Read the lines from all files:
    for filename in parsed_args.files:
        with open(filename, encoding='utf-8') as fh:
            file_content = fh.read()
            colorlines += re.findall(COLORLINE_PATTERN, file_content)
    javascript_code = generate_javascript(colorlines)

    stdoutu8 = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    stdoutu8.write(javascript_code)


if __name__ == "__main__":
    main()
