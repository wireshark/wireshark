#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Helpers for dissection suites that read merged multi-section captures.

A merged capture holds several builders' output, one pcapng section each.
A span is a section's (first, last) capture frame numbers; these helpers key
rows by the builder's own frame numbers, from 1.  Fields listed in `links`
hold frame numbers and are converted too, in rows and in filter comparisons.
'''

import copy
import re

#: Frame-number fields of the NVMe-MI and TCG Storage captures.
FRAME_LINKS = ('frame.number', 'mctp.fragment', 'nvme-mi.response_to', 'nvme-mi.response_in',
               'nvme-mi.prev_no_response', 'nvme-mi.replay_of', 'nvme-mi.replay_request',
               'nvme-mi.endpoint.mi_version.source_frame')


def column(table, field):
    '''{frame: value} for the frames where `field` is present.'''
    return {n: row[field] for n, row in table.items() if row[field] != ''}


def pick(row, *fields):
    '''The values of `fields` in `row`, as a tuple.'''
    return tuple(row[f] for f in fields)


def field(element, name):
    '''The first `name` field element under a PDML `element`; it must exist.'''
    found = element.find(f".//field[@name='{name}']")
    assert found is not None, name
    return found


def frame_in(span, n):
    '''The capture frame number of a section's frame n.'''
    return span[0] + n - 1


def frames_in(span, first=1, last=None):
    '''A display filter for a section's frames first..last.'''
    last = span[1] - span[0] + 1 if last is None else last
    return f'frame.number >= {frame_in(span, first)} && frame.number <= {frame_in(span, last)}'


def _relative(rows, span, links):
    first, last = span

    def relative(row):
        if not isinstance(row, dict):
            return row
        return {**row, **{f: ','.join(str(int(v) - first + 1) for v in row[f].split(','))
                          for f in links if row.get(f)}}
    return {n - first + 1: relative(row) for n, row in rows.items() if first <= n <= last}


def section(rows, span, links=()):
    '''A section's rows, keyed from 1 as in its builder; every frame must be present.'''
    rows = _relative(rows, span, links)
    assert sorted(rows) == list(range(1, span[1] - span[0] + 2)), span
    return rows


def pdml_section(pdml, span, links=()):
    '''A Pdml view of one section, its packets keyed from 1 as in its builder.'''
    view = copy.copy(pdml)
    view.packets = _relative(pdml.packets, span, links)
    return view


def to_capture(span, dfilter, links=()):
    '''dfilter with the frame numbers it compares `links` with converted.

    Every comparison operator and set (ranges too) is converted, so a
    relational test cannot silently compare a section number with a
    capture number.
    '''
    if not links:
        return dfilter
    number = r'(?:0[xX][0-9a-fA-F]+|\d+)'
    # The comparison tokens of epan/dfilter/scanner.l.
    operator = (r'(?:===|!==|==|!=|<=|>=|<|>'
                r'|\b(?:eq|ne|gt|ge|lt|le|any_eq|all_ne|all_eq|any_ne)\b)')
    pattern = re.compile(r'\b(?:' + '|'.join(map(re.escape, links)) + r')(?![\w.-])\s*' +
                         r'(?:' + operator + r'\s*' + number + r'\b|(?:not\s+)?in\s*\{[^}]*\})')
    return pattern.sub(lambda m: re.sub(r'(?<!\w)' + number + r'\b',
                                        lambda n: str(frame_in(span, int(n.group(0), 0))),
                                        m.group(0)), dfilter)


def at(span, cases, links=()):
    '''assert_frames_match cases with section frame numbers converted.'''
    for n, _ in cases:
        assert 1 <= n <= span[1] - span[0] + 1, (n, span)
    return [(frame_in(span, n), to_capture(span, expr, links)) for n, expr in cases]


def in_section(tshark_fields, span, links=()):
    '''tshark_fields limited to one section, with `links` in its numbering.'''
    first, last = span

    def to_section(line, sep, columns):
        values = line.split(sep)
        if len(values) != len(columns) or not line.strip():
            return line
        return sep.join(','.join(str(int(v) - first + 1) for v in value.split(','))
                        if link and value else value for link, value in zip(columns, values))

    def run(filename, dfilter=None, fields=('frame.number',), separator=None, **kwargs):
        scope = f'frame.number >= {first} && frame.number <= {last}'
        if dfilter:
            scope += ' && (' + to_capture(span, dfilter, links) + ')'
        out = tshark_fields(filename, scope, fields=fields, separator=separator, **kwargs)
        columns = [field in links for field in fields]
        if any(columns):
            out = '\n'.join(to_section(line, separator or '\t', columns)
                            for line in out.split('\n'))
        return out
    return run
