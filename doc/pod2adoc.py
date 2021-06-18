#!/usr/bin/env python3

import os
import re
import sys

from enum import Enum

# To do:
# - Fix COUNT(field)filter man output.

class PodState(Enum):
    PRE = 1
    HEAD = 2
    SYNOPSIS = 3
    ITEM_BODY = 4
    AUTHOR = 5

skip_commands = ('=back', '=begin', '=encoding', '=end', '=over')

man4_files = ('extcap', 'wireshark-filter')

tcpdump_manurls = {
    'pcap': 'https://www.tcpdump.org/manpages/pcap.3pcap.html',
    'pcap-filter': 'https://www.tcpdump.org/manpages/pcap-filter.7.html',
    'tcpdump': 'https://www.tcpdump.org/manpages/tcpdump.1.html',
}

def xlate_markup(podline, inline_nobreak=True):
    # Replace < and > in two steps, here and at the end
    podline = podline.replace('E<lt>', '{lt}')
    podline = podline.replace('E<gt>', '{gt}')
    # TShark escapes quotes
    podline = podline.replace('E<34>', '"')
    # Italic, files, bold, and code
    podline = re.sub(r'[IF]<([^>]+)>', r'__\1__', podline)
    podline = re.sub(r'B<([^>]+)>', r'*\1*', podline)
    podline = re.sub(r'C<([^>]+)>', r'`\1`', podline)
    # AsciiDoctor figures out URL links on its own.
    podline = re.sub(r'L<([^>]+)>', r'\1', podline)
    # S< ... > inserts <span style="white-space: nowrap;"> ... </span>
    # XXX Handle multiline nowraps?
    nobr_re = re.search(r'S<([^>]+)>', podline)
    if nobr_re:
        text = nobr_re.group(1).strip()
        if inline_nobreak:
            if '#' in text:
                text = f'++{text}++'
            # Use .nowrap in paragraphs instead of manarg so that we don't trigger
            # "can't break line" warnings in nroff.
            podline = re.sub(r'S<[^>]+>', f'[.nowrap]#{text}#', podline)
        else:
            podline = re.sub(r'S<([^>]+)>', r'\1', text)
    podline = podline.replace('{lt}', '<')
    podline = podline.replace('{gt}', '>')
    if not podline.endswith('\n'):
        podline += '\n'
    return(podline)

def pod2adoc(podfile):
    if not podfile.endswith('.pod'):
        sys.stderr.write(f"{podfile} doesn't have a .pod extension")
        return
    manpage_name = os.path.basename(podfile).split('.')[-2]
    mansect = 1
    adoc_fname = os.path.join(os.path.dirname(podfile), f'{manpage_name}.adoc')

    if manpage_name in man4_files:
        mansect = 4

    print(f'Processing {manpage_name}')

    state = PodState.PRE

    with open(podfile, 'r') as podf:
        adoc_body = f'''\
= {manpage_name}({mansect})
:doctype: manpage
include::../docbook/attributes.adoc[]
:stylesheet: ws.css
:linkcss:
:copycss: ../docbook/{{stylesheet}}

'''
        linenum = 0
        for podline in podf:
            if state == PodState.AUTHOR:
                author = re.sub(r'\s+', ' ', podline.strip())
                if author == '' or author.isspace():
                    state = PodState.PRE
                adoc_body += f'{author}\n'
                continue

            # Assume that command line synopses start with
            # B<command>
            # S< ... >
            if podline == f'B<{manpage_name}>\n':
                adoc_body += '[manarg]\n'
                state = PodState.SYNOPSIS

            podline = xlate_markup(podline, state != PodState.SYNOPSIS)
            linenum += 1

            if re.search('[BCEFLISXZ]<', podline):
                podline = xlate_markup(f'{podline} {next(podf)}', state != PodState.SYNOPSIS)
                sys.stderr.write(f'{manpage_name}: joined partial markup on line {linenum}\n')
                linenum += 1

            head = re.match('=head([12]) *(.*)', podline)
            if head:
                if state == PodState.ITEM_BODY:
                    adoc_body += '--\n\n'

                adoc_body += f'={"=" * int(head.group(1))} {head.group(2)}\n'
                state = PodState.HEAD
                continue

            # Continued unordered and ordered list items
            item = re.match(r'=item\s*(\*|\d+\.)\s*$', podline)
            if item:
                adoc_body += f'{item.group(1)} '
                continue

            # Inline unordered and ordered list items
            item = re.match(r'=item\s*([-\*]\s+.*|\d+\.\s+.*)\s*$', podline)
            if item:
                adoc_body += f'{item.group(1)}'
                continue

            # Other list items
            item = re.match('=item\s*(.*)\s*', podline)
            if item:
                dl_term = item.group(1)
                # Menu items
                menu = dl_term.split(':')
                if len(menu) > 1 and re.match('[A-Z][a-z]+$', menu[0]):
                    dl_term = f'menu:{menu[0]}[{",".join(menu[1:])}]'

                if state == PodState.ITEM_BODY:
                    adoc_body += '--\n\n'

                adoc_body += f'''\
{dl_term}::
+
--'''
                state = PodState.ITEM_BODY
                continue

            if podline.startswith(skip_commands):
                continue

            if podline.startswith('='):
                sys.stderr.write(f'{manpage_name}: unhandled header on line {linenum}\n')
                sys.exit(1)

            if re.search('[BCEFLISXZ]<', podline):
                sys.stderr.write(f'{manpage_name}: unhandled partial markup on line {linenum}\n')
                sys.stderr.write(podline)
                sys.exit(1)

            # Author / contributor block.
            if podline.startswith(('  Original Author', '  Contributors')):
                if not next(podf).startswith('  --------'):
                    sys.stderr.write(f'{manpage_name}: unexpected author or contributor markup on line {linenum}\n')
                    sys.exit(1)

                linenum += 1
                adoc_body += f'''\
.{podline.strip()}
[%hardbreaks]
'''
                state = PodState.AUTHOR
                continue

            for man_re in re.finditer(r'\b([\w-]+)\(\d\)', podline):
                linkfile = man_re.group(1)
                if os.path.isfile(os.path.join(os.path.dirname(podfile), linkfile + '.pod')):
                    podline = re.sub(fr'\b{linkfile}\(', f'xref:{linkfile}.html[{linkfile}](', podline)
                elif linkfile in tcpdump_manurls:
                    podline = re.sub(fr'\b{linkfile}\(', f'xref:{tcpdump_manurls[linkfile]}[{linkfile}](', podline)

            # Single line manual fixups
            if podline.startswith('*lua_script*__num__:__argument__'):
                podline = re.sub('^\*lua_script\*', '**lua_script**', podline)

            if '(__field__)__filter__*' in podline:
                podline = re.sub(r'^\*([A-Z/]+)(\(__field__\)__filter__)(\*)', r'**\1**', podline)

            if podline.startswith('*FRAMES | BYTES[()__filter__]*'):
                podline = podline.replace('*FRAMES | BYTES[()__filter__]*', '**FRAMES | BYTES**[()__filter__]')

            if state != PodState.PRE:
                adoc_body += podline

        # Clean up our empty lines.
        adoc_body = re.sub('\n\n+', '\n\n', adoc_body)

        # Clean up our item blocks.
        adoc_body = re.sub('\n+--\n\n', '\n--\n\n', adoc_body)

        # Body-wide manual fixups
        adoc_body = adoc_body.replace('[<=Jelly Bean]', '[++<=++Jelly Bean]')


        with open(adoc_fname, 'w') as adocf:
            adocf.write(f'{adoc_body}')

if __name__ == '__main__':
    for podfile in sys.argv[1:]:
        pod2adoc(podfile)
