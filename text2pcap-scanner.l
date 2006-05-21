/* -*-mode: flex-*- */

%{
    
/********************************************************************************
 *
 * text2pcap-scanner.l
 *
 * Utility to convert an ASCII hexdump into a libpcap-format capture file
 *
 * (c) Copyright 2001 Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id$
 * 
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 * 
 * 
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *******************************************************************************/
    
#include <stdio.h>
#include <stdlib.h>

#include "text2pcap.h"
    
%}

hexdigit [0-9A-Fa-f]
directive #TEXT2PCAP.*
comment #[^W].*
byte [0-9A-Fa-f][0-9A-Fa-f][ \t]
byte_eol [0-9A-Fa-f][0-9A-Fa-f]\n
offset [0-9A-Fa-f]+[: \t]
offset_eol [0-9A-Fa-f]+\n
text [^ \n\t]+
mailfwd >
eol \r?\n\r?

%%

{byte}            { parse_token(T_BYTE, yytext); }
{byte_eol}        { parse_token(T_BYTE, yytext); parse_token(T_EOL, NULL); }
{offset}          { parse_token(T_OFFSET, yytext); }
{offset_eol}      { parse_token(T_OFFSET, yytext); parse_token(T_EOL, NULL); }
{mailfwd}{offset} { parse_token(T_OFFSET, yytext+1); }
{eol}             { parse_token(T_EOL, NULL); }
[ \t]             ; /* ignore whitespace */
{directive}       { parse_token(T_DIRECTIVE, yytext); }
{comment}         ; /* ignore comments */
{text}            { parse_token(T_TEXT, yytext); }

%%

int yywrap()
{
    return 1;
}
