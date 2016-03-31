/* dtd_parse.h
* an XML dissector for Wireshark
* header file to declare functions defined in lexer and used in parser,
* or vice versa
*
* Copyright 2004, Luis E. Garcia Ontanon <luis@ontanon.org>
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
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
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

extern void DtdParse(void*,int,dtd_token_data_t*,dtd_build_data_t*);
extern void *DtdParseAlloc(void *(*)(gsize));
extern void DtdParseFree( void*, void(*)(void*) );
extern void DtdParseTrace(FILE *TraceFILE, char *zTracePrompt);
