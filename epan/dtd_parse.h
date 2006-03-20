/* dtd_parse.h
* an XML dissector for ethereal 
* header file to declare functions defined in lexer and used in parser,
* or vice versa
*
* Copyright 2004, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
*
* $Id$
*
* Ethereal - Network traffic analyzer
* By Gerald Combs <gerald@ethereal.com>
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
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

extern void DtdParse(void*,int,dtd_token_data_t*,dtd_build_data_t*);
extern void *DtdParseAlloc(void *(*)(gulong));
extern void DtdParseFree( void*, void(*)(void*) );
extern void DtdParseTrace(FILE *TraceFILE, char *zTracePrompt);	
extern int Dtd_Parse_lex(void);
