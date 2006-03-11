%option noyywrap
%option nounput 
%option never-interactive
%option prefix="Mate"

%{

	/* mate_parser.l
	* lexical analyzer for MATE configuration files
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
	
#include "mate.h"	
#include "mate_grammar.h"
	
	void MateParser(void*,int, gchar*, mate_config* matecfg);
	void *MateParserAlloc(void *(*)(gulong));
	void MateParserFree( void*, void(*)(void*) );
	void MateParseTrace(FILE*,char*);
	
#define MAX_INCLUDE_DEPTH 10
	static YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
	static int include_stack_ptr = 0;
	
	static void* pParser;
	static mate_config_frame* current_frame;
	
	static mate_config* mc;
	
#define MATE_PARSE(token_type) MateParser(pParser, (token_type), g_strdup(yytext), mc );

%}

pdu_kw				Pdu
gop_kw				Gop
gog_kw				Gog
transform_kw		Transform
match_kw			Match
always_kw			Always
strict_kw			Strict
every_kw			Every
loose_kw			Loose
replace_kw			Replace
insert_kw			Insert
gop_tree_kw			GopTree
member_kw			Member
on_kw				On
start_kw			Start
stop_kw				Stop
extra_kw			Extra
show_tree_kw		ShowTree
show_times_kw		ShowTimes
expiration_kw		Expiration
idle_timeout_kw		IdleTimeout
lifetime_kw			Lifetime
no_tree_kw			NoTree
pdu_tree_kw			PduTree
frame_tree_kw		FrameTree
basic_tree_kw		BasicTree
true_kw				[Tt][Rr][Uu][Ee]
false_kw			[Ff][Aa][Ll][Ss][Ee]
proto_kw			Proto
payload_kw          Payload
transport_kw		Transport
criteria_kw			Criteria
accept_kw			Accept
reject_kw			Reject
extract_kw			Extract
from_kw				From
drop_unassigned_kw  DropUnassigned
discard_pdu_data_kw DiscardPduData
last_pdu_kw			LastPdu
done_kw				Done
filename_kw         Filename
debug_kw            Debug
level_kw            Level
default_kw          Default


open_parens			"("
close_parens		")"
open_brace			"{"
close_brace			"}"
comma				","
semicolon			";"
slash				"/"
pipe				"|"

integer				[0-9]+
floating			([0-9]+\.[0-9]+)
doted_ip			[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?
colonized			[0-9A-Fa-f:]*[:][0-9A-Fa-f:]*

name				[a-z][-\.a-zA-Z0-9_]*
avp_operator		[$^~=<>!]
quote				["]
not_quoted			[^"]*

include			"#include"
filename		[-A-Za-z0-9_/.]+

whitespace		[[:blank:]\r]+
newline			\n

comment			"//"[^\n]*\n

blk_cmnt_start  "/*"
cmnt_char		.
blk_cmnt_stop  "*/"
 
%START OUTSIDE QUOTED INCLUDING COMMENT
%%

{newline}						current_frame->linenum++; 
{whitespace}					;

<OUTSIDE>{include}					BEGIN INCLUDING;

<INCLUDING>{filename}			{
	if ( include_stack_ptr >= MAX_INCLUDE_DEPTH )
		g_error("dtd_preparse: include files nested to deeply");
	
	include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;
	yyin = fopen( yytext, "r" );

	if (!yyin) {
		yy_delete_buffer( YY_CURRENT_BUFFER );
		
		/* coverity[negative_sink] */
		yy_switch_to_buffer(include_stack[--include_stack_ptr] );
		
		if (errno)
			g_string_sprintfa(mc->config_error, "Mate parser: Could not open file: '%s': %s", yytext, strerror(errno) );
		
	} else {
		
		current_frame = g_malloc(sizeof(mate_config_frame));
		current_frame->filename = g_strdup(yytext);
		current_frame->linenum = 1;
		
		g_ptr_array_add(mc->config_stack,current_frame);

		yy_switch_to_buffer(yy_create_buffer( yyin, YY_BUF_SIZE ) );
	}
	
	BEGIN OUTSIDE;
}

<<EOF>>	{	
	/* coverity[check_after_sink] */
	if ( --include_stack_ptr < 0 ) {
		yyterminate();
	} else {
		yy_delete_buffer( YY_CURRENT_BUFFER );
		yy_switch_to_buffer( include_stack[include_stack_ptr] );
		
		g_free(current_frame->filename);
		g_free(current_frame);
		current_frame = g_ptr_array_remove_index(mc->config_stack,mc->config_stack->len-1);
	}
}				

<OUTSIDE>{comment}					;

<OUTSIDE>{blk_cmnt_start}			BEGIN COMMENT;
<COMMENT>{cmnt_char}			;
<COMMENT>{blk_cmnt_stop}		BEGIN OUTSIDE;

<OUTSIDE>{pdu_kw}					MATE_PARSE(TOKEN_PDU_KW);
<OUTSIDE>{gop_kw}					MATE_PARSE(TOKEN_GOP_KW);
<OUTSIDE>{gog_kw}					MATE_PARSE(TOKEN_GOG_KW);
<OUTSIDE>{transform_kw}				MATE_PARSE(TOKEN_TRANSFORM_KW);
<OUTSIDE>{match_kw}					MATE_PARSE(TOKEN_MATCH_KW);
<OUTSIDE>{strict_kw}				MATE_PARSE(TOKEN_STRICT_KW);
<OUTSIDE>{every_kw}					MATE_PARSE(TOKEN_EVERY_KW);
<OUTSIDE>{loose_kw}					MATE_PARSE(TOKEN_LOOSE_KW);
<OUTSIDE>{replace_kw}				MATE_PARSE(TOKEN_REPLACE_KW);
<OUTSIDE>{insert_kw}				MATE_PARSE(TOKEN_INSERT_KW);
<OUTSIDE>{gop_tree_kw}				MATE_PARSE(TOKEN_GOP_TREE_KW);
<OUTSIDE>{member_kw}				MATE_PARSE(TOKEN_MEMBER_KW);
<OUTSIDE>{on_kw}					MATE_PARSE(TOKEN_ON_KW);
<OUTSIDE>{start_kw}					MATE_PARSE(TOKEN_START_KW);
<OUTSIDE>{stop_kw}					MATE_PARSE(TOKEN_STOP_KW);
<OUTSIDE>{extra_kw}					MATE_PARSE(TOKEN_EXTRA_KW);
<OUTSIDE>{show_tree_kw}				MATE_PARSE(TOKEN_SHOW_TREE_KW);
<OUTSIDE>{show_times_kw}			MATE_PARSE(TOKEN_SHOW_TIMES_KW);
<OUTSIDE>{expiration_kw}			MATE_PARSE(TOKEN_EXPIRATION_KW);
<OUTSIDE>{idle_timeout_kw}			MATE_PARSE(TOKEN_IDLE_TIMEOUT_KW);
<OUTSIDE>{lifetime_kw}				MATE_PARSE(TOKEN_LIFETIME_KW);
<OUTSIDE>{no_tree_kw}				MATE_PARSE(TOKEN_NO_TREE_KW);
<OUTSIDE>{pdu_tree_kw}				MATE_PARSE(TOKEN_PDU_TREE_KW);
<OUTSIDE>{frame_tree_kw}			MATE_PARSE(TOKEN_FRAME_TREE_KW);
<OUTSIDE>{basic_tree_kw}			MATE_PARSE(TOKEN_BASIC_TREE_KW);
<OUTSIDE>{true_kw}					MATE_PARSE(TOKEN_TRUE_KW);
<OUTSIDE>{false_kw}					MATE_PARSE(TOKEN_FALSE_KW);
<OUTSIDE>{proto_kw}					MATE_PARSE(TOKEN_PROTO_KW);
<OUTSIDE>{payload_kw}				MATE_PARSE(TOKEN_PAYLOAD_KW);
<OUTSIDE>{transport_kw}				MATE_PARSE(TOKEN_TRANSPORT_KW);
<OUTSIDE>{criteria_kw}				MATE_PARSE(TOKEN_CRITERIA_KW);
<OUTSIDE>{accept_kw}				MATE_PARSE(TOKEN_ACCEPT_KW);
<OUTSIDE>{reject_kw}				MATE_PARSE(TOKEN_REJECT_KW);
<OUTSIDE>{extract_kw}				MATE_PARSE(TOKEN_EXTRACT_KW);
<OUTSIDE>{from_kw}					MATE_PARSE(TOKEN_FROM_KW);
<OUTSIDE>{drop_unassigned_kw}		MATE_PARSE(TOKEN_DROP_UNASSIGNED_KW);
<OUTSIDE>{discard_pdu_data_kw}		MATE_PARSE(TOKEN_DISCARD_PDU_DATA_KW);
<OUTSIDE>{last_pdu_kw}				MATE_PARSE(TOKEN_LAST_PDU_KW);
<OUTSIDE>{done_kw}					MATE_PARSE(TOKEN_DONE_KW);
<OUTSIDE>{filename_kw}				MATE_PARSE(TOKEN_FILENAME_KW);
<OUTSIDE>{debug_kw}					MATE_PARSE(TOKEN_DEBUG_KW);
<OUTSIDE>{level_kw}					MATE_PARSE(TOKEN_LEVEL_KW);
<OUTSIDE>{default_kw}				MATE_PARSE(TOKEN_DEFAULT_KW);

<OUTSIDE>{open_parens}				MATE_PARSE(TOKEN_OPEN_PARENS);
<OUTSIDE>{close_parens}				MATE_PARSE(TOKEN_CLOSE_PARENS);
<OUTSIDE>{open_brace}				MATE_PARSE(TOKEN_OPEN_BRACE);
<OUTSIDE>{close_brace}				MATE_PARSE(TOKEN_CLOSE_BRACE);
<OUTSIDE>{comma}					MATE_PARSE(TOKEN_COMMA);
<OUTSIDE>{semicolon}				MATE_PARSE(TOKEN_SEMICOLON);
<OUTSIDE>{slash}					MATE_PARSE(TOKEN_SLASH);
<OUTSIDE>{pipe}						MATE_PARSE(TOKEN_PIPE);

<OUTSIDE>{integer}					MATE_PARSE(TOKEN_INTEGER);
<OUTSIDE>{floating}					MATE_PARSE(TOKEN_FLOATING);
<OUTSIDE>{doted_ip}					MATE_PARSE(TOKEN_DOTED_IP);
<OUTSIDE>{colonized}				MATE_PARSE(TOKEN_COLONIZED);
<OUTSIDE>{name}						MATE_PARSE(TOKEN_NAME);
<OUTSIDE>{avp_operator}				MATE_PARSE(TOKEN_AVP_OPERATOR);


<OUTSIDE>{quote}					BEGIN QUOTED;
<QUOTED>{not_quoted}			MATE_PARSE(TOKEN_QUOTED);
<QUOTED>{quote}					BEGIN OUTSIDE;

%%

extern gboolean mate_load_config(const gchar* filename, mate_config* matecfg) {
	volatile gboolean state = TRUE;
	mc = matecfg;

	yyin = fopen(filename,"r");
	
	if (!yyin) {
		g_string_sprintfa(mc->config_error,"Mate parser: Could not open file: '%s', error: %s", filename, strerror(errno) );
		return FALSE;
	}
	
	mc->config_stack = g_ptr_array_new();
	
	current_frame = g_malloc(sizeof(mate_config_frame));
	current_frame->filename = g_strdup(filename);
	current_frame->linenum = 1;
	
	g_ptr_array_add(mc->config_stack,current_frame);

	pParser = MateParserAlloc(g_malloc);
	
	/* MateParserTrace(stdout,""); */
	
	TRY {
		BEGIN OUTSIDE;

		yylex();

		MateParser(pParser, 0, NULL,mc);

		yyrestart(NULL);
	
		MateParserFree(pParser, g_free );
	
		g_free(current_frame->filename);
		g_free(current_frame);
	
		g_ptr_array_free(mc->config_stack,FALSE);
	} CATCH(MateConfigError) {
		state = FALSE;
	} CATCH_ALL {
		state = FALSE;		
		g_string_sprintfa(mc->config_error,"An unexpected error occurred");
	}
	ENDTRY;
	
	return state;
}
