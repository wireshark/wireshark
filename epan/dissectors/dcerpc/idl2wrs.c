/* idl2wrs.c
 * DCE RPC IDL to Wireshark dissector compiler
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

/*
TODO
   check that every cnf defined type,hffield,rename,... has been referenced
   at least once and if not,   abort with an error

   need to distinguish between NTTIME (absolute time) and relative time

   prune_xxx should only act inside of '[' ']'

   add support for bool8,16,32,64 with tfs strings

   add the remaining array type  (uvarray)

   add code to verify that union tag length is correct
*/
/* List of built in types :
   WERROR	A 32 bit integer holding a DCE/NT status code.

   uint8	A 8 bit integer
   int8

   uint16	A 16 bit integer
   int16

   uint32	A 32 bit integer
   int32

   uint64	A 64 bit integer

   udlong	A 64 bit integer aligned on 4 byte boundary
   dlong

   time_t	A 32 bit integer holding a unix style time_t

   NTTIME_hyper A 64 bit integer representing a NTTIME
   NTTIME_1sec

   unistr		A conformant and varying unicode string

   ascstr		A conformant and varying ascii string


   SID			A SID structure.

   uuid_t	A 16 byte FT_GUID blob.
   GUID


   policy_handle
   bool8
   uuid_t
   policy_handle
   NTTIME
*/

/* All field dissectors that call a normal type
   (i.e. not a pointer, not an array)
   has a local variable  guint param declared which is passed on to the
   type dissector.
   The default value is 0 but the PARAM_VALUE conformance tag can be used to
   change it.
   This is only meaningful if the called type dissector actually does anything
   with this parameter.
*/

#define _GNU_SOURCE

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#undef IDL2WRS_DEBUG

#define DISSECTORNAME_MAXLEN 256

#define BASE_BUFFER_SIZE 256

static FILE *tfh, *eth_code, *eth_hdr, *eth_hf, *eth_hfarr, *eth_ett, *eth_ettarr, *eth_ft, *eth_handoff;
static char *uuid=NULL;
static char *version=NULL;
static const char *pointer_default=NULL;
static char *ifname=NULL;
static char hf_status[BASE_BUFFER_SIZE];
static int lineno,linepos;
static char line[4 * BASE_BUFFER_SIZE];

static void FPRINTF(FILE *fh, const char *format, ...)
{
	va_list args;

#ifdef IDL2WRS_DEBUG
	va_start(args, format);
	vfprintf (stderr, format, args);
	va_end(args);
#endif
	if (fh) {
		va_start(args, format);
		vfprintf (fh, format, args);
		va_end(args);
	}
}

typedef struct _pointer_item_t {
	struct _pointer_item_t *next;
	const char *type;
} pointer_item_t;

#define BI_CASE			0x00000001
#define BI_CASE_DEFAULT		0x00000002
#define BI_IN			0x00000004
#define BI_OUT			0x00000008
#define BI_SIZE_IS		0x00000010
#define BI_LENGTH_IS		0x00000020
#define BI_POINTER		0x00000040
#define BI_BITMAP8		0x00000100
#define BI_BITMAP32		0x00000200
#define BI_SWITCH_TYPE		0x00000400
typedef struct _bracket_item_t {
	unsigned int flags;
	const char *case_name;
	pointer_item_t *pointer_list;
	int union_tag_size;
} bracket_item_t;

typedef struct _no_emit_item_t {
	struct _no_emit_item_t *next;
	char *name;
} no_emit_item_t;
static no_emit_item_t *no_emit_list=NULL;

typedef struct _hf_rename_item_t {
	struct _hf_rename_item_t *next;
	int refcount;	/* number of times this rename has been referenced */
	char *old_name;
	char *new_name;
} hf_rename_item_t;
static hf_rename_item_t *hf_rename_list=NULL;

typedef struct _enum_list_t {
	struct _enum_list_t *next;
	char *name;
	int val;
} enum_list_t;

typedef struct _token_item_t {
	struct _token_item_t *next;
	char *str;
} token_item_t;
static token_item_t *token_list=NULL;
static token_item_t *last_token_item=NULL;

typedef struct _type_item_t {
	struct _type_item_t *next;
	char *name;
	char *dissector;
	char *ft_type;
	char *base_type;
	char *mask;
	char *vals;
	int alignment;
} type_item_t;
static type_item_t *type_list=NULL;

typedef struct _union_tag_size_item_t {
	struct _union_tag_size_item_t *next;
	char *name;
	int size;
} union_tag_size_item_t;
static union_tag_size_item_t *union_tag_size_list=NULL;

typedef struct _hf_field_item_t {
	struct _hf_field_item_t *next;
	char *name;
	char *ft_type;
} hf_field_item_t;
static hf_field_item_t *hf_field_list=NULL;

typedef struct _dissector_param_value_t {
	struct _dissector_param_value_t *next;
	char *name;
	char *value;
} dissector_param_value_t;
static dissector_param_value_t *dissector_param_list=NULL;

static type_item_t *find_type(char *name);
static int Exit(int code);

static void
register_dissector_param_value(const char *name, const char *value)
{
	dissector_param_value_t *dpv;
	dpv=g_new0(dissector_param_value_t, 1);
	if (!dpv) {
		FPRINTF(stderr, "Can't allocate memory. Exit.\n");
		exit(10);
	}
	dpv->next=dissector_param_list;
	dissector_param_list=dpv;
	dpv->name=g_strdup(name);
	dpv->value=g_strdup(value);
}

static const char *
find_dissector_param_value(char *name)
{
	dissector_param_value_t *dpv;
	for(dpv=dissector_param_list;dpv;dpv=dpv->next){
		if(!g_strcmp0(name,dpv->name)){
			return dpv->value;
		}
	}
	return "0";
}

static pointer_item_t *
prepend_pointer_list(pointer_item_t *ptrs, int num_pointers)
{
	pointer_item_t *pi;

	pi=ptrs;
	while(pi){
		if(num_pointers)num_pointers--;
		pi=pi->next;
	}
	if(!pi)pi=ptrs;
	while(num_pointers--){
		pi=g_new0(pointer_item_t, 1);
		if (!pi) {
			FPRINTF(stderr, "Can't allocate memory. Exit.\n");
			exit(10);
		}
		pi->next=ptrs;
		pi->type=pointer_default;
		ptrs=pi;
	}
	ptrs=pi;

	return ptrs;
}

static const char *
ptr_to_define(const char *pointer_type)
{
	if(!g_strcmp0(pointer_type, "unique")){
		return "NDR_POINTER_UNIQUE";
	} else if(!g_strcmp0(pointer_type, "ref")){
		return "NDR_POINTER_REF";
	} else if(!g_strcmp0(pointer_type, "ptr")){
		return "NDR_POINTER_PTR";
	}

	FPRINTF(stderr, "prt_to_define, 	weirdo pointer :%s\n", pointer_type);
	exit(10);
}

static int
get_union_tag_size(char *name)
{
	union_tag_size_item_t *utsi;
	for(utsi=union_tag_size_list;utsi;utsi=utsi->next){
		if(!g_strcmp0(name, utsi->name)){
			return utsi->size;
		}
	}
	FPRINTF(stderr, "ERROR: size of tag for union:%s is not known\n", name);
	FPRINTF(stderr, "  use the UNION_TAG_SIZE directive to specify it in teh conformance file\n");
	exit(10);
}


/* this function will add an entry to the hf_rename list */
static void
register_hf_rename(const char *old_name, const char *new_name)
{
	hf_rename_item_t *new_item;
	new_item=g_new0(hf_rename_item_t, 1);
	if (!new_item) {
		FPRINTF(stderr, "Can't allocate memory. Exit.\n");
		exit(10);
	}
	new_item->next=hf_rename_list;
	hf_rename_list=new_item;
	new_item->refcount=0;
	new_item->old_name=g_strdup(old_name);
	new_item->new_name=g_strdup(new_name);
}

/* this function checks that all hf_rename fields have actually been referenced
   if not	out conformance file is stale
*/
static void
check_hf_rename_refcount(void)
{
	hf_rename_item_t *hri;

	/* dont generate code for renamed hf fields  just return the new name*/
	for(hri=hf_rename_list;hri;hri=hri->next){
		if(!hri->refcount){
			FPRINTF(stderr, "ERROR: the hf_rename field:%s was never referenced. it is likely the conformance file is stale\n", hri->old_name);
			exit(10);
		}
	}
}

static hf_field_item_t *
find_hf_field(char *name)
{
	hf_field_item_t *hfi;

	for(hfi=hf_field_list;hfi;hfi=hfi->next){
		if(!g_strcmp0(hfi->name, name)){
			break;
		}
	}
	if (!hfi) {
		FPRINTF(stderr, "find_hf_field:  unknown hf_field:%s\n",name);
		Exit(10);
	}

	return hfi;
}


/* this function will create the code required for a hf field.
   it MIGHT rename the field so a user MUST use the name returned
   from this function.
   for fields that are to be renamed  no code is generated
*/
static const char *
register_hf_field(const char *hf_name, const char *title, const char *filter_name, const char *ft_type, const char *base_type, const char *valsstring, const char *mask, const char *blurb)
{
	hf_field_item_t *hfi;
	hf_rename_item_t *hri;

	/* dont generate code for renamed hf fields  just return the new name*/
	for(hri=hf_rename_list;hri;hri=hri->next){
		if(!strncmp(hf_name, hri->old_name, strlen(hf_name))){
			hfi=find_hf_field(hri->new_name);
			if(g_strcmp0(ft_type, hfi->ft_type)){
				FPRINTF(stderr, "register_hf_field:  hf_fields %s and %s have different types %s %s\n",hf_name,hfi->name,ft_type,hfi->ft_type);
				Exit(10);
			}
			hri->refcount++;
			return hri->new_name;
		}
	}

	hfi=g_new0(hf_field_item_t, 1);
	if (!hfi) {
		FPRINTF(stderr, "Can't allocate memory. Exit.\n");
		exit(10);
	}
	hfi->next=hf_field_list;
	hf_field_list=hfi;
	hfi->name=g_strdup(hf_name);
	hfi->ft_type=g_strdup(ft_type);

	FPRINTF(eth_hf, "static int %s = -1;\n", hf_name);
	FPRINTF(eth_hfarr, "		{ &%s,\n", hf_name);
	FPRINTF(eth_hfarr, "		  { \"%s\", \"%s\", %s, %s,\n", title, filter_name, ft_type, base_type);
	FPRINTF(eth_hfarr, "		  %s, %s,\n", valsstring, mask);
	if (strlen(blurb) > 0)
		FPRINTF(eth_hfarr, "		 \"%s\", HFILL }},\n", blurb);
	else
		FPRINTF(eth_hfarr, "		 NULL, HFILL }},\n");
	FPRINTF(eth_hfarr, "\n");

	return hf_name;
}

/* this function will parse the no emit list and decide whether code should
   be generated for this dissector or if we should only register the type.
*/
static int
check_if_to_emit(char *name)
{
	no_emit_item_t *nel;

	for(nel=no_emit_list;nel;nel=nel->next){
		if(!g_strcmp0(name, nel->name)){
			FPRINTF(NULL, "SKIPPED emitting of %s\n",name);
			return 0;
		}
	}
	return 1;
}

#if 0
static void
prune_keywords(char *name)
{
	token_item_t *ti;

	for(ti=token_list;ti;ti=ti->next){
		if(!ti->next){
			break;
		}
		if(!g_strcmp0(ti->next->str, name)){
			if(!g_strcmp0(ti->next->next->str, ",")){
				ti->next=ti->next->next->next;
			} else {
				ti->next=ti->next->next;
			}
		}
	}
}
#endif

static void
rename_tokens(const char *old_name, const char *new_name)
{
	token_item_t *ti;

	for(ti=token_list;ti;ti=ti->next){
		if(!g_strcmp0(ti->str, old_name)){
			ti->str=g_strdup(new_name);
		}
	}
}

static void
prune_keyword_parameters(const char *name)
{
	token_item_t *ti, *tmpti;

	for(ti=token_list;ti;ti=ti->next){
		if(!g_strcmp0(ti->str, name)){
			if(!g_strcmp0(ti->next->str, "(")){
				tmpti=ti;
				while(1){
					if(!g_strcmp0(tmpti->str, ")")){
						ti->next=tmpti->next;
						break;
					}
					tmpti=tmpti->next;
				}
			}
		}
	}
}

/* this function will parse a bracket item
	   [ ... ]
   it will return the token of the next item following the ']'
*/
static token_item_t *
parsebrackets(token_item_t *ti, bracket_item_t **bracket){
	bracket_item_t *br;
	type_item_t *type_item;

	if(g_strcmp0(ti->str, "[")){
		FPRINTF(stderr, "ERROR: parsebrackets first token is not '['\n");
		Exit(10);
	}
	ti=ti->next;

	br=g_new0(bracket_item_t, 1);
	if (!br) {
		FPRINTF(stderr, "Can't allocate memory. Exit.\n");
		exit(10);
	}
	*bracket=br;
	br->flags=0;
	br->case_name=NULL;
	br->pointer_list=NULL;

	while(ti){
		if( !g_strcmp0(ti->str, "{")
		  ||!g_strcmp0(ti->str, "}")){
			FPRINTF(stderr, "ERROR: parsebrackets '{' '}' inside bracket item\n");
			Exit(10);
		}

		if(!g_strcmp0(ti->str, "[")){
			FPRINTF(stderr, "ERROR: parsebrackets '[' inside bracket item\n");
			Exit(10);
		}

		/* finished */
		if(!g_strcmp0(ti->str, "]")){
			/* check for [ ... ] [ ...] */
			ti=ti->next;

			if(!g_strcmp0(ti->str, "[")){
				ti=ti->next;
				continue;
			}
			return ti;
		}

		/* just ignore all ',' */
		if(!g_strcmp0(ti->str, ",")){
			ti=ti->next;
			continue;
		}

		/* case '(' tag ')' */
		if(!g_strcmp0(ti->str, "case")){
			br->flags|=BI_CASE;
			ti=ti->next;

			if(g_strcmp0(ti->str, "(")){
				FPRINTF(stderr, "ERROR: parsebrackets case not followed by '('\n");
				Exit(10);
			}
			ti=ti->next;

			/* name */
			br->case_name=ti->str;
			ti=ti->next;

			if(g_strcmp0(ti->str, ")")){
				FPRINTF(stderr, "ERROR: parsebrackets case does not end with ')'\n");
				Exit(10);
			}
			ti=ti->next;
			continue;
		}

		/* default */
		if(!g_strcmp0(ti->str, "default")){
			br->flags|=BI_CASE;
			br->flags|=BI_CASE_DEFAULT;
			br->case_name="default";
			ti=ti->next;
			continue;
		}


		/* in */
		if(!g_strcmp0(ti->str, "in")){
			br->flags|=BI_IN;
			ti=ti->next;
			continue;
		}

		/* out */
		if(!g_strcmp0(ti->str, "out")){
			br->flags|=BI_OUT;
			ti=ti->next;
			continue;
		}

		/* public : we dont care about this one */
		if(!g_strcmp0(ti->str, "public")){
			ti=ti->next;
			continue;
		}

		/* gensize : we dont care about this one */
		if(!g_strcmp0(ti->str, "gensize")){
			ti=ti->next;
			continue;
		}

		/* switch_is */
		if(!g_strcmp0(ti->str, "switch_is")){
			FPRINTF(stderr, "WARNING: parsebrackets can not handle switch_is properly yet  so we can not verify the tag size\n");
			while(ti){
				if(!g_strcmp0(ti->str, ")")){
					ti=ti->next;
					break;
				}
				ti=ti->next;
			}
			continue;
		}

		/* switch_is */
		if(!g_strcmp0(ti->str, "subcontext")){
			while(ti){
				if(!g_strcmp0(ti->str, ")")){
					ti=ti->next;
					break;
				}
				ti=ti->next;
			}
			continue;
		}

		/* value   we dont care about this one so just skip it */
		if(!g_strcmp0(ti->str, "value")){
			int level;
			ti=ti->next;
			if( g_strcmp0(ti->str, "(") ){
				FPRINTF(stderr, "WARNING: parsebrackets value was not followed by '('\n");
				Exit(10);
			}
			level=0;
			while(ti){
				if(!g_strcmp0(ti->str, "(")){
					ti=ti->next;
					level++;
					continue;
				}
				if(!g_strcmp0(ti->str, ")")){
					ti=ti->next;
					level--;
					if(level){
						continue;
					}
					break;
				}
				ti=ti->next;
			}
			continue;
		}

		/* range   we dont care about this one so just skip it */
		if(!g_strcmp0(ti->str, "range")){
			int level;
			ti=ti->next;
			if( g_strcmp0(ti->str, "(") ){
				FPRINTF(stderr, "WARNING: parsebrackets range was not followed by '('\n");
				Exit(10);
			}
			level=0;
			while(ti){
				if(!g_strcmp0(ti->str, "(")){
					ti=ti->next;
					level++;
					continue;
				}
				if(!g_strcmp0(ti->str, ")")){
					ti=ti->next;
					level--;
					if(level){
						continue;
					}
					break;
				}
				ti=ti->next;
			}
			continue;
		}

		/* flag   we dont care about this one so just skip it */
		if(!g_strcmp0(ti->str, "flag")){
			int level;
			ti=ti->next;
			if( g_strcmp0(ti->str, "(") ){
				FPRINTF(stderr, "WARNING: parsebrackets flag was not followed by '('\n");
				Exit(10);
			}
			level=0;
			while(ti){
				if(!g_strcmp0(ti->str, "(")){
					ti=ti->next;
					level++;
					continue;
				}
				if(!g_strcmp0(ti->str, ")")){
					ti=ti->next;
					level--;
					if(level){
						continue;
					}
					break;
				}
				ti=ti->next;
			}
			continue;
		}

		/* switch_type */
		if(!g_strcmp0(ti->str, "switch_type")){
			br->flags|=BI_SWITCH_TYPE;
			ti=ti->next;

			if(g_strcmp0(ti->str, "(")){
				FPRINTF(stderr, "WARNING: parsebrackets switch_type was not followed by '('\n");
				Exit(10);
			}
			ti=ti->next;

			type_item=find_type(ti->str);
			if(!type_item){
				FPRINTF(stderr, "ERROR : parsebrackets switch_type unknown type %s\n",ti->str);
				Exit(10);
			}
			br->union_tag_size=type_item->alignment;
			ti=ti->next;

			if(g_strcmp0(ti->str, ")")){
				FPRINTF(stderr, "WARNING: parsebrackets switch_type did not end with ')'\n");
				Exit(10);
			}
			ti=ti->next;

			continue;
		}

		/* size_is */
		if(!g_strcmp0(ti->str, "size_is")){
			br->flags|=BI_SIZE_IS;
			ti=ti->next;
			continue;
		}

		/* length_is */
		if(!g_strcmp0(ti->str, "length_is")){
			br->flags|=BI_LENGTH_IS;
			ti=ti->next;
			continue;
		}

		/* bitmap8bit */
		if(!g_strcmp0(ti->str, "bitmap8bit")){
			br->flags|=BI_BITMAP8;
			ti=ti->next;
			continue;
		}

		/* bitmap32bit */
		if(!g_strcmp0(ti->str, "bitmap32bit")){
			br->flags|=BI_BITMAP32;
			ti=ti->next;
			continue;
		}

		/* ref, unique or ptr */
		if(!g_strcmp0(ti->str, "ref")
		|| !g_strcmp0(ti->str, "unique")
		|| !g_strcmp0(ti->str, "ptr")){
			pointer_item_t *newpi;

			br->flags|=BI_POINTER;
			newpi=g_new0(pointer_item_t, 1);
			if (!newpi) {
				FPRINTF(stderr, "Can't allocate memory. Exit.\n");
				exit(10);
			}
			newpi->next=NULL;
			newpi->type=ti->str;
			newpi->next=br->pointer_list;
			br->pointer_list=newpi;
			ti=ti->next;
			continue;
		}

		FPRINTF(stderr, "ERROR: parsebrackets should not be reached  unknown tag:%s\n", ti->str);
		Exit(10);
	}

	return NULL;
}

/* this function will register a new type learnt from the IDL file
*/
static type_item_t *
register_new_type(const char *name, const char *dissectorname, const char *ft_type, const char *base_type, const char *mask, const char *valsstring, int alignment){
	type_item_t *new_type;

	FPRINTF(NULL,"XXX new type:%s dissector:%s Type:%s Base:%s Mask:%s Vals:%s alignment:%d\n", name, dissectorname, ft_type, base_type, mask, valsstring, alignment);

	new_type=g_new0(type_item_t, 1);
	if (!new_type) {
		FPRINTF(stderr, "Can't allocate memory. Exit.\n");
		exit(10);
	}
	new_type->next=type_list;
	new_type->name=g_strdup(name);
	new_type->dissector=g_strdup(dissectorname);
	new_type->ft_type=g_strdup(ft_type);
	new_type->base_type=g_strdup(base_type);
	new_type->mask=g_strdup(mask);
	new_type->vals=g_strdup(valsstring);
	new_type->alignment=alignment;
	type_list=new_type;

	return new_type;
}


/* this function will print the remaining content of the token list
*/
static void printtokenlist(int count)
{
	token_item_t *ti;
	FPRINTF(stderr, "TOKENLIST:\n");
	for(ti=token_list;ti&&count;count--,ti=ti->next){
		FPRINTF(stderr, "Token \"%s\"\n",ti->str);
	}
	if(!count){
		FPRINTF(stderr, "	 ...\n");
	}
}


/* this function will parse the header and pick up the fields
 * we are interested in.
 * the header is supposed to start at the very first token and look like
 * [ <fields> ] inteface <ifname> {
 *
 * we are interested in the fields:
 *	   uuid
 *	   version
 *	   pointer_default
 *
 * this function will also g_remove the header from the token list
 */
static void parseheader(void)
{
	char filter_name[BASE_BUFFER_SIZE];
	token_item_t *ti;
	int level=0;
	int major, minor;

	ti=token_list;
	if(!ti){
		FPRINTF(stderr, "ERROR: no tokens\n");
		Exit(10);
	}

	/* first token must be '[' */
	if( g_strcmp0(ti->str, "[") ){
		FPRINTF(stderr, "ERROR: first token is not '['\n");
		Exit(10);
	}

	for(ti=token_list;ti;ti=ti->next){
		if( !g_strcmp0(ti->str, "[")){
			level++;
			continue;
		}
		if( !g_strcmp0(ti->str, "]")){
			level--;
			if(!level){
				token_list=ti->next;
				break;
			}
		}
		if(level==1){
			if( !g_strcmp0(ti->str, "uuid")){
				uuid=ti->next->next->str;
				FPRINTF(NULL,"UUID:%s\n",uuid);
			}
			if( !g_strcmp0(ti->str, "version")){
				version=ti->next->next->str;
				FPRINTF(NULL,"VERSION:%s\n",version);
			}
			if( !g_strcmp0(ti->str, "pointer_default")){
				if(!g_strcmp0(ti->next->next->str, "unique")){
					pointer_default="unique";
				} else if(!g_strcmp0(ti->next->next->str, "ptr")){
					pointer_default="ptr";
				} else {
					FPRINTF(stderr, "ERROR: unknown pointer type\n");
					Exit(10);
				}
				FPRINTF(NULL,"POINTER_DEFAULT:%s\n",pointer_default);
			}
		}
	}
	if(!token_list){
		FPRINTF(stderr, "ERROR: ran out of tokens inside header\n");
		Exit(10);
	}
	/* interface */
	if(g_strcmp0(token_list->str, "interface")){
		FPRINTF(stderr, "ERROR: interface not found\n");
		Exit(10);
	}
	token_list=token_list->next;
	if (!token_list){
		FPRINTF(stderr, "ERROR: ran out of tokens\n");
		Exit(10);
	}
	/* interface name */
	ifname=token_list->str;
	token_list=token_list->next;
	FPRINTF(NULL,"Interface:%s\n",ifname);

	/* opnum */
	g_snprintf(hf_status, BASE_BUFFER_SIZE, "hf_%s_opnum", ifname);
	g_snprintf(filter_name, BASE_BUFFER_SIZE, "%s.opnum", ifname);
	register_hf_field(hf_status, "Operation", filter_name, "FT_UINT16", "BASE_DEC", "NULL", "0", "");

	/* status */
	g_snprintf(hf_status, BASE_BUFFER_SIZE, "hf_%s_rc", ifname);
	g_snprintf(filter_name, BASE_BUFFER_SIZE, "%s.rc", ifname);
	register_hf_field(hf_status, "Return code", filter_name, "FT_UINT32", "BASE_HEX", "VALS(NT_errors)", "0", "");

	FPRINTF(eth_ett, "static gint ett_%s = -1;\n", ifname);
	FPRINTF(eth_ettarr, "		 &ett_%s,\n", ifname);

	/* the body must start with { */
	if(g_strcmp0(token_list->str, "{")){
		FPRINTF(stderr, "ERROR: body does not start with '{'\n");
		Exit(10);
	}

	/* skip the initial '{' */
	token_list=token_list->next;

	if(!uuid){
		FPRINTF(stderr, "ERROR: no uuid found\n");
		Exit(10);
	}
	FPRINTF(eth_code,"static e_guid_t uuid_dcerpc_%s = {\n", ifname);
	FPRINTF(eth_code,"	  0x%c%c%c%c%c%c%c%c, 0x%c%c%c%c, 0x%c%c%c%c,\n",uuid[1],uuid[2],uuid[3],uuid[4],uuid[5],uuid[6],uuid[7],uuid[8],uuid[10],uuid[11],uuid[12],uuid[13],uuid[15],uuid[16],uuid[17],uuid[18]);
	FPRINTF(eth_code,"	  { 0x%c%c, 0x%c%c, 0x%c%c, 0x%c%c, 0x%c%c, 0x%c%c, 0x%c%c, 0x%c%c}\n",uuid[20],uuid[21],uuid[22],uuid[23],uuid[25],uuid[26],uuid[27],uuid[28],uuid[29],uuid[30],uuid[31],uuid[32],uuid[33],uuid[34],uuid[35],uuid[36]);
	FPRINTF(eth_code,"};\n");
	FPRINTF(eth_code,"\n");

	sscanf(version, "%d.%d", &major, &minor);
	FPRINTF(eth_code,"static guint16 ver_%s = %d;\n", ifname, major);
	FPRINTF(eth_code,"\n");

	FPRINTF(eth_handoff, "	  dcerpc_init_uuid(proto_%s, ett_%s,\n", ifname, ifname);
	FPRINTF(eth_handoff, "		  &uuid_dcerpc_%s, ver_%s,\n", ifname, ifname);
	FPRINTF(eth_handoff, "		  function_dissectors, hf_%s_opnum);\n", ifname);
}



/* this helper function is called by the tokenizer and will just append the
   current token to the linked list
*/
static void pushtoken(char *token)
{
	token_item_t *new_token_item;
	new_token_item=g_new0(token_item_t, 1);
	if (!new_token_item) {
		FPRINTF(stderr, "Can't allocate memory. Exit.\n");
		exit(10);
	}
	new_token_item->next=NULL;
	new_token_item->str=token;
	if(!token_list){
		token_list=new_token_item;
	} else {
		last_token_item->next=new_token_item;
	}
	last_token_item=new_token_item;
}

/* this function reads the idl file and translates it into tokens.
   the tokens are stored in a linked list  token_list of type token_item_t
*/
static void tokenize(FILE *fh)
{
	int ch;
	int fullinecomment=0;
	int normalcomment=0;
	int insidequote=0;
	char qs[4 * BASE_BUFFER_SIZE];
	int qspos=0;
	int insidetoken=0;
	char token[4 * BASE_BUFFER_SIZE];
	int tokenpos=0;

	while(!feof(fh)){
		ch=fgetc(fh);

		/* full line comment */
		if(fullinecomment){
			if( (ch=='\n')||(ch=='\r') ){
				fullinecomment=0;
				linepos=0;
			}
			continue;
		}
		if( (ch=='#')&&(linepos==0) ){
			fullinecomment=1;
			continue;
		}

		/* normal comment */
		if(normalcomment==0){
			if(ch=='/'){
				int nextch;
				nextch=fgetc(fh);
				if(nextch=='*'){
					normalcomment=1;
					continue;
				}
				ungetc(nextch, fh);
			}
		} else {
			if(ch=='*'){
				int nextch;
				nextch=fgetc(fh);
				if(nextch=='/'){
					normalcomment=0;
					continue;
				}
				ungetc(nextch, fh);
			}
			continue;
		}

		/* quoted string */
		if(insidequote){
			if(ch=='"'){
				insidequote=0;
				qs[qspos++]='"';
				qs[qspos]=0;
				pushtoken(g_strdup(qs));
				continue;
			} else {
				qs[qspos++]=(char)ch;
				continue;
			}
		} else {
			if(ch=='"'){
				insidequote=1;
				qs[0]='"';
				qspos=1;
				continue;
			}
		}


		switch(ch){
		case '\n':
		case '\r':
			if(insidetoken){
				insidetoken=0;
				token[tokenpos]=0;
				pushtoken(g_strdup(token));
			}
			line[linepos]=0;

			linepos=0;
			lineno++;
			break;
		case '\t':
		case ' ':
			if(insidetoken){
				insidetoken=0;
				token[tokenpos]=0;
				pushtoken(g_strdup(token));
			}
			break;
		case '[':
		case ']':
		case '(':
		case ')':
		case ',':
		case ';':
		case '*':
		case '=':
			if(insidetoken){
				insidetoken=0;
				token[tokenpos]=0;
				pushtoken(g_strdup(token));
			}
			token[0]=(char)ch;
			token[1]=0;
			pushtoken(g_strdup(token));
			break;
		default:
			if(!insidetoken){
				tokenpos=0;
			}
			insidetoken=1;
			token[tokenpos++]=(char)ch;
			line[linepos++]=(char)ch;
			break;
		}

	}
}


static type_item_t *
find_type(char *name)
{
	type_item_t *tmptype;
	for(tmptype=type_list;tmptype;tmptype=tmptype->next){
		if(!g_strcmp0(tmptype->name, name)){
			break;
		}
	}
	/* autogenerate built in types */
	if(!tmptype){
		char dissectorname[DISSECTORNAME_MAXLEN];
		if(!g_strcmp0(name,"uint16")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("uint16", dissectorname, "FT_UINT16", "BASE_DEC", "0", "NULL", 2);
		} else if(!g_strcmp0(name,"int16")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("int16", dissectorname, "FT_INT16", "BASE_DEC", "0", "NULL", 2);
		} else if(!g_strcmp0(name,"uint32")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("uint32", dissectorname, "FT_UINT32", "BASE_DEC", "0", "NULL", 4);
		} else if( (!g_strcmp0(name,"int32"))
			|| (!g_strcmp0(name,"long")) ){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			if (!g_strcmp0(name,"int32"))
				tmptype=register_new_type("int32", dissectorname, "FT_INT32", "BASE_DEC", "0", "NULL", 4);
			else
				tmptype=register_new_type("long", dissectorname, "FT_INT32", "BASE_DEC", "0", "NULL", 4);
		} else if( (!g_strcmp0(name,"uint8")) ){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uint8(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("uint8", dissectorname, "FT_UINT8", "BASE_DEC", "0", "NULL", 1);
		} else if( (!g_strcmp0(name,"int8"))
			|| (!g_strcmp0(name, "char")) ){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uint8(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			if (!g_strcmp0(name,"int8"))
				tmptype=register_new_type("int8", dissectorname, "FT_INT8", "BASE_DEC", "0", "NULL", 1);
			else
				tmptype=register_new_type("char", dissectorname, "FT_INT8", "BASE_DEC", "0", "NULL", 1);
		} else if(!g_strcmp0(name,"bool8")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uint8(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("bool8", dissectorname, "FT_INT8", "BASE_DEC", "0", "NULL", 1);
		} else if(!g_strcmp0(name,"unistr")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, 2, hf_index, FALSE, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("unistr", dissectorname, "FT_STRING", "BASE_NONE", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"ascstr")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, 1, hf_index, FALSE, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("ascstr", dissectorname, "FT_STRING", "BASE_NONE", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"GUID")
			||!g_strcmp0(name,"uuid_t")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type(name, dissectorname, "FT_GUID", "BASE_NONE", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"policy_handle")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static e_ctx_hnd policy_hnd;\n");
			FPRINTF(eth_code, "static proto_item *hnd_item;\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, di, drep,\n");
			FPRINTF(eth_code, " 				  hf_index, &policy_hnd, &hnd_item,\n");
			FPRINTF(eth_code, " 				  param&0x01, param&0x02);\n");

			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("policy_handle", dissectorname, "FT_BYTES", "BASE_NONE", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"NTTIME")){
			/* 8 bytes, aligned to 4 bytes */
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, di, drep, hf_index);\n");

			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("NTTIME", dissectorname, "FT_ABSOLUTE_TIME", "ABSOLUTE_TIME_LOCAL", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"NTTIME_hyper")){
			/* 8 bytes, aligned to 8 bytes */
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    ALIGN_TO_8_BYTES;\n");
			FPRINTF(eth_code, "    offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, di, drep, hf_index);\n");

			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("NTTIME_hyper", dissectorname, "FT_ABSOLUTE_TIME", "ABSOLUTE_TIME_LOCAL", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"NTTIME_1sec")){
			/* 8 bytes, aligned to 8 bytes */
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    ALIGN_TO_8_BYTES;\n");
			FPRINTF(eth_code, "    offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, di, drep, hf_index);\n");

			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("NTTIME_1sec", dissectorname, "FT_ABSOLUTE_TIME", "ABSOLUTE_TIME_LOCAL", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"udlong")){
			/* 8 bytes, aligned to 4 bytes */
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_duint32(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("udlong", dissectorname, "FT_UINT64", "BASE_DEC", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"dlong")){
			/* 8 bytes, aligned to 4 bytes */
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_duint32(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("dlong", dissectorname, "FT_INT64", "BASE_DEC", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"uint64")){
			/* 8 bytes, aligned to 8 bytes */
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    \n");
			FPRINTF(eth_code, "    ALIGN_TO_8_BYTES;\n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uint64(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("uint64", dissectorname, "FT_UINT64", "BASE_DEC", "0", "NULL", 8);
		} else if(!g_strcmp0(name,"time_t")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    \n");
			FPRINTF(eth_code, "    offset=dissect_ndr_time_t(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("time_t", dissectorname, "FT_ABSOLUTE_TIME", "ABSOLUTE_TIME_LOCAL", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"SID")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    di->hf_index=hf_index;\n");

			FPRINTF(eth_code, "    offset=dissect_ndr_nt_SID_with_options(tvb, offset, pinfo, tree, di, drep, param);\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("SID", dissectorname, "FT_STRING", "BASE_NONE", "0", "NULL", 4);
		} else if(!g_strcmp0(name,"WERROR")){
			g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, name);
			FPRINTF(NULL,"\nAutogenerating built-in type:%s\n------------\n",name);
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    \n");
			FPRINTF(eth_code, "    offset=dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");
			tmptype=register_new_type("WERROR", dissectorname, "FT_UINT32", "BASE_DEC", "0", "VALS(NT_errors)", 4);
		}
	}

	return tmptype;
}


/* this function will skip past an entire declare ... ; statement */
static void skipdeclare(void)
{
	token_item_t *ti;

	/* first must be the keyword const */
	ti=token_list;
	if(strncmp(ti->str, "declare", 7)){
		FPRINTF(stderr, "ERROR: skipdeclare  first token is not 'declare'\n");
		Exit(10);
	}
	while(ti->str[0] != ';'){
		ti=ti->next;
	}
	ti=ti->next;

	token_list=ti;
}

/* this function will parse a
	   const
   and generate the appropriate code
   const must be followed by a suitable keyword [uint16|uint32|...]
   the const will later be g_removed from the token list
   the function assumes that the const is the first object in the token_list
*/
static void parseconst(void)
{
	token_item_t *ti;
	char *name, *value;

	/* first must be the keyword const */
	ti=token_list;
	if(strncmp(ti->str, "const", 5)){
		FPRINTF(stderr, "ERROR: const  first token is not 'const'\n");
		Exit(10);
	}
	ti=ti->next;

	/* just skip second token */
	ti=ti->next;

	/* third is a variable and not a type */
	if(find_type(ti->str)){
		FPRINTF(stderr, "ERROR: const, not a variable name:%s\n", ti->str);
		Exit(10);
	}
	name=ti->str;
	ti=ti->next;

	/* fourth is '=' */
	if(ti->str[0] != '='){
		FPRINTF(stderr, "ERROR: const  fourth token is not '='\n");
		Exit(10);
	}
	ti=ti->next;

	/* fifth is the value */
	value=ti->str;
	ti=ti->next;

	/* sixth is ';' */
	if(ti->str[0] != ';'){
		FPRINTF(stderr, "ERROR: const  sixth token is not ';'\n");
		Exit(10);
	}
	ti=ti->next;

	FPRINTF(NULL,"\nCONST:%s\n-------\n",name);

	FPRINTF(eth_hdr, "#define %s		%s\n", name, value);

	FPRINTF(NULL,"\n----------\nEND CONST:%s\n",name);

	token_list=ti;
}

/* this function will parse a
	   typedef struct {
   construct and generate the appropriate code.
   the typedef will be g_removed from the token_list once it has been processed
   the function assumes that the typedef is the first object in the token_list
   the function will be called twice, once with pass=0 and once with pass=1
   which controls whether subdissectors are to be generated or whether the
   struct dissector itself is to be generated
*/
static void parsetypedefstruct(int pass)
{
	token_item_t *ti, *tmpti;
	char *struct_name;
	char dissectorname[DISSECTORNAME_MAXLEN];
	char tmpstr[BASE_BUFFER_SIZE], *ptmpstr;
	int level, num_pointers;
	static int alignment;
	type_item_t *type_item;
	char hf_index[BASE_BUFFER_SIZE];
	bracket_item_t *bi=NULL;
	pointer_item_t *pi;
	const char *pointer_type;
	char *field_name;
	int fixed_array_size;
	int is_array_of_pointers;
	int empty_struct = 0;

	ti=token_list;
	if(g_strcmp0(ti->str, "typedef")){
		FPRINTF(stderr, "ERROR: typedefstruct  first token is not 'typedef'\n");
		Exit(10);
	}
	ti=ti->next;

	if(!g_strcmp0(ti->str, "[")){
		ti=parsebrackets(ti, &bi);
	}
	/* check that we know how to handle the bracket thing */
	if(bi){
		if(bi->flags){
			FPRINTF(stderr, "ERROR: typedefstruct unknown bracket flags encountered : 0x%08x\n",bi->flags);
			Exit(10);
		}
	}

	if(g_strcmp0(ti->str, "struct")){
		FPRINTF(stderr, "ERROR: typedefstruct  second token is not 'struct'\n");
		Exit(10);
	}
	ti=ti->next;

	if(g_strcmp0(ti->str, "{")){
		FPRINTF(stderr, "ERROR: typedefstruct  third token is not '{'\n");
		Exit(10);
	}
	ti=ti->next;

	/* Check if the struct is empty (search if there is no end bracket) */
	if(g_strcmp0(ti->str, "}") == 0){
		empty_struct = 1;
	}

	/* search forward until the '}' so we can find the name of the struct */
	for(tmpti=ti,level=0;tmpti;tmpti=tmpti->next){
		if(!g_strcmp0(tmpti->str, "{")){
			level++;
			continue;
		}
		if(!g_strcmp0(tmpti->str, "}")){
			if(!level){
				break;
			}
			level--;
			continue;
		}
	}
	if(!tmpti || !tmpti->next){
		FPRINTF(stderr, "ERROR: typedefstruct  missing matching '}'\n");
		Exit(10);
	}

	struct_name=tmpti->next->str;
	g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, struct_name);

	FPRINTF(NULL,"\nSTRUCT:%s pass:%d\n-------\n",struct_name,pass);

	if(!check_if_to_emit(dissectorname)){
		FPRINTF(NULL,"NOEMIT Skipping this struct dissector.\n");
		ti=tmpti;
		goto typedef_struct_finished;
	}

	/* this is pass 0  so reset alignment to zero and update as items are
	   processed. we need alignment when pass 1 is run.
	   set alignment initially to 1 so we dont fail for empty structs
	*/
	if(pass==0){
		alignment=1;
	}
	/* pass 1  generate header for the struct dissector */
	if(pass==1){
		FPRINTF(eth_ett, "static gint ett_%s_%s = -1;\n", ifname, struct_name);
		FPRINTF(eth_ettarr, "		 &ett_%s_%s,\n", ifname, struct_name);
		FPRINTF(eth_hdr, "int %s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param);\n", dissectorname);
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "int\n");
		FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *parent_tree, dcerpc_info *di _U_, guint8 *drep _U_, int hf_index, guint32 param _U_)\n", dissectorname);
		FPRINTF(eth_code, "{\n");
		FPRINTF(eth_code, "    proto_item *item=NULL;\n");
		if(!empty_struct){
			FPRINTF(eth_code, "    proto_tree *tree=NULL;\n");
		}
		FPRINTF(eth_code, "    int old_offset;\n");
		FPRINTF(eth_code, "\n");
		switch(alignment){
		case 1:
			break;
		case 2:
			FPRINTF(eth_code, "    ALIGN_TO_2_BYTES;\n");
			FPRINTF(eth_code, "\n");
			break;
		case 4:
			FPRINTF(eth_code, "    ALIGN_TO_4_BYTES;\n");
			FPRINTF(eth_code, "\n");
			break;
		case 8:
			FPRINTF(eth_code, "    ALIGN_TO_8_BYTES;\n");
			FPRINTF(eth_code, "\n");
			break;
		default:
			FPRINTF(stderr, "ERROR: can not handle alignment:%d\n",alignment);
			Exit(10);
		}
		FPRINTF(eth_code, "    old_offset=offset;\n");
		FPRINTF(eth_code, "    if(parent_tree){\n");
		FPRINTF(eth_code, " 	   item=proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, ENC_NA);\n");
		if(!empty_struct){
			FPRINTF(eth_code, " 	   tree=proto_item_add_subtree(item, ett_%s_%s);\n", ifname, struct_name);
		}
		FPRINTF(eth_code, "    }\n");
		FPRINTF(eth_code, "\n");
	}

	/* scan the struct and create all subdissectors */
	level=0;
	while(ti){
		if(!g_strcmp0(ti->str, "{")){
			level++;
			ti=ti->next;
			continue;
		}
		if(!g_strcmp0(ti->str, "}")){
			if(!level){
				break;
			}
			level--;
			ti=ti->next;
			continue;
		}
		if(!g_strcmp0(ti->str, "[")){
			ti=parsebrackets(ti, &bi);
			continue;
		}

		/* check that we know how to handle the bracket thing */
		if(bi){
			if(bi->flags&(~(BI_SIZE_IS|BI_LENGTH_IS|BI_POINTER))){
				FPRINTF(stderr, "ERROR: typedefstruct unknown bracket flags encountered : 0x%08x\n",bi->flags);
				Exit(10);
			}
		}

		/* handle the type, verify that we KNOW this type */
		type_item=find_type(ti->str);
		if(!type_item){
			FPRINTF(stderr, "ERROR : typedefstruct unknown type %s\n",ti->str);
			Exit(10);
		}
		ti=ti->next;
		/* count the levels of pointers */
		for(num_pointers=0;!g_strcmp0(ti->str, "*");ti=ti->next){
			num_pointers++;
			/* poitners are aligned at 4 byte boundaries */
			if(alignment<4){
				alignment=4;
			}
		}
		/* now that we know how many real pointers there were we must
		   prepend default pointers to the list so it has the right
		   length.
		*/
		pi=prepend_pointer_list(bi?bi->pointer_list:NULL, num_pointers);
		/* keep track of alignment */
		if(alignment<type_item->alignment){
			alignment=type_item->alignment;
		}

		field_name=ti->str;
		ti=ti->next;

		/* see if it is a fixed array */
		fixed_array_size=0;
		is_array_of_pointers=0;
		if(!g_strcmp0(ti->str, "[")){
			char fss[BASE_BUFFER_SIZE];

			/* this might be a fixed array */
			ti=ti->next;

			fixed_array_size=atoi(ti->str);
			g_snprintf(fss, BASE_BUFFER_SIZE, "%d", fixed_array_size);

			if(!g_strcmp0("]", ti->str)){
				/* this is just a normal [] array */
				fixed_array_size=0;
			} else if(!g_strcmp0("*", ti->str)){
				pi=prepend_pointer_list(pi, num_pointers+1);
				fixed_array_size=0;
				is_array_of_pointers=1;
				ti=ti->next;
			} else if(g_strcmp0(fss, ti->str)){
				FPRINTF(stderr, "ERROR: typedefstruct (%s) fixed array size looks different to calculated one %s!=%s\n", struct_name, fss, ti->str);
				ti=ti->next;
				Exit(10);
			} else {
				ti=ti->next;
			}

			if(g_strcmp0(ti->str, "]")){
				FPRINTF(stderr, "ERROR: typedefstruct  fixed array does not end with ']' it ended with %s\n",ti->str);
				Exit(10);
			}
			ti=ti->next;
		}

		g_snprintf(hf_index, BASE_BUFFER_SIZE, "hf_%s_%s_%s", ifname, struct_name, field_name);
		/* pass 0  generate subdissectors */
		if(pass==0){
			char filter_name[BASE_BUFFER_SIZE];
			const char *hf;

			g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_dissect_%s_%s", ifname, struct_name, field_name);
			ptmpstr=g_strdup(tmpstr);

			if(check_if_to_emit(tmpstr)){
			  g_snprintf(filter_name, BASE_BUFFER_SIZE, "%s.%s.%s", ifname, struct_name, field_name);
			  hf=register_hf_field(hf_index, field_name, filter_name, type_item->ft_type, type_item->base_type, type_item->vals, type_item->mask, "");
			  FPRINTF(eth_code, "static int\n");
			  FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", ptmpstr);
			  FPRINTF(eth_code, "{\n");
			  FPRINTF(eth_code, "	 guint32 param=%s;\n",find_dissector_param_value(ptmpstr));
			  FPRINTF(eth_code, "	 offset=%s(tvb, offset, pinfo, tree, di, drep, %s, param);\n", type_item->dissector, hf);
			  FPRINTF(eth_code, "	 return offset;\n");
			  FPRINTF(eth_code, "}\n");
			  FPRINTF(eth_code, "\n");
			} else {
			  FPRINTF(NULL,"NOEMIT Skipping this struct item :%s\n",tmpstr);
			}

			if(is_array_of_pointers){
				pointer_type=pi->type;
				pi=pi->next;
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_%s", pointer_type, ptmpstr);
				if(check_if_to_emit(tmpstr)){
				  FPRINTF(eth_code, "static int\n");
				  FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				  FPRINTF(eth_code, "{\n");
				  FPRINTF(eth_code, "	 offset=dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, %s, %s, \"%s\", -1);\n", ptmpstr, ptr_to_define(pointer_type), field_name);
				  FPRINTF(eth_code, "	 return offset;\n");
				  FPRINTF(eth_code, "}\n");
				  FPRINTF(eth_code, "\n");
				} else {
				  FPRINTF(NULL,"NOEMIT Skipping this struct item :%s\n",tmpstr);
				}

				ptmpstr=g_strdup(tmpstr);
			} else if(fixed_array_size){
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "fixedarray_%s", ptmpstr);
				if(check_if_to_emit(tmpstr)){
				  FPRINTF(eth_code, "static int\n");
				  FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				  FPRINTF(eth_code, "{\n");
				  FPRINTF(eth_code, "	 int count=%d;\n",fixed_array_size);
				  FPRINTF(eth_code, "	 while(count--){\n");
				  FPRINTF(eth_code, "		 offset=%s(tvb, offset, pinfo, tree, di, drep);\n", ptmpstr);
				  FPRINTF(eth_code, "	 }\n");
				  FPRINTF(eth_code, "\n");
				  FPRINTF(eth_code, "	 return offset;\n");
				  FPRINTF(eth_code, "}\n");
				  FPRINTF(eth_code, "\n");
				} else {
				  FPRINTF(NULL,"NOEMIT Skipping this struct item :%s\n",tmpstr);
				}
				ptmpstr=g_strdup(tmpstr);
			}

			/* handle switch_is */
			if(bi){
			  switch(bi->flags&(BI_SIZE_IS|BI_LENGTH_IS)){
			  case 0:
				break;
			  case BI_SIZE_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "ucarray_%s", ptmpstr);
				if(check_if_to_emit(tmpstr)){
				  FPRINTF(eth_code, "static int\n");
				  FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				  FPRINTF(eth_code, "{\n");
				  FPRINTF(eth_code, "	 offset=dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, %s);\n", ptmpstr);
				  FPRINTF(eth_code, "	 return offset;\n");
				  FPRINTF(eth_code, "}\n");
				  FPRINTF(eth_code, "\n");
				} else {
				  FPRINTF(NULL,"NOEMIT Skipping this struct item :%s\n",tmpstr);
				}
				ptmpstr=g_strdup(tmpstr);
				break;
			  case BI_LENGTH_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "uvarray_%s", ptmpstr);
				if(check_if_to_emit(tmpstr)){
				  FPRINTF(eth_code, "static int\n");
				  FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				  FPRINTF(eth_code, "{\n");
				  FPRINTF(eth_code, "	 offset=dissect_ndr_uvarray(tvb, offset, pinfo, tree, di, drep, %s);\n", ptmpstr);
				  FPRINTF(eth_code, "	 return offset;\n");
				  FPRINTF(eth_code, "}\n");
				  FPRINTF(eth_code, "\n");
				} else {
				  FPRINTF(NULL,"NOEMIT Skipping this struct item :%s\n",tmpstr);
				}
				ptmpstr=g_strdup(tmpstr);
				break;
			  case BI_SIZE_IS|BI_LENGTH_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "ucvarray_%s", ptmpstr);
				if(check_if_to_emit(tmpstr)){
				  FPRINTF(eth_code, "static int\n");
				  FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				  FPRINTF(eth_code, "{\n");
				  FPRINTF(eth_code, "	 offset=dissect_ndr_ucvarray(tvb, offset, pinfo, tree, di, drep, %s);\n", ptmpstr);
				  FPRINTF(eth_code, "	 return offset;\n");
				  FPRINTF(eth_code, "}\n");
				  FPRINTF(eth_code, "\n");
				} else {
				  FPRINTF(NULL,"NOEMIT Skipping this struct item :%s\n",tmpstr);
				}
				ptmpstr=g_strdup(tmpstr);
				break;
			  default:
				FPRINTF(stderr, "ERROR: typedefstruct can not handle this combination of sizeis/lengthis\n");
				Exit(10);
			  }
			}

			/* handle pointers */
			while(num_pointers--){
				pointer_type=pi->type;
				pi=pi->next;
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_%s", pointer_type, ptmpstr);
				if(check_if_to_emit(tmpstr)){
				  FPRINTF(eth_code, "static int\n");
				  FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				  FPRINTF(eth_code, "{\n");
				  FPRINTF(eth_code, "	 offset=dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, %s, %s, \"%s\", -1);\n", ptmpstr, ptr_to_define(pointer_type), field_name);
				  FPRINTF(eth_code, "	 return offset;\n");
				  FPRINTF(eth_code, "}\n");
				  FPRINTF(eth_code, "\n");
				} else {
				  FPRINTF(NULL,"NOEMIT Skipping this struct item :%s\n",tmpstr);
				}

				ptmpstr=g_strdup(tmpstr);
			}
		}

		if(pass==1){
			g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_dissect_%s_%s", ifname, struct_name, field_name);
			ptmpstr=g_strdup(tmpstr);

			/* handle fixedsizearrays */
			if(is_array_of_pointers){
				pointer_type=pi->type;
				pi=pi->next;
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_%s", pointer_type, ptmpstr);
				ptmpstr=g_strdup(tmpstr);
			} else if(fixed_array_size){
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "fixedarray_%s", ptmpstr);
				ptmpstr=g_strdup(tmpstr);
			}

			/* handle switch_is */
			if(bi){
			  switch(bi->flags&(BI_SIZE_IS|BI_LENGTH_IS)){
			  case 0:
				break;
			  case BI_SIZE_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "ucarray_%s", ptmpstr);
				ptmpstr=g_strdup(tmpstr);
				break;
			  case BI_LENGTH_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "uvarray_%s", ptmpstr);
				ptmpstr=g_strdup(tmpstr);
				break;
			  case BI_SIZE_IS|BI_LENGTH_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "ucvarray_%s", ptmpstr);
				ptmpstr=g_strdup(tmpstr);
				break;
			  default:
				FPRINTF(stderr, "ERROR: typedefstruct can not handle this combination of sizeis/lengthis\n");
				Exit(10);
			  }
			}

			/* handle pointers */
			while(num_pointers--){
				pointer_type=pi->type;
				pi=pi->next;
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_%s", pointer_type, ptmpstr);
				ptmpstr=g_strdup(tmpstr);
			}

			FPRINTF(eth_code, "    offset=%s(tvb, offset, pinfo, tree, di, drep);\n", ptmpstr);
			FPRINTF(eth_code, "\n");
		}

		if(g_strcmp0(ti->str,";")){
			FPRINTF(stderr, "ERROR: field does not en with ';'\n");
			Exit(10);
		}
		ti=ti->next;
		bi=NULL; /* clear bi before we start on the next field */
	}

	if(pass==1){
		FPRINTF(eth_code, "    proto_item_set_len(item, offset-old_offset);\n");
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "    return offset;\n");
		FPRINTF(eth_code, "}\n");
		register_new_type(struct_name, dissectorname, "FT_NONE", "BASE_NONE", "0", "NULL", alignment);
	}


typedef_struct_finished:
	FPRINTF(NULL,"\nEND STRUCT:%s pass:%d\n-------\n",struct_name,pass);

	/* only advance token_list for pass==1
	   ti now points to the '}' token
	*/
	if(pass==1){
		if(!ti || g_strcmp0(ti->str,"}")){
			FPRINTF(stderr, "ERROR: struct does not end with '}'\n");
			Exit(10);
		}
		ti=ti->next;

		/* just skip the name */
		ti=ti->next;

		if(!ti || g_strcmp0(ti->str,";")){
			FPRINTF(stderr, "ERROR: struct does not end with ';'\n");
			Exit(10);
		}
		ti=ti->next;

		token_list=ti;
	}
}

/* this function will parse a
	   typedef bitmap {
   construct and generate the appropriate code.
   the typedef will be g_removed from the token_list once it has been processed
   the function assumes that the typedef is the first object in the token_list
   the function will be called twice, once with pass=0 and once with pass=1
   which controls whether subdissectors are to be generated or whether the
   bitmap dissector itself is to be generated

   bitmaps are by default 32 bits
*/
static void parsetypedefbitmap(int pass)
{
	token_item_t *ti, *tmpti;
	char *bitmap_name;
	char dissectorname[BASE_BUFFER_SIZE], hf_bitname[BASE_BUFFER_SIZE];
	int alignment;
	unsigned int val;
	char *name, *value;
	bracket_item_t *bi=NULL;

	ti=token_list;
	if(g_strcmp0(ti->str, "typedef")){
		FPRINTF(stderr, "ERROR: typedefbitmap  first token is not 'typedef'\n");
		Exit(10);
	}
	ti=ti->next;

	alignment=4;  /* default size is 32 bits */

	if(!g_strcmp0(ti->str, "[")){
		ti=parsebrackets(ti, &bi);
	}
	/* check that we know how to handle the bracket thing */
	if(bi){
		if(bi->flags&(~(BI_BITMAP32|BI_BITMAP8))){
			FPRINTF(stderr, "ERROR: typedefbitmap unknown bracket flags encountered : 0x%08x\n",bi->flags);
			Exit(10);
		}
		if(bi->flags&BI_BITMAP32){
			alignment=4;
		}
		if(bi->flags&BI_BITMAP8){
			alignment=1;
		}
	}


	if(g_strcmp0(ti->str, "bitmap")){
		FPRINTF(stderr, "ERROR: typedefbitmap  second token is not 'bitmap'\n");
		Exit(10);
	}
	ti=ti->next;

	if(g_strcmp0(ti->str, "{")){
		FPRINTF(stderr, "ERROR: typedefbitmap  third token is not '{'\n");
		Exit(10);
	}
	ti=ti->next;

	/* search forward until the '}' so we can find the name of the bitmap */
	for(tmpti=ti;tmpti;tmpti=tmpti->next){
		if(!g_strcmp0(tmpti->str, "{")){
			FPRINTF(stderr, "ERROR: typedefbitmap '{' encountered inside bitmap\n");
			Exit(10);
		}
		if(!g_strcmp0(tmpti->str, "}")){
			break;
		}
	}
	if (!tmpti || !tmpti->next){
		FPRINTF(stderr, "ERROR: typedefbitmap missing matching '}'\n");
		Exit(10);
	}
	bitmap_name=tmpti->next->str;
	g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, bitmap_name);

	FPRINTF(NULL,"\nBITMAP:%s pass:%d\n-------\n",bitmap_name,pass);

	/* pass 1  generate header for the struct dissector */
	if(pass==1){
		FPRINTF(eth_ett, "static gint ett_%s_%s = -1;\n", ifname, bitmap_name);
		FPRINTF(eth_ettarr, "		 &ett_%s_%s,\n", ifname, bitmap_name);
		FPRINTF(eth_hdr, "int %s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param);\n", dissectorname);
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "int\n");
		FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
		FPRINTF(eth_code, "{\n");
		FPRINTF(eth_code, "    proto_item *item=NULL;\n");
		FPRINTF(eth_code, "    proto_tree *tree=NULL;\n");
		switch(alignment){
		case 1:
			FPRINTF(eth_code, "    guint8 flags;\n");
			FPRINTF(eth_code, "\n");
			break;
		case 4:
			FPRINTF(eth_code, "    guint32 flags;\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    ALIGN_TO_4_BYTES;\n");
			break;
		default:
			FPRINTF(stderr, "ERROR: typedefbitmap can not handle alignment:%d\n",alignment);
			Exit(10);
		}
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "    if(parent_tree){\n");
		FPRINTF(eth_code, " 	   item=proto_tree_add_item(parent_tree, hf_index, tvb, offset, %d, ENC_LITTLE_ENDIAN);\n", alignment);
		FPRINTF(eth_code, " 	   tree=proto_item_add_subtree(item, ett_%s_%s);\n", ifname, bitmap_name);
		FPRINTF(eth_code, "    }\n");
		FPRINTF(eth_code, "\n");
		switch(alignment){
		case 1:
			FPRINTF(eth_code, "    offset=dissect_ndr_uint8(tvb, offset, pinfo, NULL, di, drep, -1, &flags);\n");
			FPRINTF(eth_code, "\n");
			break;
		case 4:
			FPRINTF(eth_code, "    offset=dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);\n");
			FPRINTF(eth_code, "\n");
			break;
		default:
			FPRINTF(stderr, "ERROR: typedefbitmap can not handle alignment:%d\n",alignment);
			Exit(10);
		}
		FPRINTF(eth_code, "\n");
	}

	/* scan the struct and create call for all bits */
	while(ti){
		if(!g_strcmp0(ti->str, "}")){
			break;
		}
		if(!g_strcmp0(ti->str, "[")){
			FPRINTF(stderr, "ERROR: typedefbitmap can not handle '[' yet\n");
			Exit(10);
		}

		name=ti->str;
		ti=ti->next;
		g_snprintf(hf_bitname, BASE_BUFFER_SIZE, "hf_%s_%s_%s", ifname, bitmap_name, name);

		if(g_strcmp0(ti->str, "=")){
			FPRINTF(stderr, "ERROR: typedefbitmap i expected a '=' here\n");
			Exit(10);
		}
		ti=ti->next;

		value=ti->str;
		ti=ti->next;
		val=0;
		if(!strncmp(value, "0x", 2)){
			sscanf(value, "0x%x", &val);
		} else {
			FPRINTF(stderr, "ERROR: typedefbitmap can only handle hexadecimal constants\n");
			Exit(10);
		}

		if( val&(val-1) ){
			FPRINTF(stderr, "ERROR: typedefbitmap can only handle single bit fields\n");
			Exit(10);
		}

		if(pass==0){
			char filter_name[BASE_BUFFER_SIZE], base_name[BASE_BUFFER_SIZE], tfs_name[BASE_BUFFER_SIZE];

			g_snprintf(filter_name, BASE_BUFFER_SIZE, "%s.%s.%s", ifname, bitmap_name, name);
			g_snprintf(base_name, BASE_BUFFER_SIZE, "%d", alignment*8);
			g_snprintf(tfs_name, BASE_BUFFER_SIZE, "TFS(&%s_tfs)", name);
			register_hf_field(hf_bitname, name, filter_name, "FT_BOOLEAN", base_name, tfs_name, value, "");

			FPRINTF(eth_code, "static const true_false_string %s_tfs = {\n",name);
			FPRINTF(eth_code, "    \"%s is SET\",\n", name);
			FPRINTF(eth_code, "    \"%s is NOT set\"\n", name);
			FPRINTF(eth_code, "};\n");
			FPRINTF(eth_code, "\n");
		}

		if(pass==1){
			FPRINTF(eth_code, "    proto_tree_add_boolean(tree, %s, tvb, offset-%d, %d, flags);\n", hf_bitname, alignment, alignment);
			FPRINTF(eth_code, "    if(flags&%s){\n", value);
			FPRINTF(eth_code, " 	   proto_item_append_text(item, \" %s\");\n", name);
			FPRINTF(eth_code, "    }\n");
			FPRINTF(eth_code, "    flags&=(~%s);\n", value);
			FPRINTF(eth_code, "\n");
		}

		if(!g_strcmp0(ti->str, ",")){
			ti=ti->next;
			continue;
		}
	}

	if(pass==1){
		FPRINTF(eth_code, "    if(flags){\n");
		FPRINTF(eth_code, " 	   proto_item_append_text(item, \"UNKNOWN-FLAGS\");\n");
		FPRINTF(eth_code, "    }\n");
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "    return offset;\n");
		FPRINTF(eth_code, "}\n");
		switch(alignment){
		case 1:
			register_new_type(bitmap_name, dissectorname, "FT_UINT8", "BASE_HEX", "0", "NULL", alignment);
			break;
		case 4:
			register_new_type(bitmap_name, dissectorname, "FT_UINT32", "BASE_HEX", "0", "NULL", alignment);
			break;
		default:
			FPRINTF(stderr, "ERROR: typedefbitmap can not handle alignment:%d\n",alignment);
			Exit(10);
		}
	}

	FPRINTF(NULL,"\nEND BITMAP:%s pass:%d\n-------\n",bitmap_name,pass);

	/* only advance token_list for pass==1
	   ti now points to the '}' token
	*/
	if(pass==1){
		if(!ti || g_strcmp0(ti->str,"}")){
			FPRINTF(stderr, "ERROR: bitmap does not end with '}'\n");
			Exit(10);
		}
		ti=ti->next;

		/* just skip the name */
		ti=ti->next;

		if(!ti || g_strcmp0(ti->str,";")){
			FPRINTF(stderr, "ERROR: bitmap does not end with ';'\n");
			Exit(10);
		}
		ti=ti->next;

		token_list=ti;
	}
}

/* a case tag might be a negative number, i.e. contain a '-' sign which
   is not valid inside a symbol name in c.
*/
static const char *
case2str(const char *str)
{
	char *newstr;
	if(str[0]!='-'){
		return str;
	}
	newstr=g_strdup(str);
	newstr[0]='m';
	return newstr;
}

/* this function will parse a
	typedef union {
	construct and generate the appropriate code.
	the typedef will be g_removed from the token_list once it has been processed
	the function assumes that the typedef is the first object in the token_list
	the function will be called twice, once with pass=0 and once with pass=1
	which controls whether subdissectors are to be generated or whether the
	union dissector itself is to be generated
*/
static void parsetypedefunion(int pass)
{
	char *union_name;
	token_item_t *ti, *tmpti;
	char dissectorname[BASE_BUFFER_SIZE];
	bracket_item_t *bi=NULL;
	char tmpstr[BASE_BUFFER_SIZE], *ptmpstr;
	int level, num_pointers;
	static int alignment;
	type_item_t *type_item;
	char hf_index[BASE_BUFFER_SIZE];
	int tag_alignment, item_alignment;

	ti=token_list;
	if(g_strcmp0(ti->str, "typedef")){
		FPRINTF(stderr, "ERROR: typedefunion  first token is not 'typedef'\n");
		Exit(10);
	}
	ti=ti->next;

	if(!g_strcmp0(ti->str, "[")){
		ti=parsebrackets(ti, &bi);
	}
	/* check that we know how to handle the bracket thing */
	if(bi){
		if(bi->flags&(~(BI_SWITCH_TYPE))){
			FPRINTF(stderr, "ERROR: typedefunion unknown bracket flags encountered : 0x%08x\n",bi->flags);
			Exit(10);
		}
	}

	if(g_strcmp0(ti->str, "union")){
		FPRINTF(stderr, "ERROR: typedefunion  second token is not 'union'\n");
		Exit(10);
	}
	ti=ti->next;

	if(g_strcmp0(ti->str, "{")){
		FPRINTF(stderr, "ERROR: typedefunion  third token is not '{'\n");
		Exit(10);
	}
	ti=ti->next;

	/* search forward until the '}' so we can find the name of the union */
	for(tmpti=ti,level=0;tmpti;tmpti=tmpti->next){
		if(!g_strcmp0(tmpti->str, "{")){
			level++;
			continue;
		}
		if(!g_strcmp0(tmpti->str, "}")){
			if(!level){
				break;
			}
			level--;
			continue;
		}
	}

	if (!tmpti || !tmpti->next){
		FPRINTF(stderr, "ERROR: typedefunion  missing matching '}'\n");
		Exit(10);
	}
	union_name=tmpti->next->str;
	g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_union_%s", ifname, union_name);

	FPRINTF(NULL,"\nUNION:%s pass:%d\n-------\n",union_name,pass);

	if(bi && bi->flags&BI_SWITCH_TYPE){
		tag_alignment=bi->union_tag_size;
	} else {
		tag_alignment=get_union_tag_size(union_name);
	}

	/* this is pass 0  so reset alignment to the minimum possible value
	   and update as items are processed.
	   we need alignment when pass 1 is run
	*/
	if(pass==0){
		alignment=tag_alignment;
	}

	/* pass 1  generate header for the struct dissector */
	if(pass==1){
		FPRINTF(eth_ett, "static gint ett_%s_%s = -1;\n", ifname, union_name);
		FPRINTF(eth_ettarr, "		 &ett_%s_%s,\n", ifname, union_name);
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "static int\n");
		FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
		FPRINTF(eth_code, "{\n");
		FPRINTF(eth_code, "    proto_item *item=NULL;\n");
		FPRINTF(eth_code, "    proto_tree *tree=NULL;\n");
		FPRINTF(eth_code, "    int old_offset;\n");
		/* we do alignment on the tag itself here so that
		   we skip any alignment padding prior to where the tag
		   itself starts, this makes the byterange in the hexpane
		   for the union expansion start with the first byte of the tag
		*/
		switch(tag_alignment){
		case 1:
			break;
		case 2:
			FPRINTF(eth_code, "    guint16 level;\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    ALIGN_TO_2_BYTES;\n");
			FPRINTF(eth_code, "\n");
			break;
		case 4:
			FPRINTF(eth_code, "    guint32 level = 0;\n");
			FPRINTF(eth_code, "\n");
			FPRINTF(eth_code, "    ALIGN_TO_4_BYTES;\n");
			FPRINTF(eth_code, "\n");
			break;
		default:
			FPRINTF(stderr, "ERROR: typedefunion 1 can not handle alignment:%d\n",alignment);
			Exit(10);
		}
		FPRINTF(eth_code, "    old_offset=offset;\n");
		FPRINTF(eth_code, "    if(parent_tree){\n");
		FPRINTF(eth_code, " 	   tree=proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_%s_%s, &item, \"%s\");\n", ifname, union_name, union_name);
		FPRINTF(eth_code, "    }\n");
		FPRINTF(eth_code, "\n");
		switch(tag_alignment){
		case 1:
			break;
		case 2:
			FPRINTF(eth_code, "    offset=dissect_ndr_uint16(tvb, offset, pinfo, tree,\n");
			FPRINTF(eth_code, " 							 di, drep, hf_index, &level);\n");
		break;
		case 4:
			FPRINTF(eth_code, "    offset=dissect_ndr_uint32(tvb, offset, pinfo, tree,\n");
			FPRINTF(eth_code, " 							 di, drep, hf_index, &level);\n");
			break;
		default:
			FPRINTF(stderr, "ERROR: typedefunion 2 can not handle alignment:%d\n",alignment);
			Exit(10);
		}
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "    switch(level){\n");
	}

	/* scan the struct and create all subdissectors */
	level=0;
	while(ti){
		if(!g_strcmp0(ti->str, "{")){
			ti=ti->next;
			level++;
			continue;
		}
		if(!g_strcmp0(ti->str, "}")){
			if(!level){
				break;
			}
			ti=ti->next;
			level--;
			continue;
		}
		if(!g_strcmp0(ti->str, "[")){
			ti=parsebrackets(ti, &bi);
			continue;
		}

		if(!bi){
			FPRINTF(stderr, "ERROR : typedefunion no brackets found for case\n");
			Exit(10);
		}
		/* make sure we catch when we havent implemented everything
		   yet.
		   we currently only know about CASE and CASE_DEFAULT flags
		*/
		if(bi->flags&(~(BI_CASE|BI_CASE_DEFAULT|BI_POINTER))){
			FPRINTF(stderr, "ERROR: typedefunion unknown bracket flags encountered : 0x%08x\n",bi->flags);
			Exit(10);
		}
		if(!(bi->flags&BI_CASE)){
			FPRINTF(stderr, "ERROR : typedefunion no case found in brackets\n");
			Exit(10);
		}
#ifdef g_removeD
		/* only empty default cases for now */
		if(bi->flags&BI_CASE_DEFAULT){
			if(g_strcmp0(ti->str,";")){
				FPRINTF(stderr, "ERROR: default tag is not empty\n");
				Exit(10);
			}
			ti=ti->next;
			continue;
		}
#endif

		/* just skip all and any 'empty' arms */
		if(!g_strcmp0(ti->str, ";")){
			ti=ti->next;
			continue;
		}

		/* handle the type, verify that we KNOW this type */
		type_item=find_type(ti->str);
		if(!type_item){
			FPRINTF(stderr, "ERROR : typedefunion unknown type %s\n",ti->str);
			Exit(10);
		}
		ti=ti->next;
		/* count the levels of pointers */
		for(num_pointers=0;!g_strcmp0(ti->str, "*");ti=ti->next){
			num_pointers++;
		}

		/* keep track of alignment */
		if(num_pointers){
			item_alignment=4;
		} else {
			item_alignment=type_item->alignment;
		}
		if(alignment<item_alignment){
			alignment=item_alignment;
		}

		g_snprintf(hf_index, BASE_BUFFER_SIZE, "hf_%s_%s_%s_%s", ifname, union_name, case2str(bi->case_name), ti->str);
		/* pass 0  generate subdissectors */
		if(pass==0){
			char filter_name[BASE_BUFFER_SIZE];
			const char *hf;

			g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_dissect_union_%s_%s_%s", ifname, union_name, case2str(bi->case_name), ti->str);
			ptmpstr=g_strdup(tmpstr);

			g_snprintf(filter_name, BASE_BUFFER_SIZE, "%s.%s.%s", ifname, union_name, ti->str);
			hf=register_hf_field(hf_index, ti->str, filter_name, type_item->ft_type, type_item->base_type, type_item->vals, type_item->mask, "");

			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", ptmpstr);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    guint32 param=%s;\n",find_dissector_param_value(ptmpstr));
			FPRINTF(eth_code, "    offset=%s(tvb, offset, pinfo, tree, di, drep, %s, param);\n", type_item->dissector, hf);
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");

			/* handle pointers */
			while(num_pointers--){
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_%s", ptmpstr, "unique");
				FPRINTF(eth_code, "static int\n");
				FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				FPRINTF(eth_code, "{\n");
				FPRINTF(eth_code, "    offset=dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, %s, NDR_POINTER_UNIQUE, \"%s\", -1);\n", ptmpstr, ti->str);
				FPRINTF(eth_code, "    return offset;\n");
				FPRINTF(eth_code, "}\n");
				FPRINTF(eth_code, "\n");

				ptmpstr=g_strdup(tmpstr);

			}
		}

		if(pass==1){
			/* handle pointers */
			g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_dissect_union_%s_%s_%s", ifname, union_name, case2str(bi->case_name), ti->str);
			ptmpstr=g_strdup(tmpstr);
			while(num_pointers--){
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_%s", ptmpstr, "unique");
				ptmpstr=g_strdup(tmpstr);
			}

			if(bi->flags&BI_CASE_DEFAULT){
				FPRINTF(eth_code, "    default:\n");
			} else {
				FPRINTF(eth_code, "    case %s:\n",bi->case_name);
			}
			/* each arm itself is aligned independently */
			switch(item_alignment){
			case 1:
				break;
			case 2:
				FPRINTF(eth_code, " 	   ALIGN_TO_2_BYTES;\n");
				break;
			case 4:
				FPRINTF(eth_code, " 	   ALIGN_TO_4_BYTES;\n");
				break;
			case 8:
				FPRINTF(eth_code, " 	   ALIGN_TO_8_BYTES;\n");
				break;
			default:
				FPRINTF(stderr, "ERROR: typedefunion 3 can not handle alignment:%d\n",item_alignment);
				Exit(10);
			}
			FPRINTF(eth_code, " 	   offset=%s(tvb, offset, pinfo, tree, di, drep);\n", ptmpstr);
			FPRINTF(eth_code, " 	   break;\n");
			FPRINTF(eth_code, "\n");
		}
		ti=ti->next;

		if(g_strcmp0(ti->str,";")){
			FPRINTF(stderr, "ERROR: field does not end with ';'\n");
			Exit(10);
		}
		ti=ti->next;
	}

	if(pass==1){
		FPRINTF(eth_code, "    }\n");
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "    proto_item_set_len(item, offset-old_offset);\n");
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "   return offset;\n");
		FPRINTF(eth_code, "}\n");
		switch(tag_alignment){
		case 2:
			register_new_type(union_name, dissectorname, "FT_UINT16", "BASE_DEC", "0", "NULL", alignment);
			break;
		case 4:
			register_new_type(union_name, dissectorname, "FT_UINT32", "BASE_DEC", "0", "NULL", alignment);
			break;
		default:
			FPRINTF(stderr, "ERROR: typedefunion 4 can not handle alignment:%d\n",alignment);
			Exit(10);
		}
	}

	FPRINTF(NULL,"\nEND UNION:%s pass:%d\n-------\n",union_name,pass);

	/* only advance token_list for pass==1
	   ti now points to the '}' token
	*/
	if(pass==1){
		if(!ti || g_strcmp0(ti->str,"}")){
			FPRINTF(stderr, "ERROR: union does not end with '}'\n");
			Exit(10);
		}
		ti=ti->next;

		/* just skip the name */
		ti=ti->next;

		if(!ti || g_strcmp0(ti->str,";")){
			FPRINTF(stderr, "ERROR: union does not end with ';'\n");
			Exit(10);
		}
		ti=ti->next;

		token_list=ti;
	}
}


/* this function will parse a
	   WERROR function (
   construct and generate the appropriate code.
   the function will be g_removed from the token_list once it has been processed
   the function assumes that the function is the first object in the token_list
   the function will be called three times with
	 pass=0   generate subdissectors and entries for the function table
	 pass=1   generate code for the REQUEST
	 pass=2   generate code for the REPLY
*/
static void parsefunction(int pass)
{
	char *function_name;
	static int funcno=0;
	token_item_t *ti;
	bracket_item_t *bi=NULL;
	pointer_item_t *pi;
	const char *pointer_type;

	char tmpstr[BASE_BUFFER_SIZE], *ptmpstr;
	int level, num_pointers;
	type_item_t *type_item;
	char hf_index[BASE_BUFFER_SIZE];

	ti=token_list;
	if(g_strcmp0(ti->str, "WERROR")){
		FPRINTF(stderr, "ERROR: function  first token is not 'WERROR'\n");
		Exit(10);
	}
	ti=ti->next;

	function_name=ti->str;
	ti=ti->next;

	if(g_strcmp0(ti->str, "(")){
		FPRINTF(stderr, "ERROR: function  third token is not '('\n");
		Exit(10);
	}
	ti=ti->next;

	FPRINTF(NULL,"\nFUNCTION:%s pass:%d\n-------\n",function_name,pass);

	if(pass==0){
		FPRINTF(eth_ft, "	 { %d, \"%s\",\n",funcno,function_name);
		FPRINTF(eth_ft, "		 %s_dissect_%s_request,\n", ifname, function_name);
		FPRINTF(eth_ft, "		 %s_dissect_%s_response },\n", ifname, function_name);
		funcno++;
	}

	/* pass 1,2  generate header for the function dissector */
	if((pass==1)||(pass==2)){
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "static int\n");
		FPRINTF(eth_code, "%s_dissect_%s_%s(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)\n", ifname, function_name, (pass==1)?"request":"response");
		FPRINTF(eth_code, "{\n");
	}

	/* scan the struct and create all subdissectors */
	level=0;
	while(ti){
		if(!g_strcmp0(ti->str, "(")){
			ti=ti->next;
			level++;
			continue;
		}
		if(!g_strcmp0(ti->str, ")")){
			if(!level){
				break;
			}
			ti=ti->next;
			level--;
			continue;
		}
		if(!g_strcmp0(ti->str, "[")){
			ti=parsebrackets(ti, &bi);
			continue;
		}

		if(!bi){
			FPRINTF(stderr, "ERROR : function no brackets found for case\n");
			Exit(10);
		}

		/* make sure we catch when we havent implemented everything
		   yet.
		   we currently only know about IN and OUT flags
		*/
		if(bi->flags&(~(BI_IN|BI_OUT|BI_POINTER|BI_SIZE_IS|BI_LENGTH_IS))){
			FPRINTF(stderr, "ERROR: function unknown bracket flags encountered : 0x%08x\n",bi->flags);
			Exit(10);
		}
		if(!(bi->flags&(BI_IN|BI_OUT))){
			FPRINTF(stderr, "ERROR : function  parameter is neither in nor out\n");
			Exit(10);
		}

		/* handle the type, verify that we KNOW this type */
		type_item=find_type(ti->str);
		if(!type_item){
			FPRINTF(stderr, "ERROR : function unknown type %s\n",ti->str);
			Exit(10);
		}
		ti=ti->next;
		/* count the levels of pointers */
		for(num_pointers=0;!g_strcmp0(ti->str, "*");ti=ti->next){
			num_pointers++;
		}

		/* now that we know how many real poitner there were we must
		   prepend default pointers to the list so it has the right
		   length.
		*/
		pi=prepend_pointer_list(bi->pointer_list, num_pointers);

		g_snprintf(hf_index, BASE_BUFFER_SIZE, "hf_%s_%s_%s", ifname, function_name, ti->str);
		/* pass 0  generate subdissectors */
		if(pass==0){
			char filter_name[BASE_BUFFER_SIZE];
			const char *hf;

			g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_dissect_%s_%s", ifname, function_name, ti->str);
			ptmpstr=g_strdup(tmpstr);

			g_snprintf(filter_name, BASE_BUFFER_SIZE, "%s.%s.%s", ifname, function_name, ti->str);
			hf=register_hf_field(hf_index, ti->str, filter_name, type_item->ft_type, type_item->base_type, type_item->vals, type_item->mask, "");

			FPRINTF(eth_code, "static int\n");
			FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", ptmpstr);
			FPRINTF(eth_code, "{\n");
			FPRINTF(eth_code, "    guint32 param=%s;\n",find_dissector_param_value(ptmpstr));
			FPRINTF(eth_code, "    offset=%s(tvb, offset, pinfo, tree, di, drep, %s, param);\n", type_item->dissector, hf);
			FPRINTF(eth_code, "    return offset;\n");
			FPRINTF(eth_code, "}\n");
			FPRINTF(eth_code, "\n");


			/* handle switch_is */
			if(bi){
			  switch(bi->flags&(BI_SIZE_IS|BI_LENGTH_IS)){
			  case 0:
				break;
			  case BI_SIZE_IS|BI_LENGTH_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "ucvarray_%s", ptmpstr);
				FPRINTF(eth_code, "static int\n");
				FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				FPRINTF(eth_code, "{\n");
				FPRINTF(eth_code, "    offset=dissect_ndr_ucvarray(tvb, offset, pinfo, tree, di, drep, %s);\n", ptmpstr);
				FPRINTF(eth_code, "    return offset;\n");
				FPRINTF(eth_code, "}\n");
				FPRINTF(eth_code, "\n");
				ptmpstr=g_strdup(tmpstr);
				break;
			  case BI_SIZE_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "ucarray_%s", ptmpstr);
				FPRINTF(eth_code, "static int\n");
				FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				FPRINTF(eth_code, "{\n");
				FPRINTF(eth_code, "    offset=dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, %s);\n", ptmpstr);
				FPRINTF(eth_code, "    return offset;\n");
				FPRINTF(eth_code, "}\n");
				FPRINTF(eth_code, "\n");
				ptmpstr=g_strdup(tmpstr);
				break;
			  default:
				FPRINTF(stderr, "ERROR: typedeffunction can not handle this combination of sizeis/lengthis\n");
				Exit(10);
			  }
			}

			/* handle pointers */
			while(num_pointers--){
				pointer_type=pi->type;
				pi=pi->next;
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_%s", pointer_type, ptmpstr);
				FPRINTF(eth_code, "static int\n");
				FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)\n", tmpstr);
				FPRINTF(eth_code, "{\n");
				FPRINTF(eth_code, "    offset=dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, %s, %s, \"%s\", -1);\n", ptmpstr, ptr_to_define(pointer_type), ti->str);
				FPRINTF(eth_code, "    return offset;\n");
				FPRINTF(eth_code, "}\n");
				FPRINTF(eth_code, "\n");

				ptmpstr=g_strdup(tmpstr);

			}
		}

		if((pass==1)||(pass==2)){
			g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_dissect_%s_%s", ifname, function_name, ti->str);
			ptmpstr=g_strdup(tmpstr);

			if(bi){
			  switch(bi->flags&(BI_SIZE_IS|BI_LENGTH_IS)){
			  case 0:
				break;
			  case BI_SIZE_IS|BI_LENGTH_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "ucvarray_%s", ptmpstr);
				ptmpstr=g_strdup(tmpstr);
				break;
			  case BI_SIZE_IS:
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "ucarray_%s", ptmpstr);
				ptmpstr=g_strdup(tmpstr);
				break;
			  default:
				FPRINTF(stderr, "ERROR: typedeffunction can not handle this combination of sizeis/lengthis\n");
				Exit(10);
			  }
			}

			/* handle pointers */
			while(num_pointers--){
				pointer_type=pi->type;
				pi=pi->next;
				g_snprintf(tmpstr, BASE_BUFFER_SIZE, "%s_%s", pointer_type, ptmpstr);
				ptmpstr=g_strdup(tmpstr);
			}

			if((pass==1)&&(bi->flags&BI_IN)){
				FPRINTF(eth_code, " 	   offset=%s(tvb, offset, pinfo, tree, di, drep);\n", ptmpstr);
				FPRINTF(eth_code, " 	   offset=dissect_deferred_pointers(pinfo, tvb, offset, di, drep);\n");
				FPRINTF(eth_code, "\n");
			}
			if((pass==2)&&(bi->flags&BI_OUT)){
				FPRINTF(eth_code, " 	   offset=%s(tvb, offset, pinfo, tree, di, drep);\n", ptmpstr);
				FPRINTF(eth_code, " 	   offset=dissect_deferred_pointers(pinfo, tvb, offset, di, drep);\n");
				FPRINTF(eth_code, "\n");
			}
		}
		ti=ti->next;


		if(!g_strcmp0(ti->str,",")){
			ti=ti->next;
			continue;
		}
	}

	if((pass==1)||(pass==2)){
		if(pass==2){
			FPRINTF(eth_code, "   offset=dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, %s, NULL);\n", hf_status);
			FPRINTF(eth_code, "\n");
		}
		FPRINTF(eth_code, "\n");
		FPRINTF(eth_code, "   return offset;\n");
		FPRINTF(eth_code, "}\n");
	}

	FPRINTF(NULL,"\nEND FUNCTION:%s pass:%d\n-------\n",function_name,pass);

	/* only advance token_list for pass==2
	   ti now points to the ')' token
	*/
	if(pass==2){
		if(!ti || g_strcmp0(ti->str,")")){
			FPRINTF(stderr, "ERROR: function does not end with ')'\n");
			Exit(10);
		}
		ti=ti->next;

		if(!ti || g_strcmp0(ti->str,";")){
			FPRINTF(stderr, "ERROR: function does not end with ';'\n");
			Exit(10);
		}
		ti=ti->next;

		token_list=ti;
	}
}


/* this function will parse a
	   typedef enum {
   or a
	   typedef [ v1_enum ] enum {
   construct and generate the appropriate code.
   the typedef will be g_removed from the token_list once it has been processed
   the function assumes that the typedef is the first object in the token_list
*/
static void parsetypedefenum(void)
{
	token_item_t *ti;
	enum_list_t *enum_list, *el, *lastel;
	char *p;
	long val;
	int eval, enumsize;
	char dissectorname[BASE_BUFFER_SIZE], valsstring[BASE_BUFFER_SIZE], hfvalsstring[BASE_BUFFER_SIZE];

	enumsize=16;

	ti=token_list;
	if(g_strcmp0(ti->str, "typedef")){
		FPRINTF(stderr, "ERROR: typedefenum  first token is not 'typedef'\n");
		Exit(10);
	}
	ti=ti->next;

	/* this could be a [ v1_enum ] */
	if(!g_strcmp0(ti->str, "[")){
		ti=ti->next;

		if(g_strcmp0(ti->str, "v1_enum")){
			FPRINTF(stderr, "ERROR: typedefenum  not 'v1_enum' inside brackets\n");
			Exit(10);
		}
		ti=ti->next;

		if(g_strcmp0(ti->str, "]")){
			FPRINTF(stderr, "ERROR: typedefenum  'v1_enum' is not followed by ']'\n");
			Exit(10);
		}
		ti=ti->next;

		enumsize=32;
	}


	if(g_strcmp0(ti->str, "enum")){
		FPRINTF(stderr, "ERROR: typedefenum  second token is not 'enum'\n");
		Exit(10);
	}
	ti=ti->next;

	if(g_strcmp0(ti->str, "{")){
		FPRINTF(stderr, "ERROR: typedefenum  third token is not '{'\n");
		Exit(10);
	}
	ti=ti->next;

	/* now parse all values until we find the "}" */
	eval=0;
	enum_list=NULL;
	lastel=NULL;
	while(1){
		/* check for '}' */
		if(!g_strcmp0(ti->str,"}")){
			ti=ti->next;
			break;
		}

		/* handle 4 types of entries:
		 * 1, CONST = value,
		 * 2, CONST,
		 * 3, CONST = value}
		 * 4, CONST}
		 */
		el=g_new0(enum_list_t, 1);
		if (!el) {
			FPRINTF(stderr, "Can't allocate memory. Exit.\n");
			exit(10);
		}
		el->next=NULL;
		if(!enum_list){
			enum_list=el;
		} else {
			lastel->next=el;
		}
		lastel=el;

		/* grab CONST */
		el->name=ti->str;
		ti=ti->next;

		/* grab separator */
		if(!g_strcmp0(ti->str,"=")){
			ti=ti->next;
			/* grab value */
			val=strtol(ti->str,&p,0);
			if (p==ti->str||*p) {
				FPRINTF(stderr, "ERROR: typedefenum value is not a number\n");
				Exit(10);
			}
			el->val=(int)val;
			ti=ti->next;
		} else {
			el->val=eval;
		}
		eval=el->val+1;

		/* check for ',' */
		if(!g_strcmp0(ti->str,",")){
			ti=ti->next;
			continue;
		}

		/* check for '}' */
		if(!g_strcmp0(ti->str,"}")){
			ti=ti->next;
			break;
		}

		FPRINTF(stderr,"ERROR: typedefenum should not be reached\n");
		Exit(10);
	}

	/* verify that it ends with a ';' */
	if(g_strcmp0(ti->next->str,";")){
		FPRINTF(stderr,"ERROR enum terminator is not ';'\n");
		Exit(10);
	}

	g_snprintf(valsstring, BASE_BUFFER_SIZE, "%s_%s_vals", ifname, ti->str);
	g_snprintf(dissectorname, DISSECTORNAME_MAXLEN, "%s_dissect_%s", ifname, ti->str);

	FPRINTF(NULL,"\nENUM:%s\n-------\n",ti->str);

	FPRINTF(eth_hdr, "\n");
	for(el=enum_list;el;el=el->next){
		FPRINTF(eth_hdr, "#define %s		%d\n", el->name, el->val);
	}

	FPRINTF(eth_hdr, "\n");
	FPRINTF(eth_hdr, "extern const value_string %s[];\n", valsstring);
	FPRINTF(eth_hdr, "int %s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param);\n", dissectorname);

	FPRINTF(eth_code, "\n");
	FPRINTF(eth_code, "const value_string %s[] = {\n", valsstring);

	for(el=enum_list;el;el=el->next){
		FPRINTF(eth_code, "    { %d	, \"%s\" },\n", el->val, el->name);
	}
	FPRINTF(eth_code, "    { 0	, NULL }\n");
	FPRINTF(eth_code, "};\n");

	FPRINTF(eth_code, "\n");
	FPRINTF(eth_code, "int\n");
	FPRINTF(eth_code, "%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32 param _U_)\n", dissectorname);
	FPRINTF(eth_code, "{\n");
	switch(enumsize){
	case 16:
		FPRINTF(eth_code, "    offset=dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
		break;
	case 32:
		FPRINTF(eth_code, "    offset=dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, NULL);\n");
		break;
	default:
		FPRINTF(stderr,"ERROR enum unknown size\n");
		Exit(10);
	}

	FPRINTF(eth_code, "    return offset;\n");
	FPRINTF(eth_code, "}\n");
	FPRINTF(eth_code, "\n");


	g_snprintf(hfvalsstring, BASE_BUFFER_SIZE, "VALS(%s)", valsstring);
	switch(enumsize){
	case 16:
		register_new_type(ti->str, dissectorname, "FT_INT16", "BASE_DEC", "0", hfvalsstring, 2);
		break;
	case 32:
		register_new_type(ti->str, dissectorname, "FT_INT32", "BASE_DEC", "0", hfvalsstring, 4);
		break;
	default:
		FPRINTF(stderr,"ERROR enum unknown size\n");
		Exit(10);
	}

	FPRINTF(NULL,"\n----------\nEND ENUM:%s\n",ti->str);

	/* skip past the name and the ';' */
	token_list=ti->next->next;
}

typedef struct _trimmed_prefixes_t {
	struct _trimmed_prefixes_t *next;
	char *name;
} trimmed_prefixes_t;
static trimmed_prefixes_t *prefixes_to_trim=NULL;

static void preparetrimprefix(char *prefix_name)
{
	trimmed_prefixes_t *new_prefix;
	new_prefix=g_new0(trimmed_prefixes_t, 1);
	if (!new_prefix) {
		FPRINTF(stderr, "Can't allocate memory. Exit.\n");
		exit(10);
	}
	new_prefix->next=prefixes_to_trim;
	prefixes_to_trim=new_prefix;
	new_prefix->name=g_strdup(prefix_name);
}

static void
trimprefix(void)
{
	token_item_t *ti;
	trimmed_prefixes_t *pfx;
	size_t len;

	for(pfx=prefixes_to_trim;pfx;pfx=pfx->next){
		len=strlen(pfx->name);
		for(ti=token_list;ti;ti=ti->next){
			if(!strncmp(ti->str, pfx->name, len)){
				ti->str+=len;
			}
		}
	}
}

static int Exit(int code)
{
	FPRINTF(stderr, "The tokens remaining when aborting:\n");
	printtokenlist(10);

	exit(code);
}

static void usage(void)
{
	FPRINTF(stderr, "Usage: idl2wrs <interface>\n");
}

static void
mergefile(const char *name, FILE *outfile)
{
	FILE *infile;

	FPRINTF(outfile, "\n\n/* INCLUDED FILE : %s */\n", name);
	infile=g_fopen(name, "r");
	while(!feof(infile)){
		int ch;
		ch=fgetc(infile);
		if(ch!=-1){
			fputc(ch, outfile);
		}
	}
	fclose(infile);
	FPRINTF(outfile, "/* END OF INCLUDED FILE : %s */\n\n\n", name);
}



static char *
str_read_string(char *str, char **name)
{
	char tmpstr[BASE_BUFFER_SIZE], *strptr;
	int skip_blanks;
	int quoted_string;

	strptr=tmpstr;
	skip_blanks=1;
	quoted_string=0;
	while(1){
		if(!*str){
			*strptr=0;
			*name=g_strdup(tmpstr);
			return str;
		}
		if(skip_blanks){
			if( (*str==' ') || (*str=='\t') ){
				str++;
				continue;
			}
			if( *str=='"' ){
				str++;
				quoted_string=1;
			}
			skip_blanks=0;
			continue;
		}
		if( (*str==' ') || (*str=='\t') ){
			if(quoted_string){
				*strptr++ = *str++;
				continue;
			}
			*strptr=0;
			*name=g_strdup(tmpstr);
			return str;
		}
		if( (*str=='"') || (*str=='\n') ){
			*strptr=0;
			*name=g_strdup(tmpstr);
			return ++str;
		}
		*strptr++ = *str++;
	}
	return NULL;
}

static void
readcnffile(FILE *fh)
{
	char cnfline[4 * BASE_BUFFER_SIZE];

	FPRINTF(NULL, "Reading conformance file\n=======================\n");
	while(!feof(fh)){
		cnfline[0]=0;
		if(!fgets(cnfline, 4 * BASE_BUFFER_SIZE, fh) || !cnfline[0]){
			continue;
		}
		if(cnfline[0]=='#'){
			/* ignore all comments */
		} else if(!strncmp(cnfline, "NOEMIT", 6)){
			no_emit_item_t *nei;
			char *str, *name;

			str=cnfline+6;
			str_read_string(str, &name);
			nei=g_new0(no_emit_item_t, 1);
			if (!nei) {
				FPRINTF(stderr, "Can't allocate memory. Exit.\n");
				exit(10);
			}
			nei->next=no_emit_list;
			no_emit_list=nei;
			nei->name=name;
			FPRINTF(NULL, "NOEMIT : %s\n", nei->name);
		} else if(!strncmp(cnfline, "TYPE", 4)){
			char *name, *dissectorname, *ft_type, *base_type;
			char *mask, *valsstring, *al;
			char *str;
			int alignment;

			str=cnfline+4;
			str=str_read_string(str, &name);
			str=str_read_string(str, &dissectorname);
			str=str_read_string(str, &ft_type);
			str=str_read_string(str, &base_type);
			str=str_read_string(str, &mask);
			str=str_read_string(str, &valsstring);
			str_read_string(str, &al);
			alignment=atoi(al);

			FPRINTF(NULL, "TYPE : X%s,%sX\n", name, dissectorname);
			register_new_type(name, dissectorname, ft_type, base_type, mask, valsstring, alignment);
		} else if(!strncmp(cnfline, "PARAM_VALUE", 11)){
			char *dissectorname, *value;
			char *str;

			str=cnfline+11;
			str=str_read_string(str, &dissectorname);
			str_read_string(str, &value);

			FPRINTF(NULL, "PARAM_VALUE : %s=%s\n", dissectorname,value);
			register_dissector_param_value(dissectorname, value);
		} else if(!strncmp(cnfline, "HF_FIELD", 8)){
			char *hf_index, *title, *filter_name, *ft_type;
			char *base_type, *valsstring, *mask, *blurb;
			char *str;

			str=cnfline+8;
			str=str_read_string(str, &hf_index);
			str=str_read_string(str, &title);
			str=str_read_string(str, &filter_name);
			str=str_read_string(str, &ft_type);
			str=str_read_string(str, &base_type);
			str=str_read_string(str, &valsstring);
			str=str_read_string(str, &mask);
			str_read_string(str, &blurb);
			FPRINTF(NULL, "HF_FIELD: %s \"%s\"\n", hf_index, title);
			register_hf_field(hf_index, title, filter_name, ft_type, base_type, valsstring, mask, blurb);
		} else if(!strncmp(cnfline, "HF_RENAME", 9)){
			char *old_name, *new_name;
			char *str;

			str=cnfline+9;
			str=str_read_string(str, &old_name);
			str_read_string(str, &new_name);
			FPRINTF(NULL, "HF_RENAME: %s -> %s\n", old_name, new_name);
			register_hf_rename(old_name, new_name);
		} else if(!strncmp(cnfline, "UNION_TAG_SIZE", 14)){
			char *union_name, *union_tag;
			int union_tag_size;
			union_tag_size_item_t *utsi;
			char *str;

			str=cnfline+14;
			str=str_read_string(str, &union_name);
			str_read_string(str, &union_tag);
			union_tag_size=atoi(union_tag);
			FPRINTF(NULL, "UNION_TAG_SIZE: %s == %d\n", union_name, union_tag_size);
			utsi=g_new0(union_tag_size_item_t, 1);
			if (!utsi) {
				FPRINTF(stderr, "Can't allocate memory. Exit.\n");
				exit(10);
			}
			utsi->next=union_tag_size_list;
			union_tag_size_list=utsi;
			utsi->name=g_strdup(union_name);
			utsi->size=union_tag_size;
		} else if(!strncmp(cnfline, "STRIP_PREFIX", 12)){
			char *prefix_name;
			char *str;

			str=cnfline+12;
			str_read_string(str, &prefix_name);
			FPRINTF(NULL, "STRIP_PREFIX: %s\n", prefix_name);
			preparetrimprefix(prefix_name);
		} else {
			FPRINTF(stderr, "ERROR: could not parse cnf directive:%s\n",cnfline);
			exit(10);
		}
	}
}

int main(int argc, char *argv[])
{
	char idlfile[BASE_BUFFER_SIZE];
	char tmplfile[BASE_BUFFER_SIZE];
	char prefix_str[BASE_BUFFER_SIZE];
	bracket_item_t *bi;
	FILE *fh;

	if(argc!=2){
		usage();
		exit(0);
	}

	eth_code=g_fopen("ETH_CODE", "w");
	eth_hdr=g_fopen("ETH_HDR", "w");
	eth_hfarr=g_fopen("ETH_HFARR", "w");
	eth_hf=g_fopen("ETH_HF", "w");
	eth_ettarr=g_fopen("ETH_ETTARR", "w");
	eth_ett=g_fopen("ETH_ETT", "w");
	eth_ft=g_fopen("ETH_FT", "w");
	eth_handoff=g_fopen("ETH_HANDOFF", "w");

	g_snprintf(idlfile, BASE_BUFFER_SIZE, "%s.cnf", argv[1]);
	fh=g_fopen(idlfile,"r");
	if(fh){
		readcnffile(fh);
		fclose(fh);
	}

	g_snprintf(idlfile, BASE_BUFFER_SIZE, "%s.idl", argv[1]);
	fh=g_fopen(idlfile,"r");
	if(!fh){
		FPRINTF(stderr, "ERROR: could not open idl-file:%s\n", idlfile);
		Exit(0);
	}

	lineno=0;
	linepos=0;
	tokenize(fh);
	prune_keyword_parameters("size_is");
	prune_keyword_parameters("length_is");
	rename_tokens("NTSTATUS", "WERROR");
	rename_tokens("unistr_noterm", "unistr");
	rename_tokens("ascstr_noterm", "ascstr");
	rename_tokens("hyper", "uint64");
	FPRINTF(NULL,"\n\nParsing header:\n================\n");
	parseheader();

	/* some idl files prepend a lot of symbols with <ifname>_
	   search through the tokenlist and g_remove all such
	   prefixes
	*/
	g_snprintf(prefix_str, BASE_BUFFER_SIZE, "%s_", ifname);
	preparetrimprefix(prefix_str);
	trimprefix();

	/* this is the main loop, each iteration it tries to identify what
	   kind of construct is the first entry in the token_list and call
	   the appropriate handler
	*/
	while(1) {
		/* just skip any [ ] that starts a new construct */
		if( !g_strcmp0(token_list->str, "[") ){
			token_list=parsebrackets(token_list, &bi);
			continue;
		}

		/* typedef enum { */
		if( !g_strcmp0(token_list->str,"typedef")
		  &&!g_strcmp0(token_list->next->str,"enum") ){
			parsetypedefenum();
			continue;
		}

		/* typedef [ v1_enum ] enum { */
		if( !g_strcmp0(token_list->str,"typedef")
		  &&!g_strcmp0(token_list->next->str,"[")
		  &&!g_strcmp0(token_list->next->next->str,"v1_enum")
		  &&!g_strcmp0(token_list->next->next->next->str,"]")
		  &&!g_strcmp0(token_list->next->next->next->next->str,"enum") ){
			parsetypedefenum();
			continue;
		}

		/* const */
		if( !g_strcmp0(token_list->str,"const") ){
			parseconst();
			continue;
		}

		/* typedef struct { */
		if( !g_strcmp0(token_list->str,"typedef") ){
			token_item_t *tmpti;

			tmpti=token_list->next;
			if( !g_strcmp0(tmpti->str, "[") ){
				tmpti=parsebrackets(tmpti, &bi);
				/* do some sanity checks here of bi->flags */
			}
			if( !g_strcmp0(tmpti->str, "struct") ){
				parsetypedefstruct(0);
				parsetypedefstruct(1);
				continue;
			}
		}

		/* typedef union { */
		if( !g_strcmp0(token_list->str,"typedef") ){
			token_item_t *tmpti;

			tmpti=token_list->next;
			if( !g_strcmp0(tmpti->str, "[") ){
				tmpti=parsebrackets(tmpti, &bi);
				/* do some sanity checks here of bi->flags */
			}
			if( !g_strcmp0(tmpti->str, "union") ){
				parsetypedefunion(0);
				parsetypedefunion(1);
				continue;
			}
		}

		/* typedef bitmap { */
		if( !g_strcmp0(token_list->str,"typedef") ){
			token_item_t *tmpti;

			tmpti=token_list->next;
			if( !g_strcmp0(tmpti->str, "[") ){
				tmpti=parsebrackets(tmpti, &bi);
				/* do some sanity checks here of bi->flags */
			}
			if( !g_strcmp0(tmpti->str, "bitmap") ){
				parsetypedefbitmap(0);
				parsetypedefbitmap(1);
				continue;
			}
		}

		/* functions:  WERROR function '(' */
		if( !g_strcmp0(token_list->str,"WERROR")
		  &&!g_strcmp0(token_list->next->next->str,"(") ){
			parsefunction(0);
			parsefunction(1);
			parsefunction(2);
			continue;
		}

		/* declare ... ; */
		if( !g_strcmp0(token_list->str,"declare") ){
			skipdeclare();
			continue;
		}


		break;
	};


	fclose(eth_code);
	fclose(eth_hdr);
	fclose(eth_hf);
	fclose(eth_hfarr);
	fclose(eth_ett);
	fclose(eth_ettarr);
	fclose(eth_ft);
	fclose(eth_handoff);

	/* unless the token_list now only contains a single token : '}'
	   we have failed to compile the idl file properly
		*/
	if( g_strcmp0(token_list->str, "}") || token_list->next){
		FPRINTF(stderr, "ERROR: we did not process all tokens. Compiler is incomplete.\n===========================================\n");
		printtokenlist(10);
		exit(10);
	}

	check_hf_rename_refcount();

	/* merge code and template into dissector */
	g_snprintf(line, 4 * BASE_BUFFER_SIZE, "packet-dcerpc-%s.c", ifname);
	fh=g_fopen(line, "w");
	g_snprintf(tmplfile, BASE_BUFFER_SIZE, "packet-dcerpc-%s-template.c", argv[1]);
	tfh=g_fopen(tmplfile, "r");
	if(!tfh){
		FPRINTF(stderr, "ERROR: could not find %s\n", tmplfile);
		exit(10);
	}
	while(!feof(tfh)){
		line[0]=0;
		if(!fgets(line, 4 * BASE_BUFFER_SIZE, tfh) || !line[0]){
			continue;
		}
		if(!strncmp(line, "ETH_CODE", 8)){
			mergefile("ETH_CODE",fh);
		} else if(!strncmp(line, "ETH_HDR", 7)){
			mergefile("ETH_HDR",fh);
		} else if(!strncmp(line, "ETH_HFARR", 9)){
			mergefile("ETH_HFARR",fh);
		} else if(!strncmp(line, "ETH_HF", 6)){
			mergefile("ETH_HF",fh);
		} else if(!strncmp(line, "ETH_ETTARR", 10)){
			mergefile("ETH_ETTARR",fh);
		} else if(!strncmp(line, "ETH_ETT", 7)){
			mergefile("ETH_ETT",fh);
		} else if(!strncmp(line, "ETH_FT", 6)){
			mergefile("ETH_FT",fh);
		} else if(!strncmp(line, "ETH_HANDOFF", 11)){
			mergefile("ETH_HANDOFF",fh);
		} else {
			fputs(line, fh);
		}
	}
	fclose(fh);
	fclose(tfh);

	g_snprintf(line, 4 * BASE_BUFFER_SIZE, "packet-dcerpc-%s.h", ifname);
	fh=g_fopen(line, "w");
	g_snprintf(tmplfile, BASE_BUFFER_SIZE, "packet-dcerpc-%s-template.h", argv[1]);
	tfh=g_fopen(tmplfile, "r");
	if(!tfh){
		FPRINTF(stderr, "ERROR: could not find %s\n", tmplfile);
		exit(10);
	}
	while(!feof(tfh)){
		line[0]=0;
		if(!fgets(line, 4 * BASE_BUFFER_SIZE, tfh) || !line[0]){
			continue;
		}
		if(!strncmp(line, "ETH_CODE", 8)){
			mergefile("ETH_CODE",fh);
		} else if(!strncmp(line, "ETH_HDR", 7)){
			mergefile("ETH_HDR",fh);
		} else if(!strncmp(line, "ETH_HFARR", 9)){
			mergefile("ETH_HFARR",fh);
		} else if(!strncmp(line, "ETH_HF", 6)){
			mergefile("ETH_HF",fh);
		} else if(!strncmp(line, "ETH_ETTARR", 10)){
			mergefile("ETH_ETTARR",fh);
		} else if(!strncmp(line, "ETH_ETT", 7)){
			mergefile("ETH_ETT",fh);
		} else if(!strncmp(line, "ETH_FT", 6)){
			mergefile("ETH_FT",fh);
		} else if(!strncmp(line, "ETH_HANDOFF", 11)){
			mergefile("ETH_HANDOFF",fh);
		} else {
			fputs(line, fh);
		}
	}

	g_print("%s was successfully compiled\n", ifname);

	fclose(fh);
	fclose(tfh);

	if (g_remove("ETH_CODE") == -1) {
		FPRINTF(stderr, "Can't remove ETH_CODE");
	}
	if (g_remove("ETH_HDR") == -1) {
		FPRINTF(stderr, "Can't remove ETH_CODE");
	}
	if (g_remove("ETH_HFARR") == -1) {
		FPRINTF(stderr, "Can't remove ETH_CODE");
	}
	if (g_remove("ETH_HF") == -1) {
		FPRINTF(stderr, "Can't remove ETH_CODE");
	}
	if (g_remove("ETH_ETTARR") == -1) {
		FPRINTF(stderr, "Can't remove ETH_CODE");
	}
	if (g_remove("ETH_ETT") == -1) {
		FPRINTF(stderr, "Can't remove ETH_CODE");
	}
	if (g_remove("ETH_FT") == -1) {
		FPRINTF(stderr, "Can't remove ETH_CODE");
	}
	if (g_remove("ETH_HANDOFF") == -1) {
		FPRINTF(stderr, "Can't remove ETH_CODE");
	}


	return 0;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
