/*
 ** diam_dict.h
 ** Diameter Dictionary Import Routines
 **
 ** $Id$
 **
 ** (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
 **
 ** This library is free software; you can redistribute it and/or
 ** modify it under the terms of the GNU Library General Public
 ** License as published by the Free Software Foundation; either
 ** version 2 of the License, or (at your option) any later version.
 **
 ** This library is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 ** Library General Public License for more details.
 **
 ** You should have received a copy of the GNU Library General Public
 ** License along with this library; if not, write to the
 ** Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 ** Boston, MA  02111-1307, USA.
 */

#ifndef _DIAM_DICT_H_
#define _DIAM_DICT_H_

struct _ddict_namecode_t {
	char* name;
	unsigned code;
	struct _ddict_namecode_t* next;	
};

typedef struct _ddict_namecode_t ddict_gavp_t;
typedef struct _ddict_namecode_t ddict_enum_t;
typedef struct _ddict_namecode_t ddict_application_t;

typedef struct _ddict_vendor_t {
	char* name;
	char* desc;
	unsigned code;
	struct _ddict_vendor_t* next;	
} ddict_vendor_t;

typedef struct _ddict_avp_t {
	char* name;
	char* description;
	char* vendor;
	char* type;
	unsigned code;
	ddict_gavp_t* gavps;
	ddict_enum_t* enums;
	struct _ddict_avp_t* next;
} ddict_avp_t;

typedef struct _ddict_typedefn_t {
	char* name;
	char* parent;
	struct _ddict_typedefn_t* next;
} ddict_typedefn_t;

typedef struct _ddict_cmd_t {
	char* name;
	char* vendor;
	unsigned code;
	struct _ddict_cmd_t* next;
} ddict_cmd_t;

typedef struct _ddict_xmlpi_t {
	char* name;
	char* key;
	char* value;
	struct _ddict_xmlpi_t* next;
} ddict_xmlpi_t;

typedef struct _ddict_t {
	ddict_application_t* applications;
	ddict_vendor_t* vendors;
	ddict_cmd_t* cmds;
	ddict_typedefn_t* typedefns;
	ddict_avp_t* avps;
	ddict_xmlpi_t* xmlpis;
} ddict_t;

extern void ddict_print(FILE* fh, ddict_t* d);
extern ddict_t* ddict_scan(const char* directory, const char* filename, int dbg);
extern void ddict_free(ddict_t* d);

#endif
