/*
 * $Id: dfilter-int.h,v 1.5 2002/01/21 07:37:37 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2001 Gerald Combs
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
 */

#ifndef DFILTER_INT_H
#define DFILTER_INT_H

#include "dfilter.h"
#include "syntax-tree.h"

#include <epan/proto.h>

/* Passed back to user */
struct _dfilter_t {
	GPtrArray	*insns;
	int		num_registers;
	GList		**registers;
	gboolean	*attempted_load;
    int         *interesting_fields;
    int         num_interesting_fields;
};

typedef struct {
	/* Syntax Tree stuff */
	stnode_t	*st_root;
	gboolean	syntax_error;
	GPtrArray	*insns;
	GHashTable	*loaded_fields;
	GHashTable	*interesting_fields;
	int		next_insn_id;
	int		next_register;
} dfwork_t;

/* Constructor/Destructor prototypes for Lemon Parser */
void *DfilterAlloc(void* (*)(gulong));
void DfilterFree(void*, void (*)(void *));
void Dfilter(void*, int, stnode_t*, dfwork_t*);

/* Scanner's lval */
extern stnode_t *df_lval;

/* Given a field abbreviation, returns the proto ID, or -1 if
 * it doesn't exist. */
header_field_info*
dfilter_lookup_token(char *abbrev);

/* Set dfilter_error_msg_buf and dfilter_error_msg */
void
dfilter_fail(char *format, ...);


#endif
