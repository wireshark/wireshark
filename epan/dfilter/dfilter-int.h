/* dfilter-int.h
 * Header information for use by multiple files in the dfilter submodule.
 *
 * $Id: dfilter-int.h,v 1.1 2001/02/01 20:21:18 gram Exp $
 *
 */

#ifndef DFILTER_INT_H
#define DFILTER_INT_H

#include "dfilter.h"
#include "syntax-tree.h"

#include "proto.h"

/* Passed back to user */
struct _dfilter_t {
	GPtrArray	*insns;
	int		num_registers;
	GList		**registers;
	gboolean	*attempted_load;
};

typedef struct {
	/* Syntax Tree stuff */
	stnode_t	*st_root;
	gboolean	syntax_error;
	GPtrArray	*insns;
	GHashTable	*loaded_fields;
	int		next_insn_id;
	int		next_register;
} dfwork_t;

/* Constructor/Destructor prototypes for Lemon Parser */
void *DfilterAlloc(void* (*)());
void DfilterFree(void*, void (*)());
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
