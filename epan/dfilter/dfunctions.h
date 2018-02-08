/*
 * Wireshark - Network traffic analyzer
 *
 * Copyright 2006 Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFUNCTIONS_H
#define DFUNCTIONS_H

#include <glib.h>
#include <ftypes/ftypes.h>
#include "syntax-tree.h"

/* The run-time logic of the dfilter function */
typedef gboolean (*DFFuncType)(GList *arg1list, GList *arg2list, GList **retval);

/* The semantic check for the dfilter function */
typedef void (*DFSemCheckType)(dfwork_t *dfw, int param_num, stnode_t *st_node);

/* If a function needs more args than this, increase
 * this macro and add more arg members to the dfvm_insn_t
 * struct in dfvm.h, and add some logic to dfw_append_function()
 * and dfvm_apply() */
#define DFUNCTION_MAX_NARGS 2

/* This is a "function definition" record, holding everything
 * we need to know about a function */
typedef struct {
    const char      *name;
    DFFuncType      function;
    ftenum_t        retval_ftype;
    guint           min_nargs;
    guint           max_nargs;
    DFSemCheckType  semcheck_param_function;
} df_func_def_t;

/* Return the function definition record for a function of named "name" */
df_func_def_t* df_func_lookup(char *name);

#endif
