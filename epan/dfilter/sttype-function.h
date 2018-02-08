/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STTYPE_FUNCTION_H
#define STTYPE_FUNCTION_H

#include "dfilter-int.h"
#include "dfunctions.h"

/* Set the parameters for a function stnode_t. */
void
sttype_function_set_params(stnode_t *node, GSList *params);

/* Get the function-definition record for a function stnode_t. */
df_func_def_t* sttype_function_funcdef(stnode_t *node);

/* Get the parameters for a function stnode_t. */
GSList* sttype_function_params(stnode_t *node);

/* Free the memory of a param list */
void st_funcparams_free(GSList *params);

#endif
