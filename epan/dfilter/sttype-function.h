/*
 * $Id: sttype-test.h 11400 2004-07-18 00:24:25Z guy $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
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
 */

#ifndef STTYPE_FUNCTION_H
#define STTYPE_FUNCTION_H

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
