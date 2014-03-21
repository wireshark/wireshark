/* conversation_debug.h
 * A file of debug printing stuff for conversation-related things,
 * although really anything can use this so long as it includes this
 * header file and defines DEBUG_CONVERSATION in conversation.c
 *
 * define DEBUG_CONVERSATION before including this file to turn on printing
 * and also define it in conversation.c (because it has the indent variable)
 *
 * By Hadriel Kaplan <hadrielk at yahoo dot com>
 * Copyright 2014 Hadriel Kaplan
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

#ifndef _CONVERSATION_DEBUG_H
#define _CONVERSATION_DEBUG_H

#ifdef DEBUG_CONVERSATION

#include <stdio.h>
#include "to_str.h"

extern int _debug_conversation_indent; /* the instance is in conversation.c */

#define DINDENT() _debug_conversation_indent += 4
#define DENDENT() _debug_conversation_indent -= 4

#define DPRINT(arg) \
          g_printerr("%*.*s%s: ", \
                     _debug_conversation_indent,_debug_conversation_indent," ", \
                     G_STRLOC); \
          g_printerr arg; \
          g_printerr("\n")

#define DPRINT2(arg) \
          g_printerr("%*.*s", \
                     _debug_conversation_indent,_debug_conversation_indent," "); \
          g_printerr arg; \
          g_printerr("\n")

#else /* !DEBUG_CONVERSATION */

/* a hack to let these defines be used with trailing semi-colon and not
 * cause gcc extra-check pedantic warnings for extra colons
 */
#define DINDENT() (void)0
#define DENDENT() (void)0
#define DPRINT(arg) (void)0
#define DPRINT2(arg) (void)0

#endif /* DEBUG_CONVERSATION */

#endif /* _CONVERSATION_DEBUG_H */
