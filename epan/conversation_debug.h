
/* a file of debug printing stuff for conversation-related things,
 * although really anything can use this so long as it includes this
 *
 * define DEBUG_CONVERSATION before including this file to turn on printing
 * and also define it in conversation.c (because it has the indent variable)
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
