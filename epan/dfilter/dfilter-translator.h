/** @file
 *
 * Wireshark - Network traffic analyzer
 *
 * Copyright 1998 Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <glib.h>
#include <epan/dfilter/syntax-tree.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* The run-time logic of the dfilter function */
typedef bool (*DFTranslator)(stnode_t *root_node, GString *translated);


/** Initialize our built-in translators
 */
void dfilter_translator_init(void);

/** Clean up our built-in translators
 */
void dfilter_translator_cleanup(void);

/** Register a display filter translator
 * @param translator_name A unique, proper name for the translator, suitable for display.
 * @param translator A function which will handle translating the syntax tree.
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC
bool register_dfilter_translator(const char *translator_name, DFTranslator translator);

/** Deregister a display filter translator
 * @param translator_name The name provided in register_dfilter_translator.
 */
WS_DLL_PUBLIC
void deregister_dfilter_translator(const char *translator_name);

/** Get the current translator list
 * @return A NULL terminated array of translator names.
 * The return value must be g_freed, but the names themselves must not be g_freed.
 */
WS_DLL_PUBLIC
char **get_dfilter_translator_list(void);

/** Translate a display filter.
 *
 * The root node and data pointer will be passed to the
 * @param translator_name The name of a registered translator.
 * @param dfilter The Wireshark display filter to translate.
 * @return A translated filter or rule on success, NULL on failure.
 */
WS_DLL_PUBLIC
const char *translate_dfilter(const char *translator_name, const char *dfilter);

#ifdef __cplusplus
}
#endif /* __cplusplus */
