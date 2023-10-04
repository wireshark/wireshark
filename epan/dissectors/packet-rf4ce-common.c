/* packet-rf4ce-common.c
 * Common functions and objects for RF4CE dissector
 * Copyright (C) Atmosic 2023
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-3.0-or-later WITH Bison-exception-2.2
 *
 * As a special exception, you may create a larger work that contains part or
 * all of the Bison parser skeleton and distribute that work under terms of
 * your choice, so long as that work isn't itself a parser generator using the
 * skeleton or a modified version thereof as a parser skeleton. Alternatively,
 * if you modify or redistribute the parser skeleton itself, you may (at your
 * option) remove this special exception, which will cause the skeleton and
 * the resulting Bison output files to be licensed under the GNU General
 * Public License without this special exception.
 *
 * This special exception was added by the Free Software Foundation in version
 * 2.2 of Bison.
 */

#include <epan/value_string.h>
#include "packet-rf4ce-common.h"

#define RF4CE_NO  0
#define RF4CE_YES 1

const value_string rf4ce_yes_no_vals[] = {
    { RF4CE_NO,  "No" },
    { RF4CE_YES, "Yes" },
    { 0, NULL }
};

#define RF4CE_DISABLED 0
#define RF4CE_ENABLED  1

const value_string rf4ce_en_dis_vals[] = {
    { RF4CE_ENABLED,  "Enabled" },
    { RF4CE_DISABLED, "Disabled" },
    { 0, NULL }
};

#ifdef RF4CE_DEBUG_EN
void rf4ce_print_arr(const gchar *str, guint8 *ptr, guint16 len)
{
  g_print("%s: ", str);
  for (guint16 i = 0; i < len-1; i++)
  {
    g_print("%02x:", *(ptr+i));
  }
  g_print("%02x\n", *(ptr+len-1));
}
#endif /* RF4CE_DEBUG_EN */
