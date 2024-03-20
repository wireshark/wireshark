/** @file
 *
 * Transport-Neutral Encapsulation Format (TNEF) file reading
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __TNEF_H__
#define __TNEF_H__

#include <glib.h>
#include <wiretap/wtap.h>
#include "ws_symbol_export.h"

#define TNEF_SIGNATURE 0x223E9F78

wtap_open_return_val tnef_open(wtap *wth, int *err, char **err_info);

#endif
