/* ber.h
 *
 * Basic Encoding Rules (BER) file reading
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __BER_H__
#define __BER_H__
#include <glib.h>
#include "ws_symbol_export.h"

wtap_open_return_val ber_open(wtap *wth, int *err, gchar **err_info);

#endif
