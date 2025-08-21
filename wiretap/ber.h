/** @file
 *
 * Basic Encoding Rules (BER) file reading
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __BER_H__
#define __BER_H__

#include "wtap.h"

wtap_open_return_val ber_open(wtap *wth, int *err, char **err_info);

#endif
