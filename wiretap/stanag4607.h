/** @file
 *
 * STANAG 4607 file reading
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __STANAG_4607_H__
#define __STANAG_4607_H__

#include "wtap.h"

wtap_open_return_val stanag4607_open(wtap *wth, int *err, char **err_info);

#endif
