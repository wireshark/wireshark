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

/**
 * @brief Open a Basic Encoding Rules (BER) file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val ber_open(wtap *wth, int *err, char **err_info);

#endif
