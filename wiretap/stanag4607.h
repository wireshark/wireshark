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

/**
 * @brief Opens a STANAG 4607 file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val stanag4607_open(wtap *wth, int *err, char **err_info);

#endif
