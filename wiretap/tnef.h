/** @file
 *
 * Transport-Neutral Encapsulation Format (TNEF) file reading
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __TNEF_H__
#define __TNEF_H__

#include "wtap.h"

#define TNEF_SIGNATURE 0x223E9F78

/**
 * @brief Open a TNEF file.
 *
 * Attempts to open and read the header of a TNEF (Transport Neutral Encapsulation Format) file.
 *
 * @param wth Pointer to the wtap structure that will hold the file information.
 * @param err Pointer to an integer where any error code will be stored.
 * @param err_info Pointer to a char pointer where any error message will be stored.
 * @return wtap_open_return_val The result of the open operation, indicating whether the file is TNEF or not.
 */
wtap_open_return_val tnef_open(wtap *wth, int *err, char **err_info);

#endif
