/** @file
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RFC7468_H__
#define __RFC7468_H__

#include "wtap.h"

/**
 * @brief Open a file using RFC 7468 format.
 *
 * This function attempts to open and read an initial chunk of the file to detect if it matches the RFC 7468 format.
 *
 * @param wth Pointer to the wtap structure that will hold the file information.
 * @param err Pointer to an integer where any error code will be stored.
 * @param err_info Pointer to a char pointer where any error message will be stored.
 * @return A value indicating whether the file was successfully opened or not.
 */
wtap_open_return_val rfc7468_open(wtap *wth, int *err, char **err_info);

#endif

/*
* Editor modelines  -  https://www.wireshark.org/tools/modelines.html
*
* Local Variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* vi: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
