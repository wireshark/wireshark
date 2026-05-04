/** @file
 *
 * MIME file format decoder for the Wiretap library.
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NETTRACE_3GPP_32_423__
#define __NETTRACE_3GPP_32_423__

#include "wtap.h"

/**
 * @brief Open a 3GPP TS 32.423 file for reading.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error message if an error occurs.
 * @return wtap_open_return_val Result of opening the file.
 */
wtap_open_return_val nettrace_3gpp_32_423_file_open(wtap *wth, int *err, char **err_info);

#endif
