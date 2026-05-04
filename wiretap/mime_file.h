/** @file
 *
 * MIME file format decoder for the Wiretap library.
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_JPEG_JFIF_H__
#define __W_JPEG_JFIF_H__

#include "wtap.h"

/**
 * @brief Open a MIME file for reading.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val Return value indicating success or failure.
 */
wtap_open_return_val mime_file_open(wtap *wth, int *err, char **err_info);

#endif
