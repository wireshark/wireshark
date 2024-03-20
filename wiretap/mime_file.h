/** @file
 *
 * MIME file format decoder for the Wiretap library.
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_JPEG_JFIF_H__
#define __W_JPEG_JFIF_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val mime_file_open(wtap *wth, int *err, char **err_info);

#endif
