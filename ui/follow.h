/* follow.h
 * Common routines for following data streams (qt/gtk)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __FOLLOW__H__
#define __FOLLOW__H__

#include "glib.h"

#include <epan/follow.h>
#include <epan/dissectors/packet-ipv6.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/charsets.h>
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#include <epan/ipproto.h>
#include <epan/charsets.h>

#include "config.h"
#include "globals.h"
#include "file.h"

#include "version_info.h"

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#ifdef SSL_PLUGIN
#include "packet-ssl-utils.h"
#else
#include <epan/dissectors/packet-ssl-utils.h>
#endif

#ifndef QT_CORE_LIB
#include <gtk/gtk.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    gboolean   is_from_server;
    StringInfo data;
} SslDecryptedRecord;

/* Type of follow we are doing */
typedef enum {
    FOLLOW_TCP,
    FOLLOW_SSL,
    FOLLOW_UDP
} follow_type_t;

/* Show Stream */
typedef enum {
    FROM_CLIENT,
    FROM_SERVER,
    BOTH_HOSTS
} show_stream_t;

/* Show Type */
typedef enum {
    SHOW_ASCII,
    SHOW_EBCDIC,
    SHOW_HEXDUMP,
    SHOW_CARRAY,
    SHOW_RAW
} show_type_t;

typedef enum {
    FRS_OK,
    FRS_OPEN_ERROR,
    FRS_READ_ERROR,
    FRS_PRINT_ERROR
} frs_return_t;

typedef struct {
    gboolean is_server;
    GByteArray *data;
} follow_record_t;

char *
sgetline(char *str, int *next);

gboolean
parse_http_header(char *data, size_t len, size_t *content_start);

#ifdef __cplusplus
}
#endif

#endif

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
