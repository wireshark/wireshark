/* json.h
 *
 * Copyright 2015, Dario Lombardo <lomato@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __JSON_H__
#define __JSON_H__

#include <glib.h>

#include "wtap.h"

/*
 * Impose a not-too-large limit on the maximum file size, to avoid eating
 * up 99% of the (address space, swap partition, disk space for swap/page
 * files); if we were to return smaller chunks and let the dissector do
 * reassembly, it would *still* have to allocate a buffer the size of
 * the file, so it's not as if we'd neve try to allocate a buffer the
 * size of the file.
 *
 * For now, go for 50MB.
 */
#define MAX_FILE_SIZE  (50*1024*1024)

wtap_open_return_val json_open(wtap *wth, int *err, gchar **err_info);

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
