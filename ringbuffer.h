/* ringbuffer.h
 * Definitions for capture ringbuffer files
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RINGBUFFER_H__
#define __RINGBUFFER_H__

#include <stdio.h>
#include "wiretap/wtap.h"

#define RINGBUFFER_UNLIMITED_FILES 0
/* Minimum number of ringbuffer files */
#define RINGBUFFER_MIN_NUM_FILES 0
/* Maximum number of ringbuffer files */
/* Avoid crashes on very large numbers. Should be a power of 10 */
#define RINGBUFFER_MAX_NUM_FILES 100000
/* Maximum number for FAT filesystems */
#define RINGBUFFER_WARN_NUM_FILES 65535

int ringbuf_init(const char *capture_name, guint num_files, gboolean group_read_access);
gboolean ringbuf_is_initialized(void);
const gchar *ringbuf_current_filename(void);
FILE *ringbuf_init_libpcap_fdopen(int *err);
gboolean ringbuf_switch_file(FILE **pdh, gchar **save_file, int *save_file_fd,
                             int *err);
gboolean ringbuf_libpcap_dump_close(gchar **save_file, int *err);
void ringbuf_free(void);
void ringbuf_error_cleanup(void);
gboolean ringbuf_set_print_name(gchar *name, int *err);

#endif /* ringbuffer.h */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
