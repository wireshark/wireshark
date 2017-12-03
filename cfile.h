/* cfile.h
 * capture_file definition & GUI-independent manipulation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __CFILE_H__
#define __CFILE_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Current state of file. */
typedef enum {
  FILE_CLOSED,                  /* No file open */
  FILE_READ_IN_PROGRESS,        /* Reading a file we've opened */
  FILE_READ_ABORTED,            /* Read aborted by user */
  FILE_READ_DONE                /* Read completed */
} file_state;

/* Character set for text search. */
typedef enum {
  SCS_NARROW_AND_WIDE,
  SCS_NARROW,
  SCS_WIDE
  /* add EBCDIC when it's implemented */
} search_charset_t;

typedef enum {
  SD_FORWARD,
  SD_BACKWARD
} search_direction;

struct _capture_file;
typedef struct _capture_file capture_file;

extern void cap_file_init(capture_file *cf);

extern const char *cap_file_get_interface_name(capture_file *cf, guint32 interface_id);
extern const char *cap_file_get_interface_description(capture_file *cf, guint32 interface_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* cfile.h */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
