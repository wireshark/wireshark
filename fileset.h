/* fileset.h
 * Definitions for routines for file sets.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FILESET_H__
#define __FILESET_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _fileset_entry {
    char     *fullname;      /* File name with path (g_strdup'ed) */
    char     *name;          /* File name without path (g_strdup'ed) */
    time_t   ctime;          /* create time */
    time_t   mtime;          /* last modified time */
    gint64   size;           /* size of file in bytes */
    gboolean current;        /* is this the currently loaded file? */
} fileset_entry;


/* helper: is this a probable file of a file set (does the naming pattern match)? */
extern gboolean fileset_filename_match_pattern(const char *fname);

extern void fileset_add_dir(const char *fname, void *window);

extern void fileset_delete(void);

/* get the current directory name */
extern const char *fileset_get_dirname(void);

extern fileset_entry *fileset_get_next(void);
extern fileset_entry *fileset_get_previous(void);

/**
 * Add an entry to our dialog / window. Called by fileset_update_dlg.
 * Must be implemented in the UI.
 *
 * @param entry The new fileset entry.
 * @param window Window / dialog reference provided by the UI code.
 */
extern void fileset_dlg_add_file(fileset_entry *entry, void *window);

/**
 * Notify our dialog / window that we're about to add files. Called by fileset_update_dlg.
 * Must be implemented in the UI.
 *
 * @param window Window / dialog reference provided by the UI code.
 */
extern void fileset_dlg_begin_add_file(void *window);

/**
 * Notify our dialog / window that we're done adding files. Called by fileset_update_dlg.
 * Must be implemented in the UI.
 *
 * @param window Window / dialog reference provided by the UI code.
 */
extern void fileset_dlg_end_add_file(void *window);

extern void fileset_update_dlg(void *window);

extern void fileset_update_file(const char *path);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILESET_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
