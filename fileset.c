/* fileset.c
 * Routines for handling file sets
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/ws_assert.h>

#include <wiretap/wtap.h>

#include <epan/strutil.h>

#include "fileset.h"

typedef struct _fileset {
    GList   *entries;
    char    *dirname;
} fileset;

/*
 * This is the fileset's global data.
 *
 * XXX This should probably be per-main-window instead of global.
 */
static fileset set;

/*
 * Given a stat structure, get the creation time of the file if available,
 * or 0 if not.
 */
#ifdef _WIN32
  /* Microsoft's documentation says this is the creation time */
  #define ST_CREATE_TIME(statb) ((statb).st_ctime)
#else /* _WIN32 */
  /* UN*X - do we have a creation time? */
  #if defined(HAVE_STRUCT_STAT_ST_BIRTHTIME)
    #define ST_CREATE_TIME(statb) ((statb).st_birthtime)
  #elif defined(HAVE_STRUCT_STAT___ST_BIRTHTIME)
    #define ST_CREATE_TIME(statb) ((statb).__st_birthtime)
  #else /* nothing */
    #define ST_CREATE_TIME(statb) (0)
  #endif /* creation time on UN*X */
#endif /* _WIN32 */

/* is this a probable file of a file set (does the naming pattern match)? */
fileset_match_t
fileset_filename_match_pattern(const char *fname, char **prefix, char **suffix, char **time)
{
    char        *sfx;
    char        *filename;
    fileset_match_t ret = FILESET_NO_MATCH;
    static char *pattern = "(?P<prefix>.*)_\\d{5}_(?P<time>\\d{14})$";
    static char *pattern2 = "(?P<prefix>.*)_(?P<time>\\d{14})_\\d{5}$";
    static GRegex *regex = NULL;
    static GRegex *regex2 = NULL;

    if (regex == NULL) {
        GError *gerr = NULL;
        regex = g_regex_new(pattern,
                        (GRegexCompileFlags)(G_REGEX_OPTIMIZE | G_REGEX_ANCHORED),
                        G_REGEX_MATCH_ANCHORED, &gerr);
        if (gerr) {
                ws_warning("failed to compile regex: %s", gerr->message);
                g_error_free(gerr);
                regex = NULL;
                return ret;
        }
    }

    if (regex2 == NULL) {
        GError *gerr = NULL;
        regex2 = g_regex_new(pattern2,
                        (GRegexCompileFlags)(G_REGEX_OPTIMIZE | G_REGEX_ANCHORED),
                        G_REGEX_MATCH_ANCHORED, &gerr);
        if (gerr) {
                ws_warning("failed to compile regex: %s", gerr->message);
                g_error_free(gerr);
                regex2 = NULL;
                return ret;
        }
    }

    /* d:\dir1\test_00001_20050418010750.cap */
    filename = g_path_get_basename(fname);

    /* test_00001_20050418010750.cap */
    sfx = strrchr(filename, '.');
    if (sfx != NULL) {
        *sfx = '\0';
        GSList *compression_type_extensions = wtap_get_all_compression_type_extensions_list();
        char *ext = g_ascii_strdown(sfx + 1, -1);
        for (GSList *compression_extension = compression_type_extensions;
                compression_extension != NULL;
                compression_extension = g_slist_next(compression_extension)) {
            if (g_strcmp0(ext, (const char*)compression_extension->data) == 0) {
                sfx = strrchr(filename, '.');
                if (sfx != NULL) {
                    *sfx = '\0';
                }
                break;
            }
        }
        g_free(ext);
        g_slist_free(compression_type_extensions);
    } else { /* suffix is optional */
        sfx = filename + strlen(filename);
    }

    /* test_00001_20050418010750 */

    GMatchInfo *match_info;
    g_regex_match(regex, filename, 0, &match_info);
    if (g_match_info_matches(match_info)) {
        if (prefix) {
            *prefix = g_match_info_fetch_named(match_info, "prefix");
        }
        if (time) {
            *time = g_match_info_fetch_named(match_info, "time");
        }
        if (suffix) {
            *suffix = g_strdup(sfx);
        }
        ret = FILESET_NUM_TIME;
    }
    g_match_info_free(match_info);

    if (ret == FILESET_NO_MATCH) {
        g_regex_match(regex2, filename, 0, &match_info);
        if (g_match_info_matches(match_info)) {
            if (prefix) {
                *prefix = g_match_info_fetch_named(match_info, "prefix");
            }
            if (time) {
                *time = g_match_info_fetch_named(match_info, "time");
            }
            if (suffix) {
                *suffix = g_strdup(sfx);
            }
            ret = FILESET_TIME_NUM;
        }
        g_match_info_free(match_info);
    }

    g_free(filename);

    return ret;
}


/* test if both files could be in the same file set */
/* (fname2 must already be in correct shape) */
static bool
fileset_is_file_in_set(const char *fname1, const char *fname2)
{
    char        *pfx1;
    char        *pfx2;
    char        *sfx1;
    char        *sfx2;
    fileset_match_t match1;
    fileset_match_t match2;
    bool        ret = false;

    match1 = fileset_filename_match_pattern(fname1, &pfx1, &sfx1, NULL);
    if (match1 == FILESET_NO_MATCH) {
        return false;
    }

    match2 = fileset_filename_match_pattern(fname2, &pfx2, &sfx2, NULL);
    /* just to be sure ... */
    ws_assert(match2 != FILESET_NO_MATCH);
    if (match1 == match2 && g_strcmp0(pfx1, pfx2) == 0 && g_strcmp0(sfx1, sfx2) == 0) {
        ret = true;
    }

    g_free(pfx1);
    g_free(pfx2);
    g_free(sfx1);
    g_free(sfx2);

    return ret;
}

/* GCompareFunc helper for g_list_find_custom() */
static int
fileset_find_by_path(const void *a, const void *b)
{
    const fileset_entry *entry;
    const char *path;

    entry = (const fileset_entry *) a;
    path  = (const char *) b;

    return g_strcmp0(entry->fullname, path);
}

/* update the time and size of this file in the list */
void
fileset_update_file(const char *path)
{
    int fh, result;
    ws_statb64 buf;
    fileset_entry *entry = NULL;
    GList *entry_list;

    fh = ws_open( path, O_RDONLY, 0000 /* no creation so don't matter */);
    if(fh !=  -1) {

        /* Get statistics */
        result = ws_fstat64( fh, &buf );

        /* Show statistics if they are valid */
        if( result == 0 ) {
            entry_list = g_list_find_custom(set.entries, path,
                                            fileset_find_by_path);

            if (entry_list) {
                entry = (fileset_entry *) entry_list->data;
                entry->ctime    = ST_CREATE_TIME(buf);
                entry->mtime    = buf.st_mtime;
                entry->size     = buf.st_size;
            }
        }

        ws_close(fh);
    }
}

/* we know this file is part of the set, so add it */
static fileset_entry *
fileset_add_file(const char *dirname, const char *fname, bool current)
{
    int fh, result;
    ws_statb64 buf;
    char *path;
    fileset_entry *entry = NULL;


    path = ws_strdup_printf("%s%s", dirname, fname);

    fh = ws_open( path, O_RDONLY, 0000 /* no creation so don't matter */);
    if(fh !=  -1) {

        /* Get statistics */
        result = ws_fstat64( fh, &buf );

        /* Show statistics if they are valid */
        if( result == 0 ) {
            entry = g_new(fileset_entry, 1);

            entry->fullname = g_strdup(path);
            entry->name     = g_strdup(fname);
            entry->ctime    = ST_CREATE_TIME(buf);
            entry->mtime    = buf.st_mtime;
            entry->size     = buf.st_size;
            entry->current  = current;

            set.entries = g_list_append(set.entries, entry);
        }

        ws_close(fh);
    }

    g_free(path);

    return entry;
}


/* compare two list entries by creation date/time (through filename) */
static int
fileset_sort_compare(const void *a, const void *b)
{
    const fileset_entry *entry_a = (const fileset_entry *)a;
    const fileset_entry *entry_b = (const fileset_entry *)b;

    return strcmp(entry_a->name, entry_b->name);
}


/* add all file set entries to the dialog */
void fileset_update_dlg(void *window)
{
    GList         *le;

    /* Add all entries to the dialog. */
    fileset_dlg_begin_add_file(window);
    le = g_list_first(set.entries);
    while(le) {
        fileset_dlg_add_file((fileset_entry *)le->data, window);
        le = g_list_next(le);
    }
    fileset_dlg_end_add_file(window);
}


/* walk through the directory of the loaded file and add every file matching the current file */
void
fileset_add_dir(const char *fname, void *window)
{
    WS_DIR        *dir;             /* scanned directory */
    WS_DIRENT     *file;            /* current file */
    const char    *name;
    GString       *dirname;
    char          *fname_dup;


    /* get (convert) directory name, but don't touch the given string */
    fname_dup = g_strdup(fname);
    dirname = g_string_new(get_dirname(fname_dup));
    g_free(fname_dup);

    set.dirname = g_strdup(dirname->str);

    dirname = g_string_append_c(dirname, G_DIR_SEPARATOR);

    /* is the current file probably a part of any fileset? */
    if(fileset_filename_match_pattern(fname, NULL, NULL, NULL)) {
        /* yes, go through the files in the directory and check if the file in question is part of the current file set */
        if ((dir = ws_dir_open(dirname->str, 0, NULL)) != NULL) {
            while ((file = ws_dir_read_name(dir)) != NULL) {
                name = ws_dir_get_name(file);
                if(fileset_is_file_in_set(name, get_basename(fname))) {
                    fileset_add_file(dirname->str, name, strcmp(name, get_basename(fname))== 0 /* current */);
                }
            } /* while */

            ws_dir_close(dir);
        } /* if */
    } else {
        /* no, this is a "standalone file", just add this one */
        fileset_add_file(dirname->str, get_basename(fname), true /* current */);
        /* don't add the file to the dialog here, this will be done in fileset_update_dlg() below */
    }

    g_string_free(dirname, TRUE /* free_segment */);

    /* sort entries by creation time */
    set.entries = g_list_sort(set.entries, fileset_sort_compare);

    fileset_update_dlg(window);
}


/* get current directory name */
const char *
fileset_get_dirname(void)
{
    return set.dirname;
}


/* get the current list entry, or NULL */
static GList *
fileset_get_current(void)
{
    GList         *le;
    fileset_entry *entry;


    /* add all entries to the dialog */
    le = g_list_first(set.entries);
    while(le) {
        entry = (fileset_entry *)le->data;
        if(entry->current) {
            return le;
        }
        le = g_list_next(le);
    }

    return NULL;
}


/* get the file set entry after the current one, or NULL */
fileset_entry *
fileset_get_next(void)
{
    GList         *le;


    le = fileset_get_current();
    if(le == NULL) {
        return NULL;
    }

    le = g_list_next(le);
    if(le == NULL) {
        return NULL;
    }

    return (fileset_entry *)le->data;
}


/* get the file set entry before the current one, or NULL */
fileset_entry *
fileset_get_previous(void)
{
    GList         *le;


    le = fileset_get_current();
    if(le == NULL) {
        return NULL;
    }

    le = g_list_previous(le);
    if(le == NULL) {
        return NULL;
    }

    return (fileset_entry *)le->data;
}


/* delete a single entry */
static void fileset_entry_delete(void *data, void *user_data _U_)
{
    fileset_entry *entry = (fileset_entry *)data;

    g_free( (void *) entry->fullname);
    entry->fullname = NULL;
    g_free( (void *) entry->name);
    entry->name = NULL;
    g_free(entry);
}


/* delete the whole file set */
void fileset_delete(void)
{
    /* free the entry list */
    if(set.entries) {
        g_list_foreach(set.entries, fileset_entry_delete, NULL);
        g_list_free(set.entries);
        set.entries = NULL;
    }

    /* free the rest */
    if(set.dirname) {
        g_free( (void *) set.dirname);
        set.dirname = NULL;
    }
}

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
