/* fileset.c
 * Routines for handling file sets
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <wiretap/file_util.h>
#include "globals.h"

#include <epan/filesystem.h>

#include "fileset.h"



typedef struct _fileset {
  GList         *entries;
  const char    *dirname;
} fileset;

/* this is the fileset's global data */
fileset set = { NULL, NULL};


/* is this a probable file of a file set (does the naming pattern match)? */
gboolean
fileset_filename_match_pattern(const char *fname)
{
    char        *pfx;
    int         baselen;
    int         minlen = strlen("_00001_20050418010750");
    char        *filename;
  

    /* d:\dir1\test_00001_20050418010750.cap */
    filename = g_strdup(get_basename(fname));

    /* test_00001_20050418010750.cap */
    pfx = strrchr(filename, '.');
    if(pfx == NULL) {
        return FALSE;
    }
    /* test_00001_20050418010750 */
    *pfx = '\0';

    /* filename long enough? */
    baselen = strlen(filename);
    if(baselen < minlen) {
        g_free(filename);
        return FALSE;
    }

    /* there must be two underscores at special places */
    if(filename[baselen-minlen] != '_' || filename[baselen-minlen+6] != '_') {
        g_free(filename);
        return FALSE;
    }

    /* replace the two underscores by digits */
    filename[baselen-minlen] = '0';
    filename[baselen-minlen+6] = '0';

    /* we should have only digits now */
    while(minlen--) {
        baselen--;

        if(!isdigit( (int) filename[baselen])) {
            g_free(filename);
            return FALSE;
        }
    }

    g_free(filename);

    /* ok, seems to be good */
    return TRUE;
}


/* test, if both files could be in the same file set */
/* (the filenames must already be in correct shape) */
gboolean
fileset_is_file_in_set(const char *fname1, const char *fname2)
{
    char        *pfx1;
    char        *pfx2;
    char        *dup_f1;
    char        *dup_f2;
    int         minlen = strlen("_00001_20050418010750");


    /* just to be sure ... */
    g_assert(fileset_filename_match_pattern(fname1));
    g_assert(fileset_filename_match_pattern(fname2));

    dup_f1 = g_strdup(fname1);
    dup_f2 = g_strdup(fname2);

    pfx1 = strrchr(dup_f1, '.');
    pfx2 = strrchr(dup_f2, '.');

    /* the optional suffix (file extension) must be equal */
    if(strcmp(pfx1, pfx2) != 0) {
        g_free(dup_f1);
        g_free(dup_f2);
        return FALSE;
    }

    *(pfx1-minlen) = '\0';
    *(pfx2-minlen) = '\0';

    if(strcmp(dup_f1, dup_f2) != 0) {
        g_free(dup_f1);
        g_free(dup_f2);
        return FALSE;
    }

    g_free(dup_f1);
    g_free(dup_f2);
    return TRUE;
}


/* we know this file is part of the set, so add it */
static fileset_entry *
fileset_add_file(const char *dirname, const char *fname, gboolean current)
{
    int fh, result;
    struct stat buf;
    char *path;
    fileset_entry *entry = NULL;


    path = g_strdup_printf("%s%s", dirname, fname);

    fh = eth_open( path, O_RDONLY, 0000 /* no creation so don't matter */);
    if(fh !=  -1) {

        /* Get statistics */
        result = fstat( fh, &buf );

        /* Show statistics if they are valid */
        if( result == 0 ) {
            entry = g_malloc(sizeof(fileset_entry));

            entry->fullname = g_strdup(path);
            entry->name     = g_strdup(fname);
            entry->ctime    = buf.st_ctime;
            entry->mtime    = buf.st_mtime;
            entry->size     = buf.st_size;
            entry->current  = current;

            set.entries = g_list_append(set.entries, entry);
        }

        eth_close(fh);
    }

    g_free(path);

    return entry;
}


/* compare two list entries by creation date/time (through filename) */
static gint
fileset_sort_compare(gconstpointer a, gconstpointer b)
{
    const fileset_entry *entry_a = a;
    const fileset_entry *entry_b = b;

	return strcmp(entry_a->name, entry_b->name);
}


/* add all file set entries to the dialog */
void fileset_update_dlg(void)
{
    GList         *le;


    /* add all entires to the dialog */
    le = g_list_first(set.entries);
    while(le) {
        fileset_dlg_add_file(le->data);
        le = g_list_next(le);
    }
}


/* walk through the directory of the loaded file and add every file matching the current file */
void
fileset_add_dir(const char *fname)
{
    ETH_DIR       *dir;             /* scanned directory */
    ETH_DIRENT    *file;            /* current file */
    const char    *name;
    fileset_entry *entry;
    GString       *dirname;
    gchar         *fname_dup;


    /* get (convert) directory name, but don't touch the given string */
    fname_dup = get_dirname(g_strdup(fname));
    dirname = g_string_new(fname_dup);
    g_free(fname_dup);

    set.dirname = g_strdup(dirname->str);    
    
    dirname = g_string_append_c(dirname, G_DIR_SEPARATOR);

    /* is the current file probably a part of any fileset? */
    if(fileset_filename_match_pattern(fname)) {
        /* yes, go through the files in the directory and check if the file in question is part of the current file set */
        if ((dir = eth_dir_open(dirname->str, 0, NULL)) != NULL) {
	        while ((file = eth_dir_read_name(dir)) != NULL) {
	            name = eth_dir_get_name(file);
                if(fileset_filename_match_pattern(name) && fileset_is_file_in_set(name, get_basename(fname))) {
                    fileset_add_file(dirname->str, name, strcmp(name, get_basename(fname))== 0 /* current */);
                }
            } /* while */

            eth_dir_close(dir);
        } /* if */
    } else {
        /* no, this is a "standalone file", just add this one */
        entry = fileset_add_file(dirname->str, get_basename(fname), TRUE /* current */);
        if(entry) {
            fileset_dlg_add_file(entry);
        }
    }

    g_string_free(dirname, TRUE /* free_segment */);

    /* sort entries by creation time */
    set.entries = g_list_sort(set.entries, fileset_sort_compare);

    fileset_update_dlg();
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


    /* add all entires to the dialog */
    le = g_list_first(set.entries);
    while(le) {
        entry = le->data;
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

    return le->data;
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

    return le->data;
}


/* delete a single entry */
static void fileset_entry_delete(gpointer data, gpointer user_data _U_)
{
    fileset_entry *entry = data;

    g_free( (gpointer) entry->fullname);
    entry->fullname = NULL;
    g_free( (gpointer) entry->name);
    entry->name = NULL;
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
        g_free( (gpointer) set.dirname);
        set.dirname = NULL;
    }
}


