/* filter_files.c
 * Code for reading and writing the filters file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL
#include "filter_files.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>

/*
 * Read in a list of filters.
 *
 * On error, report the error via the UI.
 */

#define INIT_BUF_SIZE  128

static GList *
add_filter_entry(GList *fl, const char *filt_name, const char *filt_expr)
{
    filter_def *filt;

    filt         = g_new(filter_def, 1);
    filt->name   = g_strdup(filt_name);
    filt->strval = g_strdup(filt_expr);
    return g_list_prepend(fl, filt);
}

static void
free_filter_entry(void * data)
{
    filter_def *filt = (filter_def*)data;
    g_free(filt->name);
    g_free(filt->strval);
    g_free(filt);
}

void ws_filter_list_free(filter_list_t *fl)
{
    g_list_free_full(fl->list, free_filter_entry);
    g_free(fl);
}

static GList *
remove_filter_entry(GList *fl, GList *fl_entry)
{
    filter_def *filt;

    filt = (filter_def *) fl_entry->data;
    g_free(filt->name);
    g_free(filt->strval);
    g_free(filt);
    return g_list_remove_link(fl, fl_entry);
}

static int
skip_whitespace(FILE *ff)
{
    int c;

    while ((c = getc(ff)) != EOF && c != '\n' && g_ascii_isspace(c))
        ;
    return c;
}

static int
getc_crlf(FILE *ff)
{
    int c;

    c = getc(ff);
    if (c == '\r') {
        /* Treat CR-LF at the end of a line like LF, so that if we're reading
         * a Windows-format file on UN*X, we handle it the same way we'd handle
         * a UN*X-format file. */
        c = getc(ff);
        if (c != EOF && c != '\n') {
            /* Put back the character after the CR, and process the CR normally. */
            ungetc(c, ff);
            c = '\r';
        }
    }
    return c;
}

filter_list_t *
ws_filter_list_read(filter_list_type_t list_type)
{
    const char *ff_name, *ff_description;
    char       *ff_path;
    FILE       *ff;
    GList      *flp = NULL;
    int         c;
    char       *filt_name, *filt_expr;
    int         filt_name_len, filt_expr_len;
    int         filt_name_index, filt_expr_index;
    int         line = 1;

    filter_list_t *list = g_new(filter_list_t, 1);
    list->type = list_type;
    list->list = NULL;

    switch (list_type) {

        case CFILTER_LIST:
            ff_name = CFILTER_FILE_NAME;
            ff_description = "capture";
            break;

        case DFILTER_LIST:
            ff_name = DFILTER_FILE_NAME;
            ff_description = "display";
            break;

        case DMACROS_LIST:
            ff_name = DMACROS_FILE_NAME;
            ff_description = "display filter macro";
            break;

        default:
            ws_assert_not_reached();
    }

    /* try to open personal "cfilters"/"dfilters" file */
    ff_path = get_persconffile_path(ff_name, true);
    if ((ff = ws_fopen(ff_path, "r")) == NULL) {
        /*
         * Did that fail because the file didn't exist?
         */
        if (errno != ENOENT) {
            /*
             * No.  Just give up.
             */
            report_warning("Could not open your %s filter file\n\"%s\": %s.",
                    ff_description, ff_path, g_strerror(errno));
            g_free(ff_path);
            return list;
        }

        /*
         * Yes. Try to open the global "cfilters/dfilters" file.
         */
        g_free(ff_path);
        ff_path = get_datafile_path(ff_name);
        if ((ff = ws_fopen(ff_path, "r")) == NULL) {
            /*
             * Well, that didn't work, either.  Just give up.
             * Report an error if the file existed but we couldn't open it.
             */
            if (errno != ENOENT) {
                report_warning("Could not open your %s filter file\n\"%s\": %s.",
                        ff_description, ff_path, g_strerror(errno));
            }
            g_free(ff_path);
            return list;
        }
    }

    /* Allocate the filter name buffer. */
    filt_name_len = INIT_BUF_SIZE;
    filt_name = (char *)g_malloc(filt_name_len + 1);
    filt_expr_len = INIT_BUF_SIZE;
    filt_expr = (char *)g_malloc(filt_expr_len + 1);

    for (line = 1; ; line++) {
        /* Lines in a filter file are of the form

           "name" expression

           where "name" is a name, in quotes - backslashes in the name
           escape the next character, so quotes and backslashes can appear
           in the name - and "expression" is a filter expression, not in
           quotes, running to the end of the line. */

        /* Skip over leading white space, if any. */
        c = skip_whitespace(ff);

        if (c == EOF)
            break;    /* Nothing more to read */
        if (c == '\n')
            continue; /* Blank line. */
        if (c == '#') {
            /* Comment. */
            while (c != '\n')
                c = getc(ff);   /* skip to the end of the line */
            continue;
        }

        /* "c" is the first non-white-space character.
           If it's not a quote, it's an error. */
        if (c != '"') {
            ws_warning("'%s' line %d doesn't have a quoted filter name.", ff_path,
                    line);
            while (c != '\n')
                c = getc(ff);   /* skip to the end of the line */
            continue;
        }

        /* Get the name of the filter. */
        filt_name_index = 0;
        for (;;) {
            c = getc_crlf(ff);
            if (c == EOF || c == '\n')
                break;  /* End of line - or end of file */
            if (c == '"') {
                /* Closing quote. */
                if (filt_name_index >= filt_name_len) {
                    /* Filter name buffer isn't long enough; double its length. */
                    filt_name_len *= 2;
                    filt_name = (char *)g_realloc(filt_name, filt_name_len + 1);
                }
                filt_name[filt_name_index] = '\0';
                break;
            }
            if (c == '\\') {
                /* Next character is escaped */
                c = getc_crlf(ff);
                if (c == EOF || c == '\n')
                    break;        /* End of line - or end of file */
            }
            /* Add this character to the filter name string. */
            if (filt_name_index >= filt_name_len) {
                /* Filter name buffer isn't long enough; double its length. */
                filt_name_len *= 2;
                filt_name = (char *)g_realloc(filt_name, filt_name_len + 1);
            }
            filt_name[filt_name_index] = c;
            filt_name_index++;
        }

        if (c == EOF) {
            if (!ferror(ff)) {
                /* EOF, not error; no newline seen before EOF */
                ws_warning("'%s' line %d doesn't have a newline.", ff_path,
                        line);
            }
            break;    /* nothing more to read */
        }

        if (c != '"') {
            /* No newline seen before end-of-line */
            ws_warning("'%s' line %d doesn't have a closing quote.", ff_path,
                    line);
            continue;
        }

        /* Skip over separating white space, if any. */
        c = skip_whitespace(ff);

        if (c == EOF) {
            if (!ferror(ff)) {
                /* EOF, not error; no newline seen before EOF */
                ws_warning("'%s' line %d doesn't have a newline.", ff_path,
                        line);
            }
            break;    /* nothing more to read */
        }

        if (c == '\n') {
            /* No filter expression */
            ws_warning("'%s' line %d doesn't have a filter expression.", ff_path,
                    line);
            continue;
        }

        /* "c" is the first non-white-space character; it's the first
           character of the filter expression. */
        filt_expr_index = 0;
        for (;;) {
            /* Add this character to the filter expression string. */
            if (filt_expr_index >= filt_expr_len) {
                /* Filter expression buffer isn't long enough; double its length. */
                filt_expr_len *= 2;
                filt_expr = (char *)g_realloc(filt_expr, filt_expr_len + 1);
            }
            filt_expr[filt_expr_index] = c;
            filt_expr_index++;

            /* Get the next character. */
            c = getc_crlf(ff);
            if (c == EOF || c == '\n')
                break;
        }

        if (c == EOF) {
            if (!ferror(ff)) {
                /* EOF, not error; no newline seen before EOF */
                ws_warning("'%s' line %d doesn't have a newline.", ff_path,
                        line);
            }
            break;    /* nothing more to read */
        }

        /* We saw the ending newline; terminate the filter expression string */
        if (filt_expr_index >= filt_expr_len) {
            /* Filter expression buffer isn't long enough; double its length. */
            filt_expr_len *= 2;
            filt_expr = (char *)g_realloc(filt_expr, filt_expr_len + 1);
        }
        filt_expr[filt_expr_index] = '\0';

        /* Add the new filter to the list of filters */
        flp = add_filter_entry(flp, filt_name, filt_expr);
    }
    if (ferror(ff)) {
        report_warning("Error reading your %s filter file\n\"%s\": %s.",
                ff_description, ff_path, g_strerror(errno));
    }
    g_free(ff_path);
    fclose(ff);
    g_free(filt_name);
    g_free(filt_expr);
    list->list = flp;
    return list;
}

/*
 * Add a new filter to the end of a list.
 */
void
ws_filter_list_add(filter_list_t *fl, const char *name,
                    const char *expression)
{
    fl->list = add_filter_entry(fl->list, name, expression);
}

static int
compare_def(const void *def, const void *name)
{
    return g_strcmp0(((filter_def *)def)->name, name);
}

GList *ws_filter_list_find(filter_list_t *list, const char *name)
{
    return g_list_find_custom(list->list, name, compare_def);
}

/*
 * Remove a filter from a list.
 */
bool
ws_filter_list_remove(filter_list_t *list, const char *name)
{
    GList      *p;

    p = g_list_find_custom(list->list, name, compare_def);
    if (p == NULL)
        return false;
    list->list = remove_filter_entry(list->list, p);
    return true;
}

/*
 * Write out a list of filters.
 *
 * On error, report the error via the UI.
 */
void
ws_filter_list_write(filter_list_t *list)
{
    char        *pf_dir_path;
    const char *ff_name, *ff_description;
    char        *ff_path, *ff_path_new;
    GList       *fl;
    GList       *flpp;
    filter_def  *filt;
    FILE        *ff;
    unsigned char      *p, c;

    switch (list->type) {

        case CFILTER_LIST:
            ff_name = CFILTER_FILE_NAME;
            ff_description = "capture";
            break;

        case DFILTER_LIST:
            ff_name = DFILTER_FILE_NAME;
            ff_description = "display";
            break;

        case DMACROS_LIST:
            ff_name = DMACROS_FILE_NAME;
            ff_description = "display filter macros";
            break;

        default:
            ws_assert_not_reached();
            return;
    }
    fl = list->list;

    /* Create the directory that holds personal configuration files,
       if necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
        report_failure("Can't create directory\n\"%s\"\nfor filter files: %s.",
                pf_dir_path, g_strerror(errno));
        g_free(pf_dir_path);
        return;
    }

    ff_path = get_persconffile_path(ff_name, true);

    /* Write to "XXX.new", and rename if that succeeds.
       That means we don't trash the file if we fail to write it out
       completely. */
    ff_path_new = ws_strdup_printf("%s.new", ff_path);

    if ((ff = ws_fopen(ff_path_new, "w")) == NULL) {
        /* We had an error saving the filter. */
        report_failure("Error saving your %s filter file\nCouldn't open \"%s\": %s.",
                ff_description, ff_path_new, g_strerror(errno));
        g_free(ff_path_new);
        g_free(ff_path);
        return;
    }
    flpp = g_list_first(fl);
    while (flpp) {
        filt = (filter_def *) flpp->data;

        /* Write out the filter name as a quoted string; escape any quotes
           or backslashes. */
        putc('"', ff);
        for (p = (unsigned char *)filt->name; (c = *p) != '\0'; p++) {
            if (c == '"' || c == '\\')
                putc('\\', ff);
            putc(c, ff);
        }
        putc('"', ff);

        /* Separate the filter name and value with a space. */
        putc(' ', ff);

        /* Write out the filter expression and a newline. */
        fprintf(ff, "%s\n", filt->strval);
        if (ferror(ff)) {
            report_failure("Error saving your %s filter file\nWrite to \"%s\" failed: %s.",
                    ff_description, ff_path_new, g_strerror(errno));
            fclose(ff);
            ws_unlink(ff_path_new);
            g_free(ff_path_new);
            g_free(ff_path);
            return;
        }
        flpp = flpp->next;
    }
    if (fclose(ff) == EOF) {
        report_failure("Error saving your %s filter file\nWrite to \"%s\" failed: %s.",
                ff_description, ff_path_new, g_strerror(errno));
        ws_unlink(ff_path_new);
        g_free(ff_path_new);
        g_free(ff_path);
        return;
    }

#ifdef _WIN32
    /* ANSI C doesn't say whether "rename()" removes the target if it
       exists; the Win32 call to rename files doesn't do so, which I
       infer is the reason why the MSVC++ "rename()" doesn't do so.
       We must therefore remove the target file first, on Windows.

       XXX - ws_rename() should be ws_stdio_rename() on Windows,
       and ws_stdio_rename() uses MoveFileEx() with MOVEFILE_REPLACE_EXISTING,
       so it should remove the target if it exists, so this stuff
       shouldn't be necessary.  Perhaps it dates back to when we were
       calling rename(), with that being a wrapper around Microsoft's
       _rename(), which didn't remove the target. */
    if (ws_remove(ff_path) < 0 && errno != ENOENT) {
        /* It failed for some reason other than "it's not there"; if
           it's not there, we don't need to remove it, so we just
           drive on. */
        report_failure("Error saving your %s filter file\nCouldn't remove \"%s\": %s.",
                ff_description, ff_path, g_strerror(errno));
        ws_unlink(ff_path_new);
        g_free(ff_path_new);
        g_free(ff_path);
        return;
    }
#endif

    if (ws_rename(ff_path_new, ff_path) < 0) {
        report_failure("Error saving your %s filter file\nCouldn't rename \"%s\" to \"%s\": %s.",
                ff_description, ff_path_new, ff_path, g_strerror(errno));
        ws_unlink(ff_path_new);
        g_free(ff_path_new);
        g_free(ff_path);
        return;
    }
    g_free(ff_path_new);
    g_free(ff_path);
}
