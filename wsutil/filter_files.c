/* filter_files.c
 * Code for reading and writing the filters file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL
#include "filter_files.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/profile_inherit.h>
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
    filt->source_profile = NULL;
    return g_list_prepend(fl, filt);
}

static void
free_filter_entry(void * data)
{
    filter_def *filt = (filter_def*)data;
    g_free(filt->name);
    g_free(filt->strval);
    g_free(filt->source_profile);
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
    g_free(filt->source_profile);
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

static const char *
filter_list_file_name(filter_list_type_t list_type, const char **description)
{
    switch (list_type) {

        case CFILTER_LIST:
            *description = "capture filter";
            return CFILTER_FILE_NAME;

        case DFILTER_LIST:
            *description = "display filter";
            return DFILTER_FILE_NAME;

        case DMACROS_LIST:
            *description = "display filter macro";
            return DMACROS_FILE_NAME;
    }

    ws_assert_not_reached();
}

/*
 * Read the filters of an open file, prepending them to flp.
 */
static GList *
read_filter_file(FILE *ff, const char *ff_path, const char *ff_description, GList *flp)
{
    int         c;
    char       *filt_name, *filt_expr;
    size_t      filt_name_len, filt_expr_len;
    size_t      filt_name_index, filt_expr_index;
    int         line = 1;

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
        report_warning("Error reading your %s file\n\"%s\": %s.",
                ff_description, ff_path, g_strerror(errno));
    }
    g_free(filt_name);
    g_free(filt_expr);
    return flp;
}

/*
 * Read the profile's own filters. A profile using the parent's filters only
 * has none, and only a profile using its own filters only falls back to the
 * global file.
 */
static filter_list_t *
filter_list_read_own(filter_list_type_t list_type, const char* app_env_var_prefix, profile_inherit_e mode)
{
    const char *ff_name, *ff_description;
    char       *ff_path;
    FILE       *ff;

    filter_list_t *list = g_new(filter_list_t, 1);
    list->type = list_type;
    list->list = NULL;

    ff_name = filter_list_file_name(list_type, &ff_description);

    if (mode == PROFILE_INHERIT_PARENT_ONLY)
        return list;

    /* try to open personal "cfilters"/"dfilters" file */
    ff_path = get_persconffile_path(ff_name, true, app_env_var_prefix);
    if ((ff = ws_fopen(ff_path, "r")) == NULL) {
        /*
         * Did that fail because the file didn't exist?
         */
        if (errno != ENOENT) {
            /*
             * No.  Just give up.
             */
            report_warning("Could not open your %s file\n\"%s\": %s.",
                    ff_description, ff_path, g_strerror(errno));
            g_free(ff_path);
            return list;
        }

        g_free(ff_path);
        if (mode != PROFILE_INHERIT_PROFILE_ONLY) {
            /* The global filters come from the parent profiles */
            return list;
        }

        /*
         * Yes. Try to open the global "cfilters/dfilters" file.
         */
        ff_path = get_datafile_path(ff_name, app_env_var_prefix);
        if ((ff = ws_fopen(ff_path, "r")) == NULL) {
            /*
             * Well, that didn't work, either.  Just give up.
             * Report an error if the file existed but we couldn't open it.
             */
            if (errno != ENOENT) {
                report_warning("Could not open your %s file\n\"%s\": %s.",
                        ff_description, ff_path, g_strerror(errno));
            }
            g_free(ff_path);
            return list;
        }
    }

    list->list = read_filter_file(ff, ff_path, ff_description, NULL);
    g_free(ff_path);
    fclose(ff);
    return list;
}

typedef struct {
    filter_list_type_t type;
    const char *description;
    GList *entries;     /* The inherited filters, in reverse order */
} read_layer_data_t;

/* A macro is found by its name, a filter also by its expression */
static const char *
filter_list_key2(filter_list_type_t list_type, const filter_def *filt)
{
    return list_type == DMACROS_LIST ? NULL : filt->strval;
}

/* Read the filters of one parent profile */
static bool
read_layer_filters(const profile_inherit_layer_t *layer, const char *path, const char *filename _U_,
                   profile_inherit_seen_t *seen, void *user_data, char **err)
{
    read_layer_data_t *data = (read_layer_data_t *)user_data;
    FILE *ff;

    if ((ff = ws_fopen(path, "r")) == NULL) {
        *err = ws_strdup_printf("Could not open the %s file \"%s\": %s.",
                                data->description, path, g_strerror(errno));
        return false;
    }
    /* In the order of the file */
    GList *layer_list = g_list_reverse(read_filter_file(ff, path, data->description, NULL));
    fclose(ff);

    for (GList *item = layer_list; item; item = g_list_next(item)) {
        filter_def *filt = (filter_def *)item->data;

        if (profile_inherit_seen_check(seen, filt->name, filter_list_key2(data->type, filt))) {
            free_filter_entry(filt);
            continue;
        }
        filt->source_profile = g_strdup(layer->source);
        data->entries = g_list_prepend(data->entries, filt);
    }
    g_list_free(layer_list);
    return true;
}

filter_list_t *
ws_filter_list_read(filter_list_type_t list_type, const char* app_env_var_prefix)
{
    const char *ff_name, *ff_description;

    ff_name = filter_list_file_name(list_type, &ff_description);
    profile_inherit_e mode = profile_get_inherit(app_env_var_prefix, NULL, ff_name);

    filter_list_t *list = filter_list_read_own(list_type, app_env_var_prefix, mode);
    if (mode == PROFILE_INHERIT_PROFILE_ONLY)
        return list;

    /* The profile's own filters come first, and win over duplicates from parents */
    profile_inherit_seen_t *seen = profile_inherit_seen_new();
    for (GList *item = list->list; item; item = g_list_next(item)) {
        const filter_def *filt = (const filter_def *)item->data;
        profile_inherit_seen_check(seen, filt->name, filter_list_key2(list_type, filt));
    }
    profile_inherit_seen_next(seen);

    read_layer_data_t data = { list_type, ff_description, NULL };
    char *err = NULL;
    if (!profile_inherit_read_layers(app_env_var_prefix, ff_name, NULL, true, mode, seen,
                                     read_layer_filters, &data, &err)) {
        report_warning("%s", err);
    }
    g_free(err);
    profile_inherit_seen_free(seen);

    list->list = g_list_concat(list->list, g_list_reverse(data.entries));
    return list;
}

filter_list_t *
ws_filter_list_read_own(filter_list_type_t list_type, const char* app_env_var_prefix)
{
    return filter_list_read_own(list_type, app_env_var_prefix, PROFILE_INHERIT_PROFILE_ONLY);
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
ws_filter_list_write(filter_list_t *list, const char* app_env_var_prefix)
{
    char        *pf_dir_path;
    const char *ff_name, *ff_description;
    char        *ff_path, *ff_path_new;
    GList       *fl;
    GList       *flpp;
    filter_def  *filt;
    FILE        *ff;
    unsigned char      *p, c;

    ff_name = filter_list_file_name(list->type, &ff_description);
    fl = list->list;

    /* Create the directory that holds personal configuration files,
       if necessary.  */
    if (create_persconffile_dir(app_env_var_prefix, &pf_dir_path) == -1) {
        report_failure("Can't create directory\n\"%s\"\nfor filter files: %s.",
                pf_dir_path, g_strerror(errno));
        g_free(pf_dir_path);
        return;
    }

    ff_path = get_persconffile_path(ff_name, true, app_env_var_prefix);

    /* Write to "XXX.new", and rename if that succeeds.
       That means we don't trash the file if we fail to write it out
       completely. */
    ff_path_new = ws_strdup_printf("%s.new", ff_path);

    if ((ff = ws_fopen(ff_path_new, "w")) == NULL) {
        /* We had an error saving the filter. */
        report_failure("Error saving your %s file\nCouldn't open \"%s\": %s.",
                ff_description, ff_path_new, g_strerror(errno));
        g_free(ff_path_new);
        g_free(ff_path);
        return;
    }
    flpp = g_list_first(fl);
    while (flpp) {
        filt = (filter_def *) flpp->data;

        /* Filters inherited from parent profiles are not written to this profile */
        if (filt->source_profile != NULL) {
            flpp = flpp->next;
            continue;
        }

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
            report_failure("Error saving your %s file\nWrite to \"%s\" failed: %s.",
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
        report_failure("Error saving your %s file\nWrite to \"%s\" failed: %s.",
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

       XXX - ws_rename() is g_rename() on Windows, and g_rename()
       uses MoveFileEx() with MOVEFILE_REPLACE_EXISTING,
       so it should remove the target if it exists, so this stuff
       shouldn't be necessary.  Perhaps it dates back to when we were
       calling rename(), with that being a wrapper around Microsoft's
       _rename(), which didn't remove the target. */
    if (ws_remove(ff_path) < 0 && errno != ENOENT) {
        /* It failed for some reason other than "it's not there"; if
           it's not there, we don't need to remove it, so we just
           drive on. */
        report_failure("Error saving your %s file\nCouldn't remove \"%s\": %s.",
                ff_description, ff_path, g_strerror(errno));
        ws_unlink(ff_path_new);
        g_free(ff_path_new);
        g_free(ff_path);
        return;
    }
#endif

    if (ws_rename(ff_path_new, ff_path) < 0) {
        report_failure("Error saving your %s file\nCouldn't rename \"%s\" to \"%s\": %s.",
                ff_description, ff_path_new, ff_path, g_strerror(errno));
        ws_unlink(ff_path_new);
        g_free(ff_path_new);
        g_free(ff_path);
        return;
    }
    g_free(ff_path_new);
    g_free(ff_path);
}
