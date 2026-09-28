/* tag_rules.c
 * Routines for tagging rules
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_EPAN

#include <glib.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/report_message.h>
#include <wsutil/strtoi.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>

#include <epan/dfilter/dfilter.h>
#include <epan/epan_dissect.h>
#include "tag_rules.h"

/*
 * Each line in the tagrules file has one of these formats:
 *
 *  @<name>@<filter>@<tag_content>@<tag_url>@<comment>
 * !@<name>@<filter>@<tag_content>@<tag_url>@<comment>
 *
 * A leading '!' marks the rule as disabled.
 * Lines beginning with '#' are comments and are ignored.
 * The first four fields are escape-encoded: '\@' → '@', '\\' → '\'.
 * The comment field (last) is unescaped and may contain '@' freely; it runs
 * to end-of-line.
 *
 * The active list is loaded from and written to a single tagrules file in
 * the active profile's directory.
 */

/* The currently active tag rule list */
static GSList *tag_rule_list;

/*
 * Escape '@' and '\' in a field value so '@' can safely be used as the
 * column delimiter.  Returns a newly g_malloc'd string; caller must g_free.
 */
static char *
escape_field(const char *s)
{
    GString *out = g_string_sized_new(strlen(s) + 4);
    for (; *s; s++) {
        if (*s == '\\' || *s == '@')
            g_string_append_c(out, '\\');
        g_string_append_c(out, *s);
    }
    return g_string_free(out, false);
}

/*
 * Read one field from the file, stopping at an unescaped '@', '\n', or EOF.
 * On return *c_out holds the character that terminated the read.
 * Writes the unescaped value into buf (g_realloc'd as needed); sets *len_inout.
 * Returns the number of bytes written (excluding the NUL terminator).
 */
static int
read_escaped_field(FILE *f, char **buf, uint32_t *len_inout, int *c_out)
{
    uint32_t i = 0;
    int c;
    while (1) {
        c = ws_getc_unlocked(f);
        if (c == EOF || c == '\n' || c == '@')
            break;
        if (c == '\\') {
            int next = ws_getc_unlocked(f);
            if (next == EOF || next == '\n') {
                if (i >= *len_inout) { *len_inout *= 2; *buf = (char *)g_realloc(*buf, *len_inout + 1); }
                (*buf)[i++] = (char)c;
                c = next;
                break;
            }
            c = next;
        }
        if (i >= *len_inout) { *len_inout *= 2; *buf = (char *)g_realloc(*buf, *len_inout + 1); }
        (*buf)[i++] = (char)c;
    }
    (*buf)[i] = '\0';
    *c_out = c;
    return (int)i;
}

/* Display preferences for the active profile */
static tag_prefs_t tag_prefs = { '\0', 0, TAG_LINK_CLICK_CTRL };

tag_prefs_t
tag_rules_get_prefs(void)
{
    return tag_prefs;
}

bool
tag_rules_used(void)
{
    return tag_rule_list != NULL;
}

void
tag_rules_set_prefs(const tag_prefs_t *tprefs)
{
    if (tprefs)
        tag_prefs = *tprefs;
}

/* ---------------------------------------------------------------------------
 * Allocation / deallocation helpers
 * ------------------------------------------------------------------------- */

tag_rule_t *
tag_rule_new(const char *name, const char *filter,
             const char *tag_content, const char *tag_url,
             const char *comment)
{
    tag_rule_t *rule;

    rule              = g_new0(tag_rule_t, 1);
    rule->rule_name   = g_strdup(name);
    rule->filter_text = g_strdup(filter);
    rule->tag_content = g_strdup(tag_content ? tag_content : "");
    rule->tag_url     = g_strdup(tag_url ? tag_url : "");
    rule->comment     = g_strdup(comment ? comment : "");
    rule->disabled    = false;
    rule->c_tagfilter = NULL;
    return rule;
}

void
tag_rule_delete(tag_rule_t *rule)
{
    if (!rule)
        return;
    g_free(rule->rule_name);
    g_free(rule->filter_text);
    g_free(rule->tag_content);
    g_free(rule->tag_url);
    g_free(rule->comment);
    dfilter_free(rule->c_tagfilter);
    g_free(rule);
}

static void
tag_rule_delete_cb(void *rule_arg)
{
    tag_rule_delete((tag_rule_t *)rule_arg);
}

static void
tag_rule_list_delete(GSList **list)
{
    g_slist_free_full(*list, tag_rule_delete_cb);
    *list = NULL;
}

/* ---------------------------------------------------------------------------
 * File I/O — read
 * ------------------------------------------------------------------------- */

#define INIT_BUF_SIZE 128

/*
 * Read tagrules from an already-open file.  Rules are appended to
 * *list_out when list_out != NULL; otherwise add_cb/cb_data are used.
 *
 * Returns 0 on success, errno on I/O error.
 */
static int
read_tagrules_file(const char *path, FILE *f,
                   GSList **list_out,
                   tag_rule_add_cb_func add_cb, void *cb_data)
{
    char     *name;
    char     *filter;
    char     *tag_content;
    char     *tag_url;
    char     *comment;
    uint32_t  name_len        = INIT_BUF_SIZE;
    uint32_t  filter_len      = INIT_BUF_SIZE;
    uint32_t  tag_content_len = INIT_BUF_SIZE;
    uint32_t  tag_url_len     = INIT_BUF_SIZE;
    uint32_t  comment_len     = INIT_BUF_SIZE;
    uint32_t  i;
    int       c;
    bool      disabled         = false;
    bool      skip_end_of_line = false;
    int       ret              = 0;

    name        = (char *)g_malloc(name_len + 1);
    filter      = (char *)g_malloc(filter_len + 1);
    tag_content = (char *)g_malloc(tag_content_len + 1);
    tag_url     = (char *)g_malloc(tag_url_len + 1);
    comment     = (char *)g_malloc(comment_len + 1);

    while (1) {

        /* Skip to end of current (bad/comment) line if requested */
        if (skip_end_of_line) {
            do {
                c = ws_getc_unlocked(f);
            } while (c != EOF && c != '\n');
            if (c == EOF)
                break;
            disabled = false;
            skip_end_of_line = false;
        }

        /* Skip whitespace (including blank lines) */
        while ((c = ws_getc_unlocked(f)) != EOF && g_ascii_isspace(c)) {
            if (c == '\n') {
                disabled = false;   /* reset disabled flag across blank lines */
            }
        }

        if (c == EOF)
            break;

        /* Leading '!' means disabled */
        if (c == '!') {
            disabled = true;
            continue;
        }

        /* '#prefs:' header — parse display prefs */
        if (c == '#') {
            /* Read the rest of the line to check for #prefs: */
            char pref_line[256];
            int pi = 0;
            while (pi < (int)(sizeof(pref_line) - 1)) {
                int pc = ws_getc_unlocked(f);
                if (pc == EOF || pc == '\n') break;
                pref_line[pi++] = (char)pc;
            }
            pref_line[pi] = '\0';
            if (g_str_has_prefix(pref_line, "prefs:")) {
                char *kv = pref_line + 6; /* skip "prefs:" */
                gchar **pairs = g_strsplit(kv, ",", -1);
                for (int pi2 = 0; pairs[pi2]; pi2++) {
                    gchar **kv2 = g_strsplit(pairs[pi2], "=", 2);
                    if (kv2[0] && kv2[1]) {
                        if (strcmp(kv2[0], "sep") == 0) {
                            /* stored as 2-digit hex to avoid comma ambiguity */
                            unsigned v = 0;
                            if (sscanf(kv2[1], "%02x", &v) == 1 && v != 0)
                                tag_prefs.separator = (char)v;
                            else
                                tag_prefs.separator = '\0';
                        }
                        else if (strcmp(kv2[0], "emoji_size") == 0) {
                            int32_t v32 = 0;
                            if (ws_strtoi32(kv2[1], NULL, &v32))
                                tag_prefs.emoji_size = (int)v32;
                        } else if (strcmp(kv2[0], "click") == 0) {
                            int32_t v32 = 0;
                            if (ws_strtoi32(kv2[1], NULL, &v32))
                                tag_prefs.link_click = (tag_link_click_mode_t)v32;
                        }
                    }
                    g_strfreev(kv2);
                }
                g_strfreev(pairs);
            }
            disabled = false;
            skip_end_of_line = false;
            continue;
        }

        /* Anything other than '@' starts an invalid line */
        if (c != '@') {
            skip_end_of_line = true;
            continue;
        }

        /* ----------------------------------------------------------------
         * We consumed the first '@'.  Now read: name @ filter @ tag_content
         * and then the remainder of the line as comment.
         * ---------------------------------------------------------------- */

        /* Read name (escaped) */
        i = read_escaped_field(f, &name, &name_len, &c);

        if (c == EOF || c == '\n') {
            disabled = false;
            skip_end_of_line = false;
            continue;
        }
        if (i == 0) {
            skip_end_of_line = true;
            continue;
        }

        /* Read filter (escaped) */
        i = read_escaped_field(f, &filter, &filter_len, &c);

        if (c == EOF || c == '\n') {
            disabled = false;
            skip_end_of_line = false;
            continue;
        }
        if (i == 0) {
            skip_end_of_line = true;
            continue;
        }

        /* Read tag_content (escaped) */
        read_escaped_field(f, &tag_content, &tag_content_len, &c);

        /* Read tag_url (escaped) */
        tag_url[0] = '\0';
        if (c == '@')
            read_escaped_field(f, &tag_url, &tag_url_len, &c);

        /*
         * Read the rest of the line as the comment.  The comment may
         * contain '@' characters; we simply read until '\n' or EOF.
         * If we already hit '\n' or EOF while reading tag_url, the
         * comment is empty.
         */
        i = 0;
        if (c == '@') {
            while (1) {
                c = ws_getc_unlocked(f);
                if (c == EOF || c == '\n')
                    break;
                if (i >= comment_len) {
                    comment_len *= 2;
                    comment = (char *)g_realloc(comment, comment_len + 1);
                }
                comment[i++] = (char)c;
            }
        }
        comment[i] = '\0';

        /* We have a complete rule — compile the filter and store it */
        {
            tag_rule_t *rule;
            dfilter_t  *temp_dfilter = NULL;
            df_error_t *df_err       = NULL;

            if (!disabled && filter[0] != '\0' &&
                !dfilter_compile(filter, &temp_dfilter, &df_err)) {
                report_warning("Disabling tag rule: Could not compile \"%s\" "
                               "in tagrules file \"%s\".\n%s",
                               name, path, df_err->msg);
                df_error_free(&df_err);
                disabled = true;
            }

            rule           = tag_rule_new(name, filter, tag_content, tag_url, comment);
            rule->disabled = disabled;

            if (list_out) {
                /* Internal call: store compiled filter directly */
                rule->c_tagfilter = temp_dfilter;
                *list_out = g_slist_append(*list_out, rule);
            } else {
                /* External (import/clone) call: caller doesn't need compiled filter */
                dfilter_free(temp_dfilter);
                add_cb(rule, cb_data);
            }
        }

        /* Reset for next rule */
        disabled         = false;
        skip_end_of_line = false;
    }

    if (ferror(f))
        ret = errno;

    g_free(name);
    g_free(filter);
    g_free(tag_content);
    g_free(tag_url);
    g_free(comment);
    return ret;
}

/* ---------------------------------------------------------------------------
 * File I/O — write
 * ------------------------------------------------------------------------- */

/*
 * Write a single rule to file f.
 * The comment field is written last; because it is delimited by end-of-line
 * rather than '@', it may contain '@' characters without escaping.
 */
static void
write_tagrule(tag_rule_t *rule, FILE *f)
{
    char *ename    = escape_field(rule->rule_name    ? rule->rule_name    : "");
    char *efilter  = escape_field(rule->filter_text  ? rule->filter_text  : "");
    char *etag     = escape_field(rule->tag_content  ? rule->tag_content  : "");
    char *eurl     = escape_field(rule->tag_url      ? rule->tag_url      : "");
    fprintf(f, "%s@%s@%s@%s@%s@%s\n",
            rule->disabled ? "!" : "",
            ename, efilter, etag, eurl,
            rule->comment); /* comment is end-of-line terminated — no escaping needed */
    g_free(ename);
    g_free(efilter);
    g_free(etag);
    g_free(eurl);
}

static void
write_tagrule_cb(void *rule_arg, void *f_arg)
{
    write_tagrule((tag_rule_t *)rule_arg, (FILE *)f_arg);
}

static bool
write_tagrules_file(GSList *list, FILE *f, const tag_prefs_t *tprefs)
{
    fprintf(f, "# This file was created by Wireshark. Edit with care.\n");
    if (tprefs) {
        fprintf(f, "#prefs:sep=%02x,emoji_size=%d,click=%d\n",
                (unsigned char)tprefs->separator,
                tprefs->emoji_size,
                (int)tprefs->link_click);
    }
    g_slist_foreach(list, write_tagrule_cb, f);
    return true;
}

/* ---------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

static void
load_tagrules_from_path(const char *path)
{
    FILE *f;
    int   ret;

    if ((f = ws_fopen(path, "r")) == NULL) {
        if (errno != ENOENT) {
            report_warning("Could not open tag rules file \"%s\": %s.",
                           path, g_strerror(errno));
        }
        return;
    }
    ret = read_tagrules_file(path, f, &tag_rule_list, NULL, NULL);
    if (ret != 0) {
        report_warning("Error reading tag rules file \"%s\": %s.",
                       path, g_strerror(ret));
    }
    fclose(f);
}

void
tag_rules_init(void)
{
    char *path;

    tag_rule_list_delete(&tag_rule_list);

    /* Load current-profile rules from the profile directory */
    path = get_persconffile_path(TAGRULES_FILE_NAME, true, NULL);
    load_tagrules_from_path(path);
    g_free(path);
}

void
tag_rules_reload(void)
{
    tag_rules_init();
}

GSList *
tag_rules_read_path(const char *path, char **err_msg)
{
    FILE   *f;
    GSList *list = NULL;
    int     ret;

    if ((f = ws_fopen(path, "r")) == NULL) {
        if (err_msg)
            *err_msg = ws_strdup_printf("Could not open\n%s\nfor reading: %s.",
                                       path, g_strerror(errno));
        return NULL;
    }
    ret = read_tagrules_file(path, f, &list, NULL, NULL);
    fclose(f);
    if (ret != 0) {
        if (err_msg)
            *err_msg = ws_strdup_printf("Error reading\n\"%s\": %s.", path, g_strerror(ret));
        tag_rule_list_delete(&list);
        return NULL;
    }
    return list;
}

bool
tag_rules_write_path(GSList *list, const char *path,
                     const tag_prefs_t *tprefs, char **err_msg)
{
    FILE *f;

    if ((f = ws_fopen(path, "w+")) == NULL) {
        if (err_msg) *err_msg = ws_strdup_printf("Could not open\n%s\nfor writing: %s.",
                                                  path, g_strerror(errno));
        return false;
    }
    write_tagrules_file(list, f, tprefs);
    fclose(f);
    return true;
}

bool
tag_rules_write(void)
{
    char *path;
    char *err_msg = NULL;
    bool  ok;

    path = get_persconffile_path(TAGRULES_FILE_NAME, true, NULL);
    ok = tag_rules_write_path(tag_rule_list, path, &tag_prefs, &err_msg);
    if (!ok) {
        report_warning("%s", err_msg);
        g_free(err_msg);
    }
    g_free(path);

    return ok;
}

void
tag_rules_clone(tag_rule_add_cb_func cb, void *user_data)
{
    for (GSList *curr = tag_rule_list; curr != NULL; curr = g_slist_next(curr)) {
        tag_rule_t *orig = (tag_rule_t *)curr->data;
        tag_rule_t *clone;

        clone           = tag_rule_new(orig->rule_name, orig->filter_text,
                                       orig->tag_content, orig->tag_url,
                                       orig->comment);
        clone->disabled = orig->disabled;
        /* c_tagfilter is not cloned; caller compiles as needed */
        cb(clone, user_data);
    }
}

void
tag_rules_apply(GSList *new_list)
{
    /* Free the old list */
    tag_rule_list_delete(&tag_rule_list);
    tag_rule_list = new_list;

    /* Compile all filters in the new list */
    for (GSList *curr = tag_rule_list; curr != NULL; curr = g_slist_next(curr)) {
        tag_rule_t *rule   = (tag_rule_t *)curr->data;
        df_error_t *df_err = NULL;

        dfilter_free(rule->c_tagfilter);
        rule->c_tagfilter = NULL;

        if (rule->disabled || rule->filter_text == NULL || rule->filter_text[0] == '\0')
            continue;

        if (!dfilter_compile(rule->filter_text, &rule->c_tagfilter, &df_err)) {
            report_warning("Disabling tag rule \"%s\": could not compile filter \"%s\".\n%s",
                           rule->rule_name, rule->filter_text, df_err->msg);
            df_error_free(&df_err);
            rule->disabled = true;
        }
    }
}

const GSList *
tag_rules_get_list(void)
{
    return tag_rule_list;
}


bool
tag_rules_export_list(GSList *list, const char *path, char **err_msg)
{
    FILE *f;

    if ((f = ws_fopen(path, "w+")) == NULL) {
        if (err_msg) *err_msg = ws_strdup_printf("Could not open\n%s\nfor writing: %s.",
                                                  path, g_strerror(errno));
        return false;
    }
    write_tagrules_file(list, f, NULL);
    fclose(f);
    return true;
}

void
tag_rule_list_free(GSList *list)
{
    tag_rule_list_delete(&list);
}

void
tag_rules_prime_edt(epan_dissect_t *edt)
{
    for (GSList *curr = tag_rule_list; curr != NULL; curr = g_slist_next(curr)) {
        tag_rule_t *rule = (tag_rule_t *)curr->data;
        if (!rule->disabled && rule->c_tagfilter != NULL)
            epan_dissect_prime_with_dfilter(edt, rule->c_tagfilter);
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
