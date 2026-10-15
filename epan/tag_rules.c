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
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include <wsutil/wsjson.h>
#include <wsutil/json_dumper.h>

#include <epan/dfilter/dfilter.h>
#include <epan/epan_dissect.h>
#include "tag_rules.h"

/*
 * The tagrules file is a JSONC file (JSON with // and block comments): a
 * top-level array of single-key objects, each of the form
 *
 *  { "<rule name>": { "filter": "...", "tag": "...", "url": "...",
 *                     "comment": "...", "enabled": true } }
 *
 * "tag", "url", "comment" and "enabled" are optional ("enabled" defaults to
 * true).  An optional element keyed TAG_PREFS_KEY holds the display prefs:
 *
 *  { "prefs_for_tagging_rules": { "separator": ",", "emoji_size": 80,
 *                                 "click": "ctrl" } }
 *
 * "click" is one of "single", "ctrl" or "none".
 *
 * The active list is loaded from and written to a single tagrules.jsonc file
 * in the active profile's directory.
 */

/* Reserved element name used for the display prefs; not a valid rule name. */
#define TAG_PREFS_KEY "prefs_for_tagging_rules"

/* The currently active tag rule list */
static GSList *tag_rule_list;

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

static const char *
click_mode_to_str(tag_link_click_mode_t mode)
{
    switch (mode) {
    case TAG_LINK_CLICK_SINGLE: return "single";
    case TAG_LINK_CLICK_NONE:   return "none";
    case TAG_LINK_CLICK_CTRL:
    default:                    return "ctrl";
    }
}

/* Parse the TAG_PREFS_KEY properties object into tag_prefs. */
static void
read_tag_prefs(char *buf, jsmntok_t *props)
{
    char    *str;
    int64_t  val;

    str = json_get_string(buf, props, "separator");
    if (str != NULL)
        tag_prefs.separator = str[0];

    if (json_get_int(buf, props, "emoji_size", &val))
        tag_prefs.emoji_size = (int)val;

    str = json_get_string(buf, props, "click");
    if (str != NULL) {
        if (strcmp(str, "single") == 0)
            tag_prefs.link_click = TAG_LINK_CLICK_SINGLE;
        else if (strcmp(str, "ctrl") == 0)
            tag_prefs.link_click = TAG_LINK_CLICK_CTRL;
        else if (strcmp(str, "none") == 0)
            tag_prefs.link_click = TAG_LINK_CLICK_NONE;
    }
}

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
    long        size;
    char       *buf;
    size_t      nread;
    int         num_tokens;
    jsmntok_t  *tokens;
    int         array_len;
    jsmntok_t  *element;

    if (fseek(f, 0, SEEK_END) == -1)
        return errno;
    size = ftell(f);
    if (size < 0)
        return errno;
    if (fseek(f, 0, SEEK_SET) == -1)
        return errno;
    if (size == 0)
        return 0;

    buf = (char *)g_malloc(size + 1);
    nread = fread(buf, 1, size, f);
    if (ferror(f)) {
        int ret = errno;
        g_free(buf);
        return ret;
    }
    buf[nread] = '\0';

    if (!json_strip_jsonc_comments(buf)) {
        report_warning("Error parsing tagrules.jsonc file\n\"%s\": unterminated block comment.", path);
        g_free(buf);
        return 0;
    }

    num_tokens = json_parse(buf, NULL, 0);
    if (num_tokens <= 0) {
        /* All comments/whitespace or invalid. Just treat it as empty. */
        g_free(buf);
        return 0;
    }

    tokens = (jsmntok_t *)g_malloc(num_tokens * sizeof(jsmntok_t));
    if (json_parse(buf, tokens, num_tokens) <= 0 || tokens[0].type != JSMN_ARRAY) {
        report_warning("Error parsing tagrules.jsonc file\n\"%s\": invalid JSON.", path);
        g_free(tokens);
        g_free(buf);
        return 0;
    }

    array_len = json_get_array_len(&tokens[0]);
    element = json_get_array_index(&tokens[0], 0);

    for (int i = 0; i < array_len; i++, element = json_get_next_object(element)) {
        char       *name, *filter, *tag_content, *tag_url, *comment;
        bool        enabled = true;
        dfilter_t  *temp_dfilter = NULL;
        df_error_t *df_err = NULL;
        tag_rule_t *rule;
        jsmntok_t  *name_tok, *properties_tok;

        if (element->type != JSMN_OBJECT || element->size != 1)
            continue;

        /* "<rule name>": { ... } */
        name_tok = element + 1;
        properties_tok = name_tok + 1;
        if (name_tok->type != JSMN_STRING || properties_tok->type != JSMN_OBJECT)
            continue;

        name = g_strndup(&buf[name_tok->start], (gsize)(name_tok->end - name_tok->start));
        if (!json_decode_string_inplace(name) || name[0] == '\0') {
            g_free(name);
            continue;
        }

        if (strcmp(name, TAG_PREFS_KEY) == 0) {
            read_tag_prefs(buf, properties_tok);
            g_free(name);
            continue;
        }

        filter      = json_get_string(buf, properties_tok, "filter");
        tag_content = json_get_string(buf, properties_tok, "tag");
        tag_url     = json_get_string(buf, properties_tok, "url");
        comment     = json_get_string(buf, properties_tok, "comment");
        json_get_boolean(buf, properties_tok, "enabled", &enabled);

        /* A rule needs a filter */
        if (filter == NULL || filter[0] == '\0') {
            g_free(name);
            continue;
        }

        if (enabled && !dfilter_compile(filter, &temp_dfilter, &df_err)) {
            report_warning("Disabling tag rule: Could not compile \"%s\" "
                           "in tagrules.jsonc file \"%s\".\n%s",
                           name, path, df_err->msg);
            df_error_free(&df_err);
            enabled = false;
        }

        rule           = tag_rule_new(name, filter, tag_content, tag_url, comment);
        rule->disabled = !enabled;
        g_free(name);

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

    g_free(tokens);
    g_free(buf);
    return 0;
}

/* ---------------------------------------------------------------------------
 * File I/O — write
 * ------------------------------------------------------------------------- */

/* Write a single rule to the dumper. */
static void
write_tagrule(tag_rule_t *rule, json_dumper *dumper)
{
    if (rule->rule_name == NULL || strcmp(rule->rule_name, TAG_PREFS_KEY) == 0) {
        ws_warning("Not saving tag rule with reserved or missing name \"%s\"",
                   rule->rule_name ? rule->rule_name : "");
        return;
    }

    json_dumper_begin_object(dumper);
    json_dumper_set_member_name(dumper, rule->rule_name);
    json_dumper_begin_object(dumper);
    json_dumper_set_member_name_const(dumper, "filter");
    json_dumper_value_string(dumper, rule->filter_text ? rule->filter_text : "");
    json_dumper_set_member_name_const(dumper, "tag");
    json_dumper_value_string(dumper, rule->tag_content ? rule->tag_content : "");
    json_dumper_set_member_name_const(dumper, "url");
    json_dumper_value_string(dumper, rule->tag_url ? rule->tag_url : "");
    json_dumper_set_member_name_const(dumper, "comment");
    json_dumper_value_string(dumper, rule->comment ? rule->comment : "");
    json_dumper_set_member_name_const(dumper, "enabled");
    json_dumper_value_anyf(dumper, "%s", rule->disabled ? "false" : "true");
    json_dumper_end_object(dumper);
    json_dumper_end_object(dumper);
}

static void
write_tagrule_cb(void *rule_arg, void *dumper_arg)
{
    write_tagrule((tag_rule_t *)rule_arg, (json_dumper *)dumper_arg);
}

static void
write_tag_prefs(const tag_prefs_t *tprefs, json_dumper *dumper)
{
    char sep[2] = { tprefs->separator, '\0' };

    json_dumper_begin_object(dumper);
    json_dumper_set_member_name_const(dumper, TAG_PREFS_KEY);
    json_dumper_begin_object(dumper);
    json_dumper_set_member_name_const(dumper, "separator");
    json_dumper_value_string(dumper, sep);
    json_dumper_set_member_name_const(dumper, "emoji_size");
    json_dumper_value_anyf(dumper, "%d", tprefs->emoji_size);
    json_dumper_set_member_name_const(dumper, "click");
    json_dumper_value_string(dumper, click_mode_to_str(tprefs->link_click));
    json_dumper_end_object(dumper);
    json_dumper_end_object(dumper);
}

static bool
write_tagrules_file(GSList *list, FILE *f, const tag_prefs_t *tprefs)
{
    json_dumper dumper = {
        .output_file = f,
        .flags = JSON_DUMPER_FLAGS_PRETTY_PRINT,
    };

    fprintf(f, "// This file was created by Wireshark. Edit with care.\n");

    json_dumper_begin_array(&dumper);
    if (tprefs)
        write_tag_prefs(tprefs, &dumper);
    g_slist_foreach(list, write_tagrule_cb, &dumper);
    json_dumper_end_array(&dumper);

    return json_dumper_finish(&dumper);
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
    char *pf_dir_path;
    char *path;
    char *err_msg = NULL;
    bool  ok;

    /* Create the directory that holds personal configuration files,
       if necessary. */
    if (create_persconffile_dir(NULL, &pf_dir_path) == -1) {
        report_warning("Can't create directory\n\"%s\"\nfor tagrules.jsonc file: %s.",
                       pf_dir_path, g_strerror(errno));
        g_free(pf_dir_path);
        return false;
    }

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
