/* field_urls.c
 * User-defined override URLs for the "Filter Field Reference" action
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

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <glib.h>

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/inet_addr.h>
#include <wsutil/report_message.h>
#include <wsutil/strtoi.h>
#include <wsutil/wslog.h>

#include "field_urls.h"

#define MAX_LINELEN 1024

/** Read a line without trailing (CR)LF. Returns -1 on failure.  */
static int
fgetline(char *buf, int size, FILE *fp)
{
    if (fgets(buf, size, fp)) {
        int len = (int)strcspn(buf, "\r\n");
        buf[len] = '\0';
        return len;
    }
    return -1;
}

typedef enum {
    ITEM_TEXT,      /* Compare the text */
    ITEM_INT,       /* An unquoted integer or integer range */
    ITEM_IPV4,      /* An unquoted IPv4 address, address range or CIDR */
    ITEM_IPV6       /* An unquoted IPv6 address, address range or CIDR */
} field_url_item_kind_t;

/* One member of a rule's value set. */
typedef struct {
    field_url_item_kind_t kind;
    bool         is_range;      /* Written as "a..b" */
    int64_t      lo, hi;        /* ITEM_INT: inclusive bounds, lo == hi for a single integer */
    uint32_t     ip4_lo, ip4_hi;/* ITEM_IPV4: inclusive bounds, host byte order */
    ws_in6_addr  ip6_lo, ip6_hi;/* ITEM_IPV6: inclusive bounds, network byte order */
    char        *str;           /* The item's text, casefolded for ITEM_TEXT if the rule is case-insensitive */
} field_url_item_t;

/* The value of the selected field, and what it looks like. */
typedef struct {
    const char  *text;
    bool         is_int;
    int64_t      num;
    bool         is_v4;
    uint32_t     v4;            /* Host byte order */
    bool         is_v6;
    ws_in6_addr  v6;
} field_url_value_t;

/* {<items>}[flags]=<url> */
typedef struct {
    GPtrArray *items;   /* field_url_item_t * */
    bool       contains;
    bool       icase;
    char      *url;
} field_url_rule_t;

/* All the URLs of one line of the file. */
typedef struct {
    GPtrArray *rules;       /* field_url_rule_t *, tried in order */
    char      *default_url; /* Used if no rule matches, can be NULL */
} field_url_entry_t;

static GHashTable *field_urls_table;

static void
field_url_item_free(void *data)
{
    field_url_item_t *item = (field_url_item_t *)data;

    g_free(item->str);
    g_free(item);
}

static void
field_url_rule_free(void *data)
{
    field_url_rule_t *rule = (field_url_rule_t *)data;

    g_ptr_array_free(rule->items, true);
    g_free(rule->url);
    g_free(rule);
}

static void
field_url_entry_free(void *data)
{
    field_url_entry_t *entry = (field_url_entry_t *)data;

    g_ptr_array_free(entry->rules, true);
    g_free(entry->default_url);
    g_free(entry);
}

/* Parse a whole decimal or 0x hexadecimal integer. */
static bool
parse_integer(const char *str, int64_t *val)
{
    uint64_t uval;

    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        if (!ws_basestrtou64(str, NULL, &uval, 16) || uval > INT64_MAX)
            return false;
        *val = (int64_t)uval;
        return true;
    }
    return ws_strtoi64(str, NULL, val);
}

/* Parse an IPv4 or IPv6 address. IPv4 is returned in host byte order. */
static bool
parse_address(const char *str, bool *is_v6, uint32_t *v4, ws_in6_addr *v6)
{
    ws_in4_addr addr4;

    if (ws_inet_pton4(str, &addr4)) {
        *is_v6 = false;
        *v4 = g_ntohl(addr4);
        return true;
    }
    if (ws_inet_pton6(str, v6)) {
        *is_v6 = true;
        return true;
    }
    return false;
}

/*
 * Parse the sides of an address range into the item, which must be of the
 * same family and in order.
 */
static bool
parse_address_range(field_url_item_t *item, const char *lo_str, const char *hi_str)
{
    bool lo_v6, hi_v6;
    uint32_t lo4, hi4;
    ws_in6_addr lo6, hi6;

    if (!parse_address(lo_str, &lo_v6, &lo4, &lo6) || !parse_address(hi_str, &hi_v6, &hi4, &hi6) ||
        lo_v6 != hi_v6)
        return false;

    if (lo_v6) {
        if (memcmp(&lo6, &hi6, sizeof(lo6)) > 0)
            return false;
        item->kind = ITEM_IPV6;
        item->ip6_lo = lo6;
        item->ip6_hi = hi6;
    } else {
        if (lo4 > hi4)
            return false;
        item->kind = ITEM_IPV4;
        item->ip4_lo = lo4;
        item->ip4_hi = hi4;
    }
    return true;
}

/*
 * See if an item is a single address or a CIDR network. Returns 1 if it
 * is, and the item is set up, 0 if it is something else (so it is text),
 * and -1 if it is an address with an invalid prefix length.
 */
static int
parse_address_or_cidr(field_url_item_t *item)
{
    char *slash = strchr(item->str, '/');
    char *addr_str = slash ? g_strndup(item->str, slash - item->str) : g_strdup(item->str);
    bool is_v6;
    uint32_t v4;
    ws_in6_addr v6;
    int prefix = -1;

    if (!parse_address(addr_str, &is_v6, &v4, &v6)) {
        g_free(addr_str);
        return 0;
    }
    g_free(addr_str);

    if (slash != NULL) {
        if (!ws_strtoi(slash + 1, NULL, &prefix) || prefix < 0 || prefix > (is_v6 ? 128 : 32))
            return -1;
    } else {
        prefix = is_v6 ? 128 : 32;
    }

    if (is_v6) {
        item->kind = ITEM_IPV6;
        for (int i = 0; i < 16; i++) {
            int bits = prefix - 8 * i;
            uint8_t mask;

            bits = bits < 0 ? 0 : (bits > 8 ? 8 : bits);
            mask = bits == 0 ? 0 : (uint8_t)(0xff << (8 - bits));
            item->ip6_lo.bytes[i] = v6.bytes[i] & mask;
            item->ip6_hi.bytes[i] = item->ip6_lo.bytes[i] | (uint8_t)~mask;
        }
    } else {
        uint32_t mask = prefix == 0 ? 0 : 0xffffffffU << (32 - prefix);

        item->kind = ITEM_IPV4;
        item->ip4_lo = v4 & mask;
        item->ip4_hi = item->ip4_lo | ~mask;
    }
    return 1;
}

/*
 * Parse a rule starting at the '{' at *pp. Returns the rule, or NULL if
 * it is malformed. Either way *pp is moved past the rule, or to the end
 * of the line if its end could not be found.
 */
static field_url_rule_t *
parse_rule(const char **pp)
{
    const char *p = *pp + 1;    /* Skip '{' */
    field_url_rule_t *rule = g_new0(field_url_rule_t, 1);
    bool closed = false;

    rule->items = g_ptr_array_new_with_free_func(field_url_item_free);

    /* The flags come after the items, so keep the item text as is for now. */
    while (*p) {
        field_url_item_t *item;
        GString *text = g_string_new(NULL);
        bool quoted = false;

        while (*p == ' ' || *p == '\t')
            p++;

        if (*p == '"') {
            quoted = true;
            p++;
            while (*p && *p != '"') {
                if (*p == '\\' && (p[1] == '"' || p[1] == '\\'))
                    p++;
                g_string_append_c(text, *p++);
            }
            if (*p != '"') {
                g_string_free(text, true);
                goto malformed_eol; /* Unterminated quote */
            }
            p++;
            while (*p == ' ' || *p == '\t')
                p++;
        } else {
            while (*p && *p != ',' && *p != '}' && *p != '"' && *p != ' ' && *p != '\t')
                g_string_append_c(text, *p++);
            while (*p == ' ' || *p == '\t')
                p++;
        }

        if (text->len == 0 && !quoted) {
            g_string_free(text, true);
            goto malformed;         /* Empty item */
        }
        if (*p != ',' && *p != '}') {
            g_string_free(text, true);
            goto malformed;         /* Junk after an item */
        }

        item = g_new0(field_url_item_t, 1);
        item->str = g_string_free(text, false);
        if (!quoted) {
            char *dots = strstr(item->str, "..");
            if (dots != NULL) {
                char *lo_str = g_strndup(item->str, dots - item->str);
                bool ok = false;

                if (parse_integer(lo_str, &item->lo) && parse_integer(dots + 2, &item->hi)) {
                    item->kind = ITEM_INT;
                    ok = item->lo <= item->hi;
                } else {
                    ok = parse_address_range(item, lo_str, dots + 2);
                }
                g_free(lo_str);
                if (!ok) {
                    field_url_item_free(item);
                    goto malformed; /* Bad range */
                }
                item->is_range = true;
            } else if (parse_integer(item->str, &item->lo)) {
                item->hi = item->lo;
                item->kind = ITEM_INT;
            } else if (parse_address_or_cidr(item) < 0) {
                field_url_item_free(item);
                goto malformed;     /* Bad prefix length */
            }
        }
        g_ptr_array_add(rule->items, item);

        if (*p == '}') {
            p++;
            closed = true;
            break;
        }
        p++;    /* Skip ',' */
    }
    if (!closed)
        goto malformed_eol;

    /* Flags */
    for (;; p++) {
        if (*p == 'i')
            rule->icase = true;
        else if (*p == '*')
            rule->contains = true;
        else
            break;
    }
    if (*p != '=')
        goto malformed_token;
    p++;

    {
        size_t len = strcspn(p, " \t");
        if (len == 0)
            goto malformed_token;   /* No URL */
        rule->url = g_strndup(p, len);
        p += len;
    }

    /* now we know the flags, so finish the items. */
    for (unsigned i = 0; i < rule->items->len; i++) {
        field_url_item_t *item = (field_url_item_t *)g_ptr_array_index(rule->items, i);

        if (rule->contains) {
            if (item->is_range)
                goto malformed_token;   /* A range can't be searched for */
            item->kind = ITEM_TEXT;     /* Search for the text */
        }
        if (rule->icase && item->kind == ITEM_TEXT) {
            char *folded = g_utf8_casefold(item->str, -1);
            g_free(item->str);
            item->str = folded;
        }
    }

    *pp = p;
    return rule;

malformed_token:
    /* Skip the rest of this token. */
    p += strcspn(p, " \t");
    *pp = p;
    field_url_rule_free(rule);
    return NULL;

malformed:
    /* Resume after the closing '}' if there is one. */
    {
        const char *close = strchr(p, '}');

        if (close == NULL)
            goto malformed_eol;
        p = close + 1;
    }
    goto malformed_token;

malformed_eol:
    *pp = p + strlen(p);
    field_url_rule_free(rule);
    return NULL;
}

/*
 * File format is <abbrev> followed by whitespace-separated rules,
 * "{<items>}[flags]=<url>", and optionally a URL to use if no rule matches.
 * A line with only a URL after the abbreviation is the simple form.
 * Lines whose first non-blank character is '#' are comments. A '#'
 * elsewhere is part of the URL (e.g. a fragment), so it is not treated as
 * a comment.
 */
static bool
read_field_urls_file(const char *path)
{
    FILE *fp;
    char line[MAX_LINELEN];

    if ((fp = ws_fopen(path, "r")) == NULL)
        return false;

    while (fgetline(line, sizeof(line), fp) >= 0) {
        char *abbrev;
        const char *p;
        size_t len;
        field_url_entry_t *entry;

        abbrev = line + strspn(line, " \t");
        if (abbrev[0] == '\0')
            continue; /* blank line */

        if (abbrev[0] == '#')
            continue; /* comment */

        len = strcspn(abbrev, " \t");
        if (abbrev[len] == '\0')
            continue; /* no URL */
        abbrev[len] = '\0';
        p = abbrev + len + 1;

        /* The first entry for an abbreviation wins. */
        if (g_hash_table_contains(field_urls_table, abbrev))
            continue;

        entry = g_new0(field_url_entry_t, 1);
        entry->rules = g_ptr_array_new_with_free_func(field_url_rule_free);

        while (*p) {
            p += strspn(p, " \t");
            if (*p == '\0')
                break;

            if (*p == '{') {
                field_url_rule_t *rule = parse_rule(&p);

                if (rule != NULL) {
                    g_ptr_array_add(entry->rules, rule);
                } else {
                    ws_warning("%s: ignoring a malformed rule for \"%s\"", path, abbrev);
                }
                continue;
            }

            /* A URL: used if no rule matches, and it ends the line. */
            len = strcspn(p, " \t");
            entry->default_url = g_strndup(p, len);
            break;
        }

        if (entry->rules->len == 0 && entry->default_url == NULL) {
            field_url_entry_free(entry);    /* Nothing usable */
            continue;
        }
        g_hash_table_insert(field_urls_table, g_strdup(abbrev), entry);
    }

    fclose(fp);
    return true;
}

static const field_url_entry_t *
field_url_entry_lookup(const char *abbrev)
{
    if (abbrev == NULL)
        return NULL;

    if (field_urls_table == NULL) {
        char *path;

        field_urls_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, field_url_entry_free);

        path = get_persconffile_path(FIELDURLS_FILE_NAME, false, NULL);
        if (!read_field_urls_file(path) && errno != ENOENT) {
            report_open_failure(path, errno, false);
        }
        g_free(path);
    }

    return (const field_url_entry_t *)g_hash_table_lookup(field_urls_table, abbrev);
}

static bool
rule_matches(const field_url_rule_t *rule, const field_url_value_t *value)
{
    char *folded = NULL;
    bool match = false;

    if (rule->icase)
        folded = g_utf8_casefold(value->text, -1);

    for (unsigned i = 0; i < rule->items->len && !match; i++) {
        const field_url_item_t *item = (const field_url_item_t *)g_ptr_array_index(rule->items, i);

        switch (item->kind) {
        case ITEM_INT:
            if (value->is_int)
                match = value->num >= item->lo && value->num <= item->hi;
            else    /* The value isn't a number, see if it is the same text. */
                match = strcmp(value->text, item->str) == 0;
            break;
        case ITEM_IPV4:
            if (value->is_v4)
                match = value->v4 >= item->ip4_lo && value->v4 <= item->ip4_hi;
            else
                match = strcmp(value->text, item->str) == 0;
            break;
        case ITEM_IPV6:
            if (value->is_v6)
                match = memcmp(&value->v6, &item->ip6_lo, sizeof(value->v6)) >= 0 &&
                        memcmp(&value->v6, &item->ip6_hi, sizeof(value->v6)) <= 0;
            else
                match = strcmp(value->text, item->str) == 0;
            break;
        case ITEM_TEXT:
        default:
            {
                const char *text = rule->icase ? folded : value->text;

                if (rule->contains)
                    match = strstr(text, item->str) != NULL;
                else
                    match = strcmp(text, item->str) == 0;
            }
            break;
        }
    }

    g_free(folded);
    return match;
}

/* Get the URL of an entry that applies to a value, or NULL. */
static const char *
field_url_select(const char *abbrev, const char *fieldvalue)
{
    const field_url_entry_t *entry = field_url_entry_lookup(abbrev);

    if (entry == NULL)
        return NULL;

    if (fieldvalue != NULL) {
        field_url_value_t value = { .text = fieldvalue };
        bool is_v6;

        value.is_int = parse_integer(fieldvalue, &value.num);
        if (parse_address(fieldvalue, &is_v6, &value.v4, &value.v6)) {
            value.is_v6 = is_v6;
            value.is_v4 = !is_v6;
        }

        for (unsigned i = 0; i < entry->rules->len; i++) {
            const field_url_rule_t *rule = (const field_url_rule_t *)g_ptr_array_index(entry->rules, i);

            if (rule_matches(rule, &value))
                return rule->url;
        }
    }

    return entry->default_url;
}

/* Append text to out, optionally replacing each '.' and ':' with '-' and
 * percent-encoding it. */
static void
append_expanded(GString *out, const char *text, bool separators_to_dashes, bool escape)
{
    char *tmp = g_strdup(text ? text : "");

    if (separators_to_dashes)
        g_strdelimit(tmp, ".:", '-');

    if (escape) {
        char *escaped = g_uri_escape_string(tmp, NULL, false);
        g_string_append(out, escaped);
        g_free(escaped);
    } else {
        g_string_append(out, tmp);
    }
    g_free(tmp);
}

char *
field_url_expand(const char *url, const char *fieldname, const char *fieldvalue)
{
    GString *out = g_string_new(NULL);
    const char *p = url;

    while (*p) {
        if (g_str_has_prefix(p, "${fieldnameraw}")) {
            append_expanded(out, fieldname, false, false);
            p += strlen("${fieldnameraw}");
        } else if (g_str_has_prefix(p, "${fieldname}")) {
            append_expanded(out, fieldname, true, false);
            p += strlen("${fieldname}");
        } else if (g_str_has_prefix(p, "${fieldvalueraw}")) {
            append_expanded(out, fieldvalue, false, true);
            p += strlen("${fieldvalueraw}");
        } else if (g_str_has_prefix(p, "${fieldvalue}")) {
            append_expanded(out, fieldvalue, true, true);
            p += strlen("${fieldvalue}");
        } else {
            g_string_append_c(out, *p++);
        }
    }

    return g_string_free(out, false);
}

bool
field_url_needs_value(const char *fieldname, const char *protoname)
{
    const char *abbrevs[] = { fieldname, protoname };

    /* The first entry that exists is the one that applies. */
    for (unsigned i = 0; i < G_N_ELEMENTS(abbrevs); i++) {
        const field_url_entry_t *entry = field_url_entry_lookup(abbrevs[i]);

        if (entry == NULL)
            continue;
        if (entry->rules->len > 0)
            return true;
        return entry->default_url != NULL && strstr(entry->default_url, "${fieldvalue") != NULL;
    }

    return false;
}

char *
field_url_for(const char *fieldname, const char *protoname, const char *fieldvalue)
{
    const char *url = field_url_select(fieldname, fieldvalue);

    if (url == NULL)
        url = field_url_select(protoname, fieldvalue);
    if (url == NULL)
        return NULL;

    return field_url_expand(url, fieldname, fieldvalue);
}
