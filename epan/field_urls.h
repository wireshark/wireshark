/** @file
 *
 * User-defined override URLs for the "Filter Field Reference" action
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <stdbool.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define FIELDURLS_FILE_NAME  "fieldurls"  /**< Personal (all profiles) field URL override file. */

/*
 * The "fieldurls" file in the personal configuration directory (shared by
 * all profiles) has one line per field or protocol abbreviation:
 *
 *     <abbrev> <url>
 *     <abbrev> {<items>}[flags]=<url> ... [<default url>]
 *
 * Fields are separated by whitespace and lines starting with '#' are
 * comments. A rule's <items> are a comma separated list of values, each
 * either unquoted (a value, an inclusive range "a..b", an IPv4 or IPv6
 * address, address range or CIDR network, which are compared as addresses
 * to values that are addresses) or double quoted (always text, with \" and
 * \\ as escapes). The optional flags are 'i' (case-insensitive) and '*'
 * (the value contains an item, instead of being equal to it). Rules are
 * tried in order against the value of the selected field and the first
 * match gives the URL. The URL at the end of the line is used if no rule
 * matches. The file is read once, on first use.
 */

/**
 * @brief Replace the placeholders in a URL.
 *
 * - "${fieldname}": fieldname with each '.' replaced by '-' (ip.ttl -> ip-ttl).
 * - "${fieldnameraw}": fieldname as is (ip.ttl).
 * - "${fieldvalue}": fieldvalue with each '.' and ':' replaced by '-' (10.0.0.1 -> 10-0-0-1,
 *   fe80::1 -> fe80--1).
 * - "${fieldvalueraw}": fieldvalue percent-encoded, '.' kept , (a ':' becomes %3A).
 *
 * Other text, including unknown "${...}" sequences, is left untouched.
 *
 * @param url The URL, possibly containing placeholders.
 * @param fieldname Abbreviation of the selected field, e.g. "tcp.len".
 * @param fieldvalue Value of the selected field, or NULL for an empty value.
 * @return The expanded URL, which must be g_free()d.
 */
WS_DLL_PUBLIC char *field_url_expand(const char *url, const char *fieldname, const char *fieldvalue);

/**
 * @brief Check whether the value of a field is needed to get its URL.
 *
 * The value is needed if the entry that applies to the field has rules,
 * which are matched against the value, or if its URL uses a
 * "${fieldvalue}" or "${fieldvalueraw}" placeholder. Getting a field's
 * value can be expensive (e.g. for large byte fields), so callers can use
 * this to avoid computing it when it isn't needed.
 *
 * @param fieldname Abbreviation of the selected field, e.g. "tcp.len".
 * @param protoname Abbreviation of the field's protocol, e.g. "tcp".
 * @return true if there is an entry for the field or protocol and it needs the field value.
 */
WS_DLL_PUBLIC bool field_url_needs_value(const char *fieldname, const char *protoname);

/**
 * @brief Get the user-defined URL for a field, with placeholders expanded.
 *
 * Tries an entry for fieldname, then one for protoname. An entry with rules
 * gives the URL of the first rule that matches fieldvalue, or else its
 * default URL, and if it has neither the next entry is tried.
 *
 * @param fieldname Abbreviation of the selected field, e.g. "tcp.len".
 * @param protoname Abbreviation of the field's protocol, e.g. "tcp".
 * @param fieldvalue Value of the selected field, or NULL for an empty value.
 * @return The expanded URL, which must be g_free()d, or NULL if there is no override.
 */
WS_DLL_PUBLIC char *field_url_for(const char *fieldname, const char *protoname, const char *fieldvalue);

#ifdef __cplusplus
}
#endif /* __cplusplus */
