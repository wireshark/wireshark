/* extractors.h
 * Header file for the TRANSUM response time analyzer post-dissector
 * By Paul Offord <paul.offord@advance7.com>
 * Copyright 2016 Advance Seven Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include <epan/prefs.h>
#include <epan/packet.h>

#define MAX_RETURNED_ELEMENTS 16

int extract_uint(proto_tree *tree, int field_id, guint32 *result_array, size_t *element_count);
int extract_ui64(proto_tree *tree, int field_id, guint64 *result_array, size_t *element_count);
int extract_si64(proto_tree *tree, int field_id, guint64 *result_array, size_t *element_count);
int extract_bool(proto_tree *tree, int field_id, gboolean *result_array, size_t *element_count);
