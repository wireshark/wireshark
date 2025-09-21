/* aggregation_fields.h
 * Definitions and functions for aggregation fields
 * By Hamdi Miladi <hamdi.miladi@technica-engineering.de>
 * Copyright 2025 Hamdi Miladi
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __AGGREGATION_FIELDS_H__
#define __AGGREGATION_FIELDS_H__

#include <epan/prefs.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Aggregation fields.
 */

typedef struct aggregation_field {
	char	*field;
	int      hf_id;
} aggregation_field_t;

/* Keep the UAT structure local to the aggregation_fields */
void aggregation_field_register_uat(module_t* pref_module);

#ifdef __cplusplus
}
#endif /* __cplusplus */

WS_DLL_PUBLIC
void apply_aggregation_prefs(void);

#endif /* __AGGREGATION_FIELDS_H__ */
