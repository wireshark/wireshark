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
#pragma once
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

/**
 * @brief Registers UAT for aggregation fields.
 *
 * This function registers a User-Accessible Table (UAT) for managing aggregation fields,
 * allowing users to configure and save their preferences persistently across sessions.
 *
 * @param pref_module Pointer to the module structure where preferences are registered.
 */
void aggregation_field_register_uat(module_t* pref_module);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/**
 * @brief Applies aggregation preferences from a UAT (User-Accessible Table) to the global preferences structure.
 *
 * This function frees any existing list of aggregation fields and then rebuilds it based on the current entries in the UAT.
 * It skips empty entries and updates the number of aggregation fields. Finally, it marks the UAT as unchanged.
 */
WS_DLL_PUBLIC
void apply_aggregation_prefs(void);
