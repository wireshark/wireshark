/* aggregation_fields.c
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

#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/uat-int.h>
#include <epan/aggregation_fields.h>

/* UAT variables */
static uat_t                 *uat_aggregation;
static aggregation_field_t   *uat_aggregation_fields;
static unsigned               uat_aggregation_fields_num;

/* Field callbacks. */
UAT_DISPLAY_FILTER_CB_DEF(uat_aggregation, field, aggregation_field_t)

static uat_field_t aggregation_uat_flds[] = {
        UAT_FLD_PROTO_FIELD(uat_aggregation,
            field,
            "Aggregation Field",
            "Fields used to aggregate messages"),
        UAT_END_FIELDS
};

static void aggregation_free_cb(void*r) {
	aggregation_field_t* rec = (aggregation_field_t*)r;
	g_free(rec->field);
}

static void* aggregation_copy_cb(void* n, const void* o, size_t siz _U_) {
	aggregation_field_t* new_record = (aggregation_field_t*)n;
	const aggregation_field_t* old_record = (const aggregation_field_t*)o;
	new_record->field = g_strdup(old_record->field);
	return new_record;
}

static void aggregation_post_cb(void) {
    uat_aggregation->changed = true;
}

void aggregation_field_register_uat(module_t* pref_module) {
	uat_aggregation = uat_new("Aggregation fields",
                                  sizeof(aggregation_field_t),   /* record size */
			          "aggregation_fields",          /* filename */
			          true,                          /* from_profile */
			          &uat_aggregation_fields,       /* data_ptr */
			          &uat_aggregation_fields_num,   /* numitems_ptr */
			          0,                             /* Doesn't not explicitly effect dissection */
			          NULL,                          /* help */
                                  aggregation_copy_cb,           /* copy callback */
			          NULL,                          /* update callback */
			          aggregation_free_cb,           /* free callback */
			          aggregation_post_cb,           /* post update callback */
			          NULL,                          /* reset callback */
                                  aggregation_uat_flds);         /* UAT field definitions */

        prefs_register_uat_preference(pref_module, "aggregation_fields",
            "Aggregation fields",
            "Fields used for aggregation view.",
            uat_aggregation);

        prefs_set_preference_effect(pref_module, "aggregation_fields", PREF_EFFECT_AGGREGATION);
}

void apply_aggregation_prefs(void) {
    g_list_free(prefs.aggregation_fields);
    prefs.aggregation_fields = NULL;
    for (unsigned i = 0; i < uat_aggregation_fields_num; i++) {
        char* field = uat_aggregation_fields[i].field;
        // Skip empty entries
        if (field != NULL && field[0] != '\0')
            prefs.aggregation_fields = g_list_append(prefs.aggregation_fields, field);
    }
    prefs.aggregation_fields_num = g_list_length(prefs.aggregation_fields);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
