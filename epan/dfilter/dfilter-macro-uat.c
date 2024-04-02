/* dfilter-macro.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER
#include "dfilter-macro.h"
#include "dfilter-macro-uat.h"
#include <epan/uat-int.h>
#include <wsutil/filter_files.h>
#include <wsutil/filesystem.h>

/*
 * This file is only used to migrate the dfilter_macros UAT file to the
 * new "dmacros" configuration file. It should be removed eventually.
 */

static dfilter_macro_t* macros;
static unsigned num_macros;

static void macro_uat_free(void* r) {
	dfilter_macro_t* m = (dfilter_macro_t*)r;
	g_free(m->name);
	g_free(m->text);
	g_free(m->priv);
	g_free(m->parts);
	g_free(m->args_pos);
}

static void* macro_uat_copy(void* dest, const void* orig, size_t len _U_) {
	dfilter_macro_t* d = (dfilter_macro_t*)dest;
	const dfilter_macro_t* m = (const dfilter_macro_t*)orig;

	//DUMP_MACRO(m);

	d->name = g_strdup(m->name);
	d->text = g_strdup(m->text);
	d->usable = m->usable;

	if (m->parts) {
		unsigned nparts = 0;

		/*
		 * Copy the contents of m->priv (a "cooked" version
		 * of m->text) into d->priv.
		 *
		 * First we clone m->text into d->priv, this gets
		 * us a NUL terminated string of the proper length.
		 *
		 * Then we loop copying bytes from m->priv into
		 * d-priv.  Since m->priv contains internal ACSII NULs
		 * we use the length of m->text to stop the copy.
		 */

		d->priv = g_strdup(m->text);
		{
			const char* oldText = m->text;
			const char* oldPriv = (const char*)m->priv;
			char* newPriv = (char*)d->priv;
			while(oldText && *oldText) {
				*(newPriv++) = *(oldPriv++);
				oldText++;
			}
		}

		/*
		 * The contents of the m->parts array contains pointers
		 * into various sections of m->priv.  Since it's
		 * an argv style array of ponters, this array is
		 * actually one larger than the number of parts
		 * to hold the final NULL terminator.
		 *
		 * The following copy clones the original m->parts
		 * array into d->parts but then fixes-up the pointers
		 * so that they point into the appropriate sections
		 * of the d->priv.
		 */

		do nparts++; while (m->parts[nparts]);
		d->parts = (char **)g_memdup2(m->parts,(nparts+1)*(unsigned)sizeof(void*));
		nparts = 0;
		while(m->parts[nparts]) {
			if(nparts) {
				d->parts[nparts] = d->parts[nparts - 1] + (m->parts[nparts] - m->parts[nparts - 1]);
			} else {
				d->parts[nparts] = (char *)d->priv;
			}
			nparts++;
		}

		/*
		 * Clone the contents of m->args_pos into d->args_pos.
		 */

		d->args_pos = (int *)g_memdup2(m->args_pos,(--nparts)*(unsigned)sizeof(int));
	}
	return d;
}

static void macro_uat_post_update(void) {

	for (unsigned i = 0; i < num_macros; i++) {
		macro_parse(&macros[i]);
	}
}

static bool macro_name_chk(void *mp, const char *in_name, unsigned name_len,
		const void *u1 _U_, const void *u2 _U_, char **error) {
	dfilter_macro_t* m = (dfilter_macro_t*)mp;
	unsigned i;

	if (name_len == 0) {
		*error = g_strdup("invalid name");
		return false;
	}

	for (i=0; i < name_len; i++) {
		if (!(in_name[i] == '_' || g_ascii_isalnum(in_name[i]) ) ) {
			*error = g_strdup("invalid char in name");
			return false;
		}
	}

	/* When loading (!m->name) or when adding/changing the an item with a
	 * different name, check for uniqueness. NOTE: if a duplicate already
	 * exists (because the user manually edited the file), then this will
	 * not trigger a warning. */
	if (!m->name || g_strcmp0(m->name, in_name)) {
		for (i = 0; i < num_macros; i++) {
			/* This a string field which is always NUL-terminated,
			 * so no need to check name_len. */
			if (!g_strcmp0(in_name, macros[i].name)) {
				*error = ws_strdup_printf("macro '%s' already exists",
							 in_name);
				return false;
			}
		}
	}

	return true;
}

UAT_CSTRING_CB_DEF(macro,name,dfilter_macro_t)
UAT_CSTRING_CB_DEF(macro,text,dfilter_macro_t)

void convert_old_uat_file(void)
{
	uat_t *dfilter_macro_uat = NULL;
	char *err = NULL;

	/* Check if we need to convert an old dfilter_macro configuration file. */
	char *new_path = get_persconffile_path(DMACROS_FILE_NAME, true);
	if (file_exists(new_path)) {
		/* Already converted. */
		g_free(new_path);
		return;
	}
	char *old_path = get_persconffile_path(DFILTER_MACRO_FILENAME, true);
	if (!file_exists(old_path)) {
		/* Nothing to do.*/
		g_free(new_path);
		g_free(old_path);
		return;
	}

	static uat_field_t uat_fields[] =  {
		UAT_FLD_CSTRING_OTHER(macro,name,"Name",macro_name_chk,"The name of the macro."),
		/* N.B. it would be nice if there was a field type for display filters (with
		   auto-completion & colouring), but this wouldn't work here as the filter string
		   will contain $1, etc... */
		UAT_FLD_CSTRING_ISPRINT(macro,text,"Text","The text this macro resolves to."),
		UAT_END_FIELDS
	};

	dfilter_macro_uat = uat_new("Display Filter Macros",
				    sizeof(dfilter_macro_t),
				    DFILTER_MACRO_FILENAME,
				    true,
				    &macros,
				    &num_macros,
				    UAT_AFFECTS_FIELDS,
				    "ChDisplayFilterMacrosSection",
				    macro_uat_copy,
				    NULL,
				    macro_uat_free,
				    macro_uat_post_update,
				    NULL,
				    uat_fields);

	if (uat_load(dfilter_macro_uat, old_path, &err)) {
		if (num_macros > 0) {
			// We expect the new list to be empty.
			filter_list_t *list = ws_filter_list_read(DMACROS_LIST);
			for (unsigned i = 0; i < num_macros; i++) {
				if (macros[i].usable) {
					// Add only if it is a new entry
					if (ws_filter_list_find(list, macros[i].name) == NULL) {
						ws_filter_list_add(list,
							macros[i].name,
							macros[i].text);
					}
				}
			}
			ws_filter_list_write(list);
			ws_filter_list_free(list);
		}
	}
	else {
		ws_message("Error loading '%s' UAT: %s", DFILTER_MACRO_FILENAME, err);
		g_free(err);
	}
	uat_destroy(dfilter_macro_uat);
	g_free(new_path);
	g_free(old_path);
}
