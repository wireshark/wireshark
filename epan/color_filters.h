/* color_filters.h
 * Definitions for color filters
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef  __COLOR_FILTERS_H__
#define  __COLOR_FILTERS_H__

#include <glib.h>

#include "ws_symbol_export.h"

#include <wsutil/color.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct epan_dissect;

#define COLORFILTERS_FILE_NAME          "colorfilters"

#define CONVERSATION_COLOR_PREFIX       "___conversation_color_filter___"
/** @file
 *  Color filters.
 */

/* Data for a color filter. */
typedef struct _color_filter {
    char      *filter_name;         /* name of the filter */
    char      *filter_text;         /* text of the filter expression */
    color_t    bg_color;            /* background color for packets that match */
    color_t    fg_color;            /* foreground color for packets that match */
    bool       disabled;            /* set if the filter is disabled */

                                    /* only used inside of color_filters.c */
    struct epan_dfilter *c_colorfilter;  /* compiled filter expression */

                                    /* only used outside of color_filters.c (beside init) */
} color_filter_t;

/** A color filter was added (while importing).
 * (color_filters.c calls this for every filter coming in)
 *
 * @param colorf the new color filter
 * @param user_data from caller
 */
typedef void (*color_filter_add_cb_func)(color_filter_t *colorf, void *user_data);

/** Init the color filters (incl. initial read from file). */
WS_DLL_PUBLIC bool color_filters_init(char** err_msg, color_filter_add_cb_func add_cb);

/** Reload the color filters */
WS_DLL_PUBLIC bool color_filters_reload(char** err_msg, color_filter_add_cb_func add_cb);

/** Cleanup remaining color filter zombies */
WS_DLL_PUBLIC void color_filters_cleanup(void);

/** Color filters currently used?
 *
 * @return true, if filters are used
 */
WS_DLL_PUBLIC bool color_filters_used(void);

/** Are there any temporary coloring filters used?
 *
 * @return true, if temporary coloring filters are used
 */
WS_DLL_PUBLIC bool tmp_color_filters_used(void);

/** Get the filter string of a temporary color filter
 *
 * @param filt_nr a number 1-10 pointing to a temporary color
 * @return the current filter string which is assigned to the specified slot, or NULL if not available.
 */
WS_DLL_PUBLIC char*
color_filters_get_tmp(uint8_t filt_nr);

/** Set the filter string of a temporary color filter
 *
 * @param filt_nr a number 1-10 pointing to a temporary color
 * @param filter the new filter-string
 * @param disabled whether the filter-rule should be disabled
 * @param err_msg a string with error message
 */
WS_DLL_PUBLIC bool
color_filters_set_tmp(uint8_t filt_nr, const char *filter, bool disabled, char **err_msg);

/** Get a temporary color filter.
 *
 * @param filter_num A number from 1 to 10 specifying the color to fetch.
 * @return The corresponding color or NULL.
 */
WS_DLL_PUBLIC const color_filter_t *
color_filters_tmp_color(uint8_t filter_num);

/** Reset the temporary color filters
 *
 */
WS_DLL_PUBLIC bool
color_filters_reset_tmp(char **err_msg);

/* Prime the epan_dissect_t with all the compiled
 * color filters of the current filter list.
 *
 * @param the epan dissector details
 */
WS_DLL_PUBLIC void color_filters_prime_edt(struct epan_dissect *edt);

/** Check if any of the enabled compiled color filters of the current
 * filter list depend on a given header field.
 *
 * @param hfid The header field ID to check
 * @return true if the color filter contains the header field.
 */
WS_DLL_PUBLIC bool
color_filters_use_hfid(int hfid);

/** Check if any of the enabled compiled color filters of the current
 * filter list depend on any field in a given protocol.
 *
 * @param proto_id The protocol ID to check
 * @return true if the color filter contains a field from the protocol
 */
WS_DLL_PUBLIC bool
color_filters_use_proto(int proto_id);

/** Colorize a specific packet.
 *
 * @param edt the dissected packet
 * @return the matching color filter or NULL
 */
WS_DLL_PUBLIC const color_filter_t *
color_filters_colorize_packet(struct epan_dissect *edt);

/** Clone the currently active filter list.
 *
 * @param user_data will be returned by each call to color_filter_add_cb()
 * @param add_cb the callback function to add color filter
 */
WS_DLL_PUBLIC void color_filters_clone(void *user_data, color_filter_add_cb_func add_cb);

/** Load filters (import) from some other filter file.
 *
 * @param path the path to the import file
 * @param user_data will be returned by each call to color_filter_add_cb()
 * @param err_msg a string with error message
 * @param add_cb the callback function to add color filter
 * @return true, if read succeeded
 */
WS_DLL_PUBLIC bool color_filters_import(const char *path, void *user_data, char **err_msg, color_filter_add_cb_func add_cb);

/** Read filters from the global filter file (not the users file).
 *
 * @param user_data will be returned by each call to color_filter_add_cb()
 * @param err_msg a string with error message
 * @param add_cb the callback function to add color filter
 * @return true, if read succeeded
 */
WS_DLL_PUBLIC bool color_filters_read_globals(void *user_data, char** err_msg, color_filter_add_cb_func add_cb);


/** Apply a changed filter list.
 *
 * @param tmp_cfl the temporary color filter list to apply
 * @param edit_cfl the edited permanent color filter list to apply
 * @param err_msg a string with error message
 */
WS_DLL_PUBLIC bool color_filters_apply(GSList *tmp_cfl, GSList *edit_cfl, char** err_msg);

/** Save filters in users filter file.
 *
 * @param cfl the filter list to write
 * @param err_msg a string with error message
 * @return true if write succeeded
 */
WS_DLL_PUBLIC bool color_filters_write(GSList *cfl, char** err_msg);

/** Save filters (export) to some other filter file.
 *
 * @param path the path to the filter file
 * @param cfl the filter list to write
 * @param only_selected true if only the selected filters should be saved
 * @param err_msg a string with error message
 * @return true, if write succeeded
 */
WS_DLL_PUBLIC bool color_filters_export(const char *path, GSList *cfl, bool only_selected, char** err_msg);

/** Create a new color filter (g_malloc'ed).
 *
 * @param name the name of the filter
 * @param filter_string the filter string
 * @param bg_color background color
 * @param fg_color foreground color
 * @param disabled bool
 * @return the new color filter
 */
WS_DLL_PUBLIC color_filter_t *color_filter_new(
    const char *name, const char *filter_string,
    color_t *bg_color, color_t *fg_color, bool disabled);

/** Delete a single color filter (g_free'ed).
 *
 * @param colorf the color filter to be removed
 */
WS_DLL_PUBLIC void color_filter_delete(color_filter_t *colorf);

/** Delete a filter list including all entries.
 *
 * @param cfl the filter list to delete
 */
WS_DLL_PUBLIC void color_filter_list_delete(GSList **cfl);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

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
