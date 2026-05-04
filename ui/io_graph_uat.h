/** @file
 *
 * Macros for I/O graph UAT items
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __IO_GRAPH_UAT_H__
#define __IO_GRAPH_UAT_H__

//Allow the enable/disable field to be a checkbox, but for backwards
//compatibility with pre-2.6 versions, the strings are "Enabled"/"Disabled",
//not "true"/"false". (Pre-4.4 versions require "true" to be all-caps.)
#define UAT_BOOL_ENABLE_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    if (tmp_str && ((g_strcmp0(tmp_str, "Enabled") == 0) || \
        (g_ascii_strcasecmp(tmp_str, "true") == 0))) \
        ((rec_t*)rec)->field_name = 1; \
    else \
        ((rec_t*)rec)->field_name = 0; \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%s",((rec_t*)rec)->field_name ? "Enabled" : "Disabled"); \
    *out_len = (unsigned)strlen(*out_ptr); }

/**
 * @brief Checks if the input string is a valid enable/disable value.
 *
 * This function verifies if the provided string represents a valid enable or disable state,
 * including case-insensitive matches for "true" and "false".
 *
 * @param u1 Unused parameter.
 * @param strptr Pointer to the input string.
 * @param len Length of the input string.
 * @param u2 Unused parameter.
 * @param u3 Unused parameter.
 * @param err Pointer to a character pointer where an error message will be stored if validation fails.
 * @return true if the string is a valid enable/disable value, false otherwise.
 */
static bool uat_fld_chk_enable(void* u1 _U_, const char* strptr, unsigned len, const void* u2 _U_, const void* u3 _U_, char** err)
{
    char* str = g_strndup(strptr, len);

    if (str &&
        ((g_strcmp0(str, "Enabled") == 0) ||
            (g_strcmp0(str, "Disabled") == 0) ||
            (g_ascii_strcasecmp(str, "true") == 0) ||  //just for UAT functionality
            (g_ascii_strcasecmp(str, "false") == 0))) {
        *err = NULL;
        g_free(str);
        return true;
    }

    //User should never see this unless they are manually modifying UAT
    *err = ws_strdup_printf("invalid value: %s (must be Enabled or Disabled)", str);
    g_free(str);
    return false;
}

#define UAT_FLD_BOOL_ENABLE(basename,field_name,title,desc) \
{#field_name, title, PT_TXTMOD_BOOL,{uat_fld_chk_enable,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

extern "C" {

#define UAT_FLD_SMA_PERIOD(basename,field_name,title,enum,desc) \
    {#field_name, title, PT_TXTMOD_ENUM,{sma_period_chk_enum,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{&(enum),&(enum),&(enum)},&(enum),desc,FLDFILL}

/**
 * @brief Checks if the SMA period value is valid.
 *
 * @param u1 Unused parameter.
 * @param strptr The string pointer to be checked.
 * @param len The length of the string.
 * @param v Pointer to the value string array.
 * @param u3 Unused parameter.
 * @param err Pointer to store error message if any.
 * @return true If the SMA period is valid.
 * @return false If the SMA period is invalid.
 */
bool sma_period_chk_enum(void* u1 _U_, const char* strptr, unsigned len, const void* v, const void* u3 _U_, char** err);

/**
 * @brief Converts SMA period to a string representation.
 *
 * @param rec Pointer to the record containing the SMA period.
 * @param out_ptr Pointer to the output buffer for the string.
 * @param out_len Pointer to the length of the output buffer.
 * @param vs Pointer to the value string array.
 * @param u2 Unused parameter.
 */
void io_graph_sma_period_tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* vs, const void* u2 _U_);

/**
 * @brief Callback function to set the SMA period for an IO graph.
 *
 * This function processes the input buffer containing the SMA period setting and updates the record accordingly.
 *
 * @param rec Pointer to the record being updated.
 * @param buf Buffer containing the input string.
 * @param len Length of the input buffer.
 * @param vs Pointer to the value_string array for valid SMA periods.
 * @param u2 Unused parameter.
 */
void io_graph_sma_period_set_cb(void* rec, const char* buf, unsigned len, const void* vs, const void* u2 _U_);

/**
 * @brief Callback function for enabling/disabling an I/O graph.
 *
 * @param rec Pointer to the record being processed.
 * @param buf Buffer containing the new value.
 * @param len Length of the buffer.
 * @param vs Pointer to the variable settings.
 * @param u2 Unused parameter.
 * @return UAT_BOOL_ENABLE_CB_DEF Return type for boolean enable callbacks.
 */
UAT_BOOL_ENABLE_CB_DEF(io_graph, enabled, io_graph_settings_t)
UAT_CSTRING_CB_DEF(io_graph, name, io_graph_settings_t)
UAT_DISPLAY_FILTER_CB_DEF(io_graph, dfilter, io_graph_settings_t)
UAT_COLOR_CB_DEF(io_graph, color, io_graph_settings_t)
UAT_VS_DEF(io_graph, style, io_graph_settings_t, uint32_t, 0, "Line")
UAT_PROTO_FIELD_CB_DEF(io_graph, yfield, io_graph_settings_t)
UAT_DBL_CB_DEF(io_graph, y_axis_factor, io_graph_settings_t)

/**
 * @brief Callback function to enable or disable AOT (Ahead-of-Time) processing for I/O graphs.
 *
 * @param rec Pointer to the record being processed.
 * @param buf Buffer containing the data to be processed.
 * @param len Length of the data in the buffer.
 * @param vs Pointer to additional user-defined data.
 * @param u2 Unused parameter.
 * @return UAT_BOOL_ENABLE_CB_DEF Return value indicating whether AOT processing should be enabled or disabled.
 */
UAT_BOOL_ENABLE_CB_DEF(io_graph, asAOT, io_graph_settings_t)
}

#endif /* __IO_GRAPH_UAT_H__ */
