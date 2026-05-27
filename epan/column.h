/** @file
 * Definitions for column handling routines
 * Column preference and format settings.
 *
 * For internal Wireshark useonly. Don't include this header in dissectors!
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "ws_symbol_export.h"
#include <epan/column-utils.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Defines used in fmt_data.display.
 * The values are legacy from U Unresolved and R Resolved stored in the preferences.
 */
#define COLUMN_DISPLAY_VALUES  'U'
#define COLUMN_DISPLAY_STRINGS 'R'
#define COLUMN_DISPLAY_DETAILS 'D'

/**
 * @brief Describes the configuration of a single column in the packet list.
 */
typedef struct _fmt_data {
    char *title;            /**< User-visible column heading text */
    int   fmt;              /**< Column format type (see COL_* constants), e.g. COL_NUMBER, COL_CUSTOM */
    char *custom_fields;    /**< Semicolon-separated display filter field names used when @p fmt is COL_CUSTOM */
    int   custom_occurrence;/**< Ordinal occurrence of the custom field to display (0 = all occurrences) */
    bool  visible;          /**< True if the column is shown in the packet list; false if hidden */
    char  display;          /**< Aggregation or display modifier for multi-occurrence custom field values */
} fmt_data;

/**
 * @brief Convert a column format number to its corresponding string representation.
 *
 * @param fmt The column format number.
 * @return The string representation of the column format, or NULL if invalid.
 */
WS_DLL_PUBLIC
const char          *col_format_to_string(const int fmt);

/**
 * @brief Get the description of a column format.
 *
 * @param fmt_num The format number to get the description for.
 * @return The description of the column format, or NULL if invalid.
 */
WS_DLL_PUBLIC
const char          *col_format_desc(const int fmt_num);

/**
 * @brief Get the abbreviation of a column format.
 *
 * @param fmt_num The format number to get the abbreviation for.
 * @return The abbreviation of the column format, or NULL if invalid.
 */
WS_DLL_PUBLIC
const char          *col_format_abbrev(const int fmt_num);

/**
 * @brief Get the format of a column.
 *
 * @param col The index of the column.
 * @return The format of the column, or -1 if the column is invalid.
 */
WS_DLL_PUBLIC
int                  get_column_format(const int col);

/**
 * @brief Set the format for a column.
 *
 * @param col The ID of the column to set the format for.
 * @param fmt The format number to set.
 */
WS_DLL_PUBLIC
void                 set_column_format(const int col, const int fmt);

/**
 * @brief Get column format matches based on a boolean array and an integer value.
 *
 * @param[out] fmt_list Array to store the matches.
 * @param[in] format Integer value representing the column format.
 */
WS_DLL_PUBLIC
void                 get_column_format_matches(bool *fmt_list, const int format);

/**
 * @brief Get the column format number from a string representation.
 *
 * @param str The string representation of the column format.
 * @return The column format number corresponding to the string, or -1 if invalid.
 */
WS_DLL_PUBLIC
int                  get_column_format_from_str(const char *str);

/**
 * @brief Get the title of a column.
 *
 * @param col The index of the column.
 * @return char* The title of the column, or NULL if the column is invalid.
 */
WS_DLL_PUBLIC
char                *get_column_title(const int col);

/**
 * @brief Set the title of a column.
 *
 * @param col The index of the column.
 * @param title The new title for the column.
 */
WS_DLL_PUBLIC
void                 set_column_title(const int col, const char *title);

/**
 * @brief Get the visibility status of a column.
 *
 * @param col The index of the column to check.
 * @return true if the column is visible, false otherwise.
 */
WS_DLL_PUBLIC
bool                 get_column_visible(const int col);

/**
 * @brief Set the visibility of a column.
 *
 * @param col The index of the column to set visibility for.
 * @param visible Whether the column should be visible (true) or not (false).
 */
WS_DLL_PUBLIC
void                 set_column_visible(const int col, bool visible);

/**
 * @brief Get the current display format for a column.
 *
 * @param col The index of the column.
 * @return char The current display format.
 */
WS_DLL_PUBLIC
char                 get_column_display_format(const int col);

/**
 * @brief Set the display format for a specific column.
 *
 * @param col The index of the column to set the display format for.
 * @param display The new display format character.
 */
WS_DLL_PUBLIC
void                 set_column_display_format(const int col, char display);

/**
 * @brief Get custom fields for a specific column.
 *
 * @param col The column index.
 * @return const char* Custom fields string or NULL if invalid column.
 */
WS_DLL_PUBLIC
const char          *get_column_custom_fields(const int col);

/**
 * @brief Set custom fields for a specific column.
 *
 * @param col The index of the column.
 * @param custom_fields A string containing the custom fields to set.
 */
WS_DLL_PUBLIC
void                 set_column_custom_fields(const int col, const char *custom_fields);

/**
 * @brief Get the custom occurrence of a column.
 *
 * @param col The column index.
 * @return int The custom occurrence value.
 */
WS_DLL_PUBLIC
int                  get_column_custom_occurrence(const int col);

/**
 * @brief Set a custom occurrence for a specific column.
 *
 * @param col The column index.
 * @param custom_occurrence The custom occurrence value to set.
 */
WS_DLL_PUBLIC
void                 set_column_custom_occurrence(const int col, const int custom_occurrence);

/**
 * @brief Get the text of a column element.
 *
 * The string returned may vary depending on the format specified.
 *
 * @param format The format of the column.
 * @return A string representing the longest possible value for the specified column type.
 */
WS_DLL_PUBLIC
const char          *get_column_longest_string(const int format);

/**
 * @brief Get a string representing the width of a column.
 *
 * Determines the appropriate width for a column based on its format and content.
 *
 * @param format The format of the column.
 * @param col The index of the column.
 * @return A string representing the width of the column.
 */
WS_DLL_PUBLIC
const char          *get_column_width_string(const int format, const int col);

/**
 * @brief Get the character width of a column format.
 *
 * @param format The column format identifier.
 * @return The character width of the specified column format.
 */
WS_DLL_PUBLIC
int                  get_column_char_width(const int format);

/**
 * @brief Get the tooltip text of a column element.
 *
 * The string returned may depend on whether the resolved member variable is set.
 * For internal Wireshark use, not to be called from dissectors.
 * Dissectors use col_get_text() in column-utils.h
 *
 * @param col the column index to use (not the format)
 * @return The tooltip text of the column element or NULL if invalid column requested
 */
WS_DLL_PUBLIC
char                *get_column_tooltip(const int col);

/**
 * @brief Get the text of a column element.
 *
 * The string returned may
 * depend on whether the resolved member variable is set.
 * For internal Wireshark use, not to be called from dissectors.
 * Dissectors use col_get_text() in column-utils.h
 *
 * @param cinfo the column information
 * @param col the column index to use (not the format)
 *
 * @return the text string
 */
WS_DLL_PUBLIC
const char          *get_column_text(column_info *cinfo, const int col);

/**
 * @brief Finalizes a column by compiling custom filters and splitting fields.
 *
 * @param cinfo Pointer to the column information structure.
 */
WS_DLL_PUBLIC
void
col_finalize(column_info *cinfo);

/**
 * @brief Build an array of column formats based on the provided parameters.
 *
 * @param cinfo Pointer to the column information structure.
 * @param num_cols Number of columns to be processed.
 * @param reset_fences Flag indicating whether to reset column fences.
 */
WS_DLL_PUBLIC
void
build_column_format_array(column_info *cinfo, const int num_cols, const bool reset_fences);

/**
 * @brief Dump the available column formats and their descriptions to the console.
 */
WS_DLL_PUBLIC
void                 column_dump_column_formats(void);

/**
 * @brief Parse a column format string into a fmt_data struct.
 *
 * If the format string possibly can be that of a deprecated column
 * that has been migrated to a custom column (e.g., upon first being
 * read from a preference file), call try_convert_to_custom_column() first.
 *
 * @param[out] cfmt The parsed cfmt, still owned by the caller.
 * For custom columns, the caller is responsible for freeing
 * the custom_fields member as well.
 * @param[in] fmt The column format to parse.
 *
 * @return true if conversion was successful, false if unsuccessful
 */
WS_DLL_PUBLIC
bool parse_column_format(fmt_data *cfmt, const char *fmt);

/**
 * @brief Given a fmt_data struct, returns the column format string that should
 * be written to the preferences to generate the fmt_data struct.
 * The inverse of parse_column_format() above.
 *
 * @param[in] cfmt The fmt_data struct.
 *
 * @return A column format string that corresponds to the fmt_data.
 * This string is owned by the caller, and must be freed. Returns
 * NULL if cfmt is NULL.
 */
extern
char * column_fmt_data_to_str(const fmt_data *cfmt);

/**
 * @brief Checks a column format string to see if it is a deprecated column
 * that has been migrated to a custom column, and converts the format
 * to the corresponding custom column format if so, otherwise leaving
 * it unchanged.
 *
 * @param[in,out] fmt The column format to check and possibly convert.
 */
WS_DLL_PUBLIC
void try_convert_to_custom_column(char **fmt);

/**
 * @brief Checks a column field string to see if it is a name of a filter
 * field created using a default column title (as used in tshark -e),
 * and alias it to the new column type based field.
 *
 * @param[in] field The old title based field, e.g. "_ws.col.Info"
 * @return The new field, e.g. "_ws.col.info", or NULL
 */
WS_DLL_PUBLIC
const char* try_convert_to_column_field(const char *field);

/**
 * @brief Registers all fields for Wireshark columns.
 *
 * This function registers all necessary fields for displaying and managing columns in Wireshark.
 * It ensures that the protocol ID is correctly set and then deregisters any existing column fields.
 * If a list of preferred columns is provided, it processes each format to register unique fields.
 */
WS_DLL_PUBLIC
void column_register_fields(void);
#ifdef __cplusplus
}
#endif /* __cplusplus */
