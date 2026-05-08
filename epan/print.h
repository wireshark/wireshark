/** @file
 * Definitions for printing packet analysis trees.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <stdio.h>

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/print_stream.h>

#include <wsutil/json_dumper.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* print output format */
typedef enum {
  PR_FMT_TEXT,    /* plain text */
  PR_FMT_PS       /* postscript */
} print_format_e;

/* print_dissections, enum how the dissections should be printed */
typedef enum {
  print_dissections_none,         /* no dissections at all */
  print_dissections_collapsed,    /* no dissection details */
  print_dissections_as_displayed, /* details as displayed */
  print_dissections_expanded      /* all dissection details */
} print_dissections_e;


typedef enum {
  FORMAT_CSV,     /* CSV */
  FORMAT_JSON,    /* JSON */
  FORMAT_EK,      /* JSON bulk insert to Elasticsearch */
  FORMAT_XML      /* PDML output */
} fields_format;

typedef enum {
  PF_NONE = 0x00,
  PF_INCLUDE_CHILDREN = 0x01
} pf_flags;

/*
 * Print user selected list of fields
 */
struct _output_fields;
typedef struct _output_fields output_fields_t;

typedef GSList* (*proto_node_children_grouper_func)(proto_node *node);

/**
 * @brief Create a new instance of output_fields_t.
 *
 * @return A pointer to the newly created output_fields_t structure.
 */
WS_DLL_PUBLIC output_fields_t* output_fields_new(void);

/**
 * @brief Free the memory allocated for an output_fields_t structure.
 *
 * @param info Pointer to the output_fields_t structure to be freed.
 */
WS_DLL_PUBLIC void output_fields_free(output_fields_t* info);

/**
 * @brief Adds a field to the output fields list.
 *
 * @param info Pointer to the output_fields_t structure.
 * @param field The field to be added.
 */
WS_DLL_PUBLIC void output_fields_add(output_fields_t* info, const char* field);

/**
 * @brief Retrieves the list of valid output fields.
 *
 * @param info Pointer to the output_fields_t structure.
 * @return A pointer to the list of valid output fields.
 */
WS_DLL_PUBLIC GSList * output_fields_valid(output_fields_t* info);

/**
 * @brief Gets the number of fields in the output fields list.
 *
 * @param info Pointer to the output_fields_t structure.
 * @return The number of fields in the list.
 */
WS_DLL_PUBLIC size_t output_fields_num_fields(output_fields_t* info);

/**
 * @brief Sets an option for the output fields.
 * @param info Pointer to the output_fields_t structure.
 * @param option The option to set.
 * @return true if the option was successfully set, false otherwise.
 */
WS_DLL_PUBLIC bool output_fields_set_option(output_fields_t* info, char* option);

/**
 * @brief Outputs the list of available fields to a file handle.
 * @param fh File handle where the list of fields will be printed.
 */
WS_DLL_PUBLIC void output_fields_list_options(FILE *fh);

/**
 * @brief Adds a protocol filter to the output fields.
 * @param info Pointer to the output_fields_t structure.
 * @param field The name of the field to be added as a protocol filter.
 * @param filter_flags Flags to specify how the protocol filter should be applied (e.g., whether to include child fields).
 * @return true if the protocol filter was successfully added, false otherwise
 */
WS_DLL_PUBLIC bool output_fields_add_protocolfilter(output_fields_t* info, const char* field, pf_flags filter_flags);

/**
 * @brief Checks if the output fields have columns.
 *
 * @param info Pointer to the output_fields_t structure.
 * @return true if the output fields have columns, false otherwise.
 */
WS_DLL_PUBLIC bool output_fields_has_cols(output_fields_t* info);

/**
 * @brief Outputs fields in a prime EDT format.
 *
 * @param edt The epan_dissect structure containing packet information.
 * @param info The output_fields_t structure containing field information.
 */
WS_DLL_PUBLIC void output_fields_prime_edt(struct epan_dissect *edt, output_fields_t* info);


/**
 * @brief Prints the protocol tree.
 * @param print_dissections The level of dissection details to print.
 * @param print_hex_data Whether to print hexadecimal data.
 * @param edt The epan_dissect structure containing packet information.
 * @param output_only_tables A hash table of tables to print, or NULL to print all tables.
 * @param stream The print stream to which the output will be written.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC bool proto_tree_print(print_dissections_e print_dissections,
                                        bool print_hex_data,
                                        epan_dissect_t *edt,
                                        GHashTable *output_only_tables,
                                        print_stream_t *stream);

/*
 * Hexdump option for displaying data sources:
 */

#define HEXDUMP_SOURCE_MASK           (0x0004U)
#define HEXDUMP_SOURCE_OPTION(option) ((option) & HEXDUMP_SOURCE_MASK)

#define HEXDUMP_SOURCE_MULTI          (0x0000U) /* create hexdumps for all data sources assigned to a frame (legacy tshark behaviour) */
#define HEXDUMP_SOURCE_PRIMARY        (0x0004U) /* create hexdumps for only the frame data */

#define HEXDUMP_TIMESTAMP_MASK        (0x0008U)
#define HEXDUMP_TIMESTAMP_OPTION(option) ((option) & HEXDUMP_TIMESTAMP_MASK)
#define HEXDUMP_TIMESTAMP_NONE        (0x0000U) /* create hexdumps for all data sources assigned to a frame (default behavior) */
#define HEXDUMP_TIMESTAMP             (0x0008U) /* create hexdumps for only the frame data */

/**
 * @brief Prints hexadecimal data to a stream.
 *
 * @param stream The output stream where the hex data will be printed.
 * @param edt The epan dissector context containing the packet information.
 * @param hexdump_options Options for how the hex data should be displayed.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC bool print_hex_data(print_stream_t *stream, epan_dissect_t *edt, unsigned hexdump_options);

/**
 * @brief Writes the preamble for a PDML (Packet Data Markup Language) file.
 *
 * @param fh File handle to write the preamble to.
 * @param filename Name of the capture file, or NULL if not applicable.
 * @param doc_dir Directory containing the XML stylesheet.
 */
WS_DLL_PUBLIC void write_pdml_preamble(FILE *fh, const char* filename, const char* doc_dir);

/**
 * @brief Writes a protocol tree in PDML format to a file.
 *
 * @param fields Output fields structure containing the fields to be printed.
 * @param edt Epan dissector information.
 * @param cinfo Column information.
 * @param fh File handle where the PDML data will be written.
 * @param use_color Whether to use color in the output.
 */
WS_DLL_PUBLIC void write_pdml_proto_tree(output_fields_t* fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh, bool use_color);

/**
 * @brief Writes the final PDML tag to the file.
 *
 * @param fh File handle where the PDML finale should be written.
 */
WS_DLL_PUBLIC void write_pdml_finale(FILE *fh);

// Implementations of proto_node_children_grouper_func
// Groups each child separately
WS_DLL_PUBLIC GSList *proto_node_group_children_by_unique(proto_node *node);
// Groups children by json key (children with the same json key get put in the same group
WS_DLL_PUBLIC GSList *proto_node_group_children_by_json_key(proto_node *node);

/**
 * @brief Writes the JSON preamble to the specified file handle.
 *
 * @param fh File handle where the JSON output will be written.
 * @return json_dumper A json_dumper structure initialized with the provided file handle and pretty print flag.
 */
WS_DLL_PUBLIC json_dumper write_json_preamble(FILE *fh);

/**
 * @brief Writes a protocol tree to JSON format.
 *
 * @param fields Output fields configuration.
 * @param print_dissections Type of dissection to print.
 * @param print_hex_data Whether to include hexadecimal data in the output.
 * @param edt The epan dissector context.
 * @param cinfo Column information.
 * @param node_children_grouper Function to group proto node children.
 * @param dumper JSON dumper for output.
 */
WS_DLL_PUBLIC void write_json_proto_tree(output_fields_t* fields,
                                         print_dissections_e print_dissections,
                                         bool print_hex_data,
                                         epan_dissect_t *edt,
                                         column_info *cinfo,
                                         proto_node_children_grouper_func node_children_grouper,
                                         json_dumper *dumper);

/**
 * @brief Ends JSON output.
 *
 * @param dumper Pointer to the json_dumper structure.
 */
WS_DLL_PUBLIC void write_json_finale(json_dumper *dumper);

/**
 * @brief Writes protocol tree data in a specific format to a file.
 *
 * @param fields Output fields structure containing relevant information.
 * @param print_summary Flag indicating whether to print summary information.
 * @param print_hex_data Flag indicating whether to print hexadecimal data.
 * @param edt Pointer to the epan_dissect_t structure containing dissection data.
 * @param cinfo Pointer to the column_info structure for column formatting.
 * @param fh File handle where the output will be written.
 */
WS_DLL_PUBLIC void write_ek_proto_tree(output_fields_t* fields,
                                       bool print_summary,
                                       bool print_hex_data,
                                       epan_dissect_t *edt,
                                       column_info *cinfo, FILE *fh);

/**
 * @brief Writes the PSML preamble to the specified file.
 *
 * @param cinfo Pointer to column information structure.
 * @param fh File handle where the PSML preamble will be written.
 */
WS_DLL_PUBLIC void write_psml_preamble(column_info *cinfo, FILE *fh);

/**
 * @brief Writes PSML columns to a file.
 *
 * @param edt Pointer to epan_dissect_t structure containing dissection data.
 * @param fh File handle where the PSML columns will be written.
 * @param use_color Boolean indicating whether to use color filtering.
 */
WS_DLL_PUBLIC void write_psml_columns(epan_dissect_t *edt, FILE *fh, bool use_color);

/**
 * @brief Writes the final PSML tag to the file.
 *
 * @param fh File handle where the PSML finale will be written.
 */
WS_DLL_PUBLIC void write_psml_finale(FILE *fh);

/**
 * @brief Writes CSV column titles to a file.
 *
 * @param cinfo Pointer to the column information structure.
 * @param fh File handle where the column titles will be written.
 */
WS_DLL_PUBLIC void write_csv_column_titles(column_info *cinfo, FILE *fh);

/**
 * @brief Writes CSV columns to a file.
 *
 * @param edt Pointer to the epan_dissect_t structure containing dissection data.
 * @param fh File handle where the CSV columns will be written.
 */
WS_DLL_PUBLIC void write_csv_columns(epan_dissect_t *edt, FILE *fh);

/**
 * @brief Writes hexadecimal data from a list of data sources to a file.
 *
 * @param num Number of data sources to process.
 * @param fh File handle where the data will be written.
 * @param edt Pointer to the epan_dissect_t structure containing the data sources.
 */
WS_DLL_PUBLIC void write_carrays_hex_data(uint32_t num, FILE *fh, epan_dissect_t *edt);

/**
 * @brief Writes the preamble for fields output.
 *
 * @param fields Pointer to the output_fields_t structure containing field information.
 * @param fh File handle where the preamble will be written.
 */
WS_DLL_PUBLIC void write_fields_preamble(output_fields_t* fields, FILE *fh);

/**
 * @brief Writes specified fields to a protocol tree.
 *
 * @param fields The output fields to be written.
 * @param edt The dissector information.
 * @param cinfo Column information.
 * @param fh File handle for output.
 */
WS_DLL_PUBLIC void write_fields_proto_tree(output_fields_t* fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh);

/**
 * @brief Writes the finale for fields output.
 *
 * @param fields Pointer to the output_fields_t structure containing field information.
 * @param fh File handle where the finale will be written.
 */
WS_DLL_PUBLIC void write_fields_finale(output_fields_t* fields, FILE *fh);

 /**
  * @brief Retrieves the value of a node field.
  *
  * @param fi Pointer to the field_info structure containing the field information.
  * @param edt Pointer to the epan_dissect_t structure containing the dissection context.
  * @return char* The value of the field as a string, or NULL if not found.
  */

WS_DLL_PUBLIC char* get_node_field_value(field_info* fi, epan_dissect_t* edt);

/**
 * @brief Prints cache field handles.
 *
 * This function retrieves and prints the IDs of the "Data" and "Frame" protocol fields.
 */
extern void print_cache_field_handles(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
