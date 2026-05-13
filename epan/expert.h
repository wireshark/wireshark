/** @file
 * Collecting of Expert information.
 *
 * For further info, see WSDG: 9.3. How to add an expert item:
 *    https://www.wireshark.org/docs/wsdg_html/#ChDissectExpertInfo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <epan/proto.h>
#include <epan/packet_info.h>
#include <wsutil/value_string.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** only for internal and display use. */
typedef struct expert_info_s {
	uint32_t     packet_num;
	int          group;    /* from a bitfield, should probably be unsigned */
	int          severity; /* from a bitfield, should probably be unsigned */
	int          hf_index; /* hf_index of the expert item. Might be -1. */
	const char *protocol;
	char        *summary;
	proto_item  *pitem;
} expert_info_t;

/* Expert Info and Display hf data */
typedef struct expert_field
{
	int ei;
	int hf;
} expert_field;

#define EI_INIT_EI 0
#define EI_INIT_HF 0
#define EI_INIT {EI_INIT_EI, EI_INIT_HF}

typedef struct expert_field_info {
	/* ---------- set by dissector --------- */
	const char       *name;
	int               group;
	int               severity;
	const char       *summary;

	/* ------- set by register routines (prefilled by EXPFILL macro, see below) ------ */
	int               id;
	const char       *protocol;
	int               orig_severity; /* Matches severity when registered, used to restore original severity
					  * if UAT severity entry is removed */
	struct expert_field_info *same_name_next; /**< Link to next ei with the same abbrev */
	hf_register_info  hf_info;

} expert_field_info;

#define EXPFILL 0, NULL, 0, NULL, \
        {0, {NULL, NULL, FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}}

typedef struct ei_register_info {
	expert_field      *ids;         /**< written to by register() function */
	expert_field_info  eiinfo;      /**< the field info to be registered */
} ei_register_info;

typedef struct expert_module expert_module_t;

#define PRE_ALLOC_EXPERT_FIELDS_MEM 5000

/* "proto_expert" is exported from libwireshark.dll.
 * Thus we need a special declaration.
 */
WS_DLL_PUBLIC int proto_expert;

/**
 * @brief Initializes expert system.
 *
 * This function initializes the expert system, setting up necessary data structures and resources.
 */
extern void
expert_init(void);

/**
 * @brief Initializes the expert system for each packet.
 *
 * This function initializes the expert system for each packet, setting up necessary data structures and resources.
 */
extern void
expert_packet_init(void);

/**
 * @brief Cleans up resources used by expert processing.
 */
extern void
expert_cleanup(void);

/**
 * @brief Cleans up resources used by expert processing.
 *
 * This function is responsible for cleaning up any resources that were allocated
 * during the initialization and operation of expert processing in Wireshark.
 */
extern void
expert_packet_cleanup(void);

/**
 * @brief Get the highest severity of expert information.
 *
 * @return The highest severity level.
 */
WS_DLL_PUBLIC int
expert_get_highest_severity(void);

/**
 * @brief Update the expert info comment count.
 *
 * @param count The new comment count.
 */
WS_DLL_PUBLIC void
expert_update_comment_count(uint64_t count);

/**
 * @brief Add an expert info.
 *
 * Add an expert info tree to a protocol item using registered expert info item
 * @param pinfo Packet info of the currently processed packet. May be NULL if
 *       pi is supplied
 * @param pi Current protocol item (or NULL)
 * @param eiindex The registered expert info item
 * @return the newly created expert info tree
 */
WS_DLL_PUBLIC proto_item *
expert_add_info(packet_info *pinfo, proto_item *pi, expert_field *eiindex);

/** Add an expert info.
 Add an expert info tree to a protocol item using registered expert info item,
 but with a formatted message.
 @param pinfo Packet info of the currently processed packet. May be NULL if
        pi is supplied
 @param pi Current protocol item (or NULL)
 @param eiindex The registered expert info item
 @param format Printf-style format string for additional arguments
 @return the newly created expert info tree
 */
WS_DLL_PUBLIC proto_item *
expert_add_info_format(packet_info *pinfo, proto_item *pi, expert_field *eiindex,
                       const char *format, ...) G_GNUC_PRINTF(4, 5);

/** Add an expert info associated with some byte data
 Add an expert info tree to a protocol item using registered expert info item.
 This function is intended to replace places where a "text only" proto_tree_add_xxx
 API + expert_add_info would be used.
 @param tree Current protocol tree (or NULL)
 @param pinfo Packet info of the currently processed packet. May be NULL if tree is supplied
 @param eiindex The registered expert info item
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @return the newly created item above expert info tree
 */
WS_DLL_PUBLIC proto_item *
proto_tree_add_expert(proto_tree *tree, packet_info *pinfo, expert_field *eiindex,
        tvbuff_t *tvb, unsigned start, unsigned length);

/**
 * @brief Add an expert info associated with some byte data
 *
 * Add an expert info tree to a protocol item using registered expert info item.
 * This function is intended to replace places where a "text only" proto_tree_add_xxx
 * API + expert_add_info would be used. Length will be to the end of the tvb.

 * @param tree Current protocol tree (or NULL)
 * @param pinfo Packet info of the currently processed packet. May be NULL if tree is supplied
 * @param eiindex The registered expert info item
 * @param tvb the tv buffer of the current data
 * @param start start of data in tvb
 * @return the newly created item above expert info tree
 */

WS_DLL_PUBLIC proto_item*
proto_tree_add_expert_remaining(proto_tree* tree, packet_info* pinfo, expert_field* eiindex,
	tvbuff_t* tvb, unsigned start);

/**
 * @brief Add an expert info associated with some byte data
 *
 * Add an expert info tree to a protocol item, using registered expert info item,
 * but with a formatted message.
 * Add an expert info tree to a protocol item using registered expert info item.
 * This function is intended to replace places where a "text only" proto_tree_add_xxx
 * API + expert_add_info_format
 * would be used.
 *
 * @param tree Current protocol tree (or NULL)
 * @param pinfo Packet info of the currently processed packet. May be NULL if tree is supplied
 * @param eiindex The registered expert info item
 * @param tvb the tv buffer of the current data
 * @param start start of data in tvb
 * @param length length of data in tvb
 * @param format Printf-style format string for additional arguments
 * @return the newly created item above expert info tree
 */
WS_DLL_PUBLIC proto_item *
proto_tree_add_expert_format(proto_tree *tree, packet_info *pinfo, expert_field *eiindex,
        tvbuff_t *tvb, unsigned start, unsigned length, const char *format, ...) G_GNUC_PRINTF(7, 8);

/** Same as proto_tree_add_expert_format but without the length parameter, length
 will be sret to end of the tvb.
 Add an expert info associated with some byte data
 Add an expert info tree to a protocol item, using registered expert info item,
 but with a formatted message.
 Add an expert info tree to a protocol item using registered expert info item.
 This function is intended to replace places where a "text only" proto_tree_add_xxx
 API + expert_add_info_format
 would be used.
 @param tree Current protocol tree (or NULL)
 @param pinfo Packet info of the currently processed packet. May be NULL if tree is supplied
 @param eiindex The registered expert info item
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param format Printf-style format string for additional arguments
 @return the newly created item above expert info tree
 */
WS_DLL_PUBLIC proto_item*
proto_tree_add_expert_format_remaining(proto_tree* tree, packet_info* pinfo, expert_field* eiindex,
	tvbuff_t* tvb, unsigned start, const char* format, ...) G_GNUC_PRINTF(6, 7);

/**
 * @brief Register that a protocol has expert info.
 * @param id The protocol ID to register.
 * @return A pointer to the expert module for the protocol, or NULL if registration fails.
 */
WS_DLL_PUBLIC expert_module_t *expert_register_protocol(int id);

/**
 * @brief Deregister a expert info.
 * @param abbrev The abbreviation of the expert info to deregister.
 */
void expert_deregister_expertinfo (const char *abbrev);

/**
 * @brief Deregister expert info from a protocol.
 * @param module The expert module for the protocol.
 */
void expert_deregister_protocol (expert_module_t *module);

/**
 * @brief Free deregistered expert infos.
 */
void expert_free_deregistered_expertinfos (void);

/**
 * @brief Get summary text of an expert_info field.
 *
 * This is intended for use in expert_add_info_format or proto_tree_add_expert_format
 * to get the "base" string to then append additional information
 * @param eiindex The registered expert info item
 * @return The summary text of the expert info item, or NULL if the item is not found.
 */
WS_DLL_PUBLIC const char* expert_get_summary(expert_field *eiindex);

/**
 * @brief Register a expert field array.
 * @param module the protocol handle from expert_register_protocol()
 * @param ei the ei_register_info array
 * @param num_records the number of records in exp
 */
WS_DLL_PUBLIC void
expert_register_field_array(expert_module_t *module, ei_register_info *ei, const int num_records);

#define EXPERT_CHECKSUM_DISABLED    -2
#define EXPERT_CHECKSUM_UNKNOWN     -1
#define EXPERT_CHECKSUM_GOOD        0
#define EXPERT_CHECKSUM_BAD         1

WS_DLL_PUBLIC const value_string expert_group_vals[];

WS_DLL_PUBLIC const value_string expert_severity_vals[];

WS_DLL_PUBLIC const value_string expert_checksum_vals[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
