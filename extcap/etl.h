/** @file
 *
 * Copyright 2020, Odysseus Yang
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_ETL_H__
#define __W_ETL_H__

#include "wiretap/wtap.h"
#include "ws_symbol_export.h"
#include "wiretap/wtap_module.h"

#include <glib.h>
#include <stdlib.h>

#include <windows.h>
#include <winsock2.h>
#include <tdh.h>
#include <guiddef.h>

#define LOGGER_NAME L"wireshark etwdump"

typedef struct
{
    EVENT_TRACE_PROPERTIES prop;
    char padding[64];
} SUPER_EVENT_TRACE_PROPERTIES;

typedef struct _PROVIDER_FILTER {
    GUID ProviderId;
    ULONG64 Keyword;
    UCHAR Level;
} PROVIDER_FILTER;

typedef struct _SCENARIO {
    const WCHAR* name;
    const PROVIDER_FILTER ProviderFilter;
} SCENARIO;

#define SCENARIO_KEY L"Scenario-"
extern const struct _SCENARIO g_scenarios[];

/**
 * @brief Dumps ETL data to a PCAPNG file.
 *
 * @param etl_filename The filename of the ETL input file.
 * @param pcapng_filename The filename of the PCAPNG output file.
 * @param params Additional parameters for the dump process.
 * @param err Pointer to an integer that will receive an error code if an error occurs.
 * @param err_info Pointer to a string that will receive an error message if an error occurs.
 * @return wtap_open_return_val The result of the dump operation.
 */
extern wtap_open_return_val etw_dump(const char* etl_filename, const char* pcapng_filename, const char* params, int* err, char** err_info);

/**
 * @brief Adds a new interface to the ETL (Extcap) dump.
 *
 * This function is used to add a new interface to the ETL dump with the specified parameters.
 *
 * @param pkt_encap The packet encapsulation type for the interface.
 * @param interface_name The name of the interface.
 * @param interface_name_length The length of the interface name.
 * @param interface_desc A description of the interface.
 * @param interface_desc_length The length of the interface description.
 */
extern void wtap_etl_add_interface(int pkt_encap, const char* interface_name, unsigned short interface_name_length, const char* interface_desc, unsigned short interface_desc_length);

/**
 * @brief Dumps an ETL record as a Wireshark packet.
 *
 * @param etl_record Pointer to the ETL record data.
 * @param total_packet_length Total length of the packet in bytes.
 * @param original_packet_length Original length of the packet in bytes.
 * @param interface_id Interface ID for the packet.
 * @param is_inbound Boolean indicating if the packet is inbound.
 * @param timestamp Timestamp of the packet.
 * @param pkt_encap Packet encapsulation type.
 * @param comment Optional comment associated with the packet.
 * @param comment_length Length of the comment in bytes.
 */
extern void wtap_etl_rec_dump(char* etl_record, ULONG total_packet_length, ULONG original_packet_length, unsigned int interface_id, BOOLEAN is_inbound, ULARGE_INTEGER timestamp, int pkt_encap, char* comment, unsigned short comment_length);

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
