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
#include "wiretap/wtap-int.h"

#include <glib.h>
#include <stdlib.h>
#include <tdh.h>
#include <guiddef.h>

#define LOGGER_NAME L"wireshark etwdump"

typedef struct
{
    EVENT_TRACE_PROPERTIES prop;
    char padding[64];
} SUPER_EVENT_TRACE_PROPERTIES;

extern wtap_open_return_val etw_dump(const char* etl_filename, const char* pcapng_filename, const char* params, int* err, char** err_info);

extern void wtap_etl_add_interface(int pkt_encap, char* interface_name, unsigned short interface_name_length, char* interface_desc, unsigned short interface_desc_length);

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
