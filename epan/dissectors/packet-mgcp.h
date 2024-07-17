/* packet-mgcp.h
 * Routines for mgcp packet disassembly
 * RFC 2705
 *
 * Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /* A simple MGCP type that is occasionally handy */
typedef enum _mgcp_type
{
	MGCP_REQUEST,
	MGCP_RESPONSE,
	MGCP_OTHERS
} mgcp_type_t;

/* Container for tapping relevant data */
typedef struct _mgcp_info_t
{
	mgcp_type_t mgcp_type;
	char code[5];
	uint32_t transid;
	nstime_t req_time;
	bool is_duplicate;
	bool request_available;
	uint32_t req_num; /* frame number request seen */
	char *endpointId;
	char *observedEvents;
	uint32_t rspcode;
	char *signalReq;
	bool hasDigitMap;
	bool is_osmux;
} mgcp_info_t;

/* Item of request list */
typedef struct _mgcp_call_t
{
	uint32_t transid;
	char code[5];
	uint32_t req_num; /* frame number request seen */
	uint32_t rsp_num; /* frame number response seen */
	uint32_t rspcode;
	nstime_t req_time;
	bool responded;
} mgcp_call_t;

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
