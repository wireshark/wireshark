/* packet-IEEE1609dot2.c
 * Routines for IEEE 1609.2
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Also contains IEEE std 1609.12
 * section 4.1.3 PSID allocations
 */

#include "config.h"

#include <stdlib.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <wsutil/array.h>

#include "packet-oer.h"
#include "packet-ieee1609dot2.h"

#define PNAME  "IEEE1609dot2"
#define PSNAME "IEEE1609dot2"
#define PFNAME "ieee1609dot2"

void proto_register_ieee1609dot2(void);
void proto_reg_handoff_ieee1609dot2(void);

/* Initialize the protocol and registered fields */
int proto_ieee1609dot2;
dissector_handle_t proto_ieee1609dot2_handle;

/* WSMP PSID range to be passed to IEEE 1609.2 dissector */
static range_t *global_wsmp_psid_range;
/* This is used for WSMP PSID range */
#define DEFAULT_WSMP_PSID_RANGE "32,39,128,129,130,131,132,133,135,142,143,144,145,2113685,2113686,2113687,2113689"
#define MAX_WSMP_PSID           4294967295
#include "packet-ieee1609dot2-hf.c"

/* Initialize the subtree pointers */
static int ett_ieee1609dot2_ssp;
#include "packet-ieee1609dot2-ett.c"

static dissector_table_t unsecured_data_subdissector_table;
static dissector_table_t ssp_subdissector_table;

typedef struct ieee1609_private_data {
  tvbuff_t *unsecured_data;
  uint64_t psidssp; // psid for Service Specific Permissions
} ieee1609_private_data_t;

void
ieee1609dot2_set_next_default_psid(packet_info *pinfo, uint32_t psid)
{
  p_add_proto_data(wmem_file_scope(), pinfo, proto_ieee1609dot2, 0, GUINT_TO_POINTER(psid));
}

#include "packet-ieee1609dot2-fn.c"


static void
ieee1609dot2_NinetyDegreeInt_fmt(char *s, uint32_t v)
{
  int32_t lat = (int32_t)v;
  if (lat == 900000001) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable(%d)", lat);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
               abs(lat) / 10000000,
               abs(lat) % 10000000 * 6 / 1000000,
               abs(lat) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
               (lat >= 0) ? 'N' : 'S',
               lat);
  }
}

static void
ieee1609dot2_OneEightyDegreeInt_fmt(char *s, uint32_t v)
{
  int32_t lng = (int32_t)v;
  if (lng == 1800000001) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable(%d)", lng);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
               abs(lng) / 10000000,
               abs(lng) % 10000000 * 6 / 1000000,
               abs(lng) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
               (lng >= 0) ? 'E' : 'W',
               lng);
  }
}


static void
ieee1609dot2_Time32_fmt(char *s, uint32_t v)
{
  time_t secs = v + 1072915200 - 5;
  struct tm *tm = gmtime(&secs);
  snprintf(s, ITEM_LABEL_LENGTH, "%u-%02u-%02u %02u:%02u:%02u (%u)",
    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, v
  );
}

static void
ieee1609dot2_Time64_fmt(char *s, uint64_t v)
{
  time_t secs = v / 1000000 + 1072915200 - 5;
  uint32_t usecs = v % 1000000;
  struct tm *tm = gmtime(&secs);
  snprintf(s, ITEM_LABEL_LENGTH, "%u-%02u-%02u %02u:%02u:%02u.%06u (%" PRIu64 ")",
    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, usecs, v
  );
}

/*--- proto_register_ieee1609dot2 ----------------------------------------------*/
void proto_register_ieee1609dot2(void) {

  module_t *ieee1609dot2_module;

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-ieee1609dot2-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-ieee1609dot2-ettarr.c"
        &ett_ieee1609dot2_ssp,
  };

  /* Register protocol */
  proto_ieee1609dot2 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ieee1609dot2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  proto_ieee1609dot2_handle = register_dissector("ieee1609dot2.data", dissect_Ieee1609Dot2Data_PDU, proto_ieee1609dot2);

  // See TS17419_ITS-AID_AssignedNumbers
  unsecured_data_subdissector_table = register_dissector_table("ieee1609dot2.psid",
        "ATS-AID/PSID based dissector for unsecured/signed data", proto_ieee1609dot2, FT_UINT32, BASE_HEX);
  ssp_subdissector_table = register_dissector_table("ieee1609dot2.ssp",
        "ATS-AID/PSID based dissector for Service Specific Permissions (SSP)", proto_ieee1609dot2, FT_UINT32, BASE_HEX);

    range_convert_str(wmem_epan_scope(),
                      &global_wsmp_psid_range,
                      DEFAULT_WSMP_PSID_RANGE,
                      MAX_WSMP_PSID);

    /* Register configuration options */
    ieee1609dot2_module = prefs_register_protocol(proto_ieee1609dot2,
                                                  proto_reg_handoff_ieee1609dot2);

    prefs_register_range_preference(ieee1609dot2_module,
                                    "wsmp.psid",
                                    "WSMP PSIDs",
                                    "WSMP PSIDs to be decoded as IEEE 1609.2 data (default: "
                                    DEFAULT_WSMP_PSID_RANGE ")",
                                    &global_wsmp_psid_range, MAX_WSMP_PSID);
}


void proto_reg_handoff_ieee1609dot2(void) {

    static bool inited = false;
    static range_t *wsmp_psid_range;

    if(!inited) {
        dissector_add_string("media_type", "application/x-its", proto_ieee1609dot2_handle);
        dissector_add_string("media_type", "application/x-its-request", proto_ieee1609dot2_handle);
        dissector_add_string("media_type", "application/x-its-response", proto_ieee1609dot2_handle);
        inited = true;
    } else {
        dissector_delete_uint_range("wsmp.psid", wsmp_psid_range, proto_ieee1609dot2_handle);
        wmem_free(wmem_epan_scope(), wsmp_psid_range);
    }

    /* set port for future deletes */
    wsmp_psid_range = range_copy(wmem_epan_scope(), global_wsmp_psid_range);
    dissector_add_uint_range("wsmp.psid", wsmp_psid_range, proto_ieee1609dot2_handle);

    dissector_add_uint("ieee1609dot2.psid", psid_certificate_revocation_list_application, create_dissector_handle(dissect_SecuredCrl_PDU, proto_ieee1609dot2));
    //dissector_add_uint_range_with_preference("udp.port", "56000,56001", proto_ieee1609dot2_handle);

}
