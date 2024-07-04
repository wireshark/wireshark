/* packet-ulp.c
 * Routines for OMA UserPlane Location Protocol packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2014-2019, Pascal Quantin <pascal@wireshark.org>
 * Copyright 2020, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ref OMA-TS-ULP-V2_0_5-20191028-A
 * http://www.openmobilealliance.org
 */

#include "config.h"

#include "math.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-tcp.h"
#include "packet-gsm_map.h"
#include "packet-e164.h"
#include "packet-e212.h"

#define PNAME  "OMA UserPlane Location Protocol"
#define PSNAME "ULP"
#define PFNAME "ulp"

void proto_register_ulp(void);

static dissector_handle_t rrlp_handle;
static dissector_handle_t lpp_handle;

/* IANA Registered Ports
 * oma-ulp         7275/tcp    OMA UserPlane Location
 * oma-ulp         7275/udp    OMA UserPlane Location
 */
#define ULP_PORT    7275

/* Initialize the protocol and registered fields */
static int proto_ulp;


#define ULP_HEADER_SIZE 2

static bool ulp_desegment = true;

#include "packet-ulp-hf.c"
static int hf_ulp_mobile_directory_number;
static int hf_ulp_ganssTimeModels_bit0;
static int hf_ulp_ganssTimeModels_bit1;
static int hf_ulp_ganssTimeModels_bit2;
static int hf_ulp_ganssTimeModels_bit3;
static int hf_ulp_ganssTimeModels_bit4;
static int hf_ulp_ganssTimeModels_spare;

/* Initialize the subtree pointers */
static int ett_ulp;
static int ett_ulp_setid;
static int ett_ulp_thirdPartyId;
static int ett_ulp_ganssTimeModels;
#include "packet-ulp-ett.c"

static dissector_handle_t ulp_tcp_handle;
static dissector_handle_t ulp_pdu_handle;

static const value_string ulp_ganss_id_vals[] = {
  {  0, "Galileo"},
  {  1, "SBAS"},
  {  2, "Modernized GPS"},
  {  3, "QZSS"},
  {  4, "GLONASS"},
  {  5, "BDS"},
  {  0, NULL},
};

static const value_string ulp_ganss_sbas_id_vals[] = {
  {  0, "WAAS"},
  {  1, "EGNOS"},
  {  2, "MSAS"},
  {  3, "GAGAN"},
  {  0, NULL},
};

static void
ulp_ganssDataBitInterval_fmt(char *s, uint32_t v)
{
  if (v == 15) {
    snprintf(s, ITEM_LABEL_LENGTH, "Time interval is not specified (15)");
  } else {
    double interval = (0.1*pow(2, (double)v));

    snprintf(s, ITEM_LABEL_LENGTH, "%gs (%u)", interval, v);
  }
}

static void
ulp_ExtendedEphemeris_validity_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%uh (%u)", 4*v, v);
}

static void
ulp_PositionEstimate_latitude_fmt(char *s, uint32_t v)
{
  double latitude = ((double)v*90)/pow(2,23);

  snprintf(s, ITEM_LABEL_LENGTH, "%g degrees (%u)", latitude, v);
}

static void
ulp_PositionEstimate_longitude_fmt(char *s, uint32_t v)
{
  double longitude = ((double)(int32_t)v*360)/pow(2,24);

  snprintf(s, ITEM_LABEL_LENGTH, "%g degrees (%u)", longitude, v);
}

static void
ulp_NMRelement_rxLev_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RxLev < -110dBm (0)");
  } else if (v == 63) {
    snprintf(s, ITEM_LABEL_LENGTH, "RxLev >= -48dBm (63)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RxLev < %ddBm (%u)", -111+v, -110+v, v);
  }
}

static void
ulp_UTRA_CarrierRSSI_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSSI < -100dBm (0)");
  } else if (v == 76) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSSI >= -25dBm (76)");
  } else if (v > 76) {
    snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSSI < %ddBm (%u)", -101+v, -100+v, v);
  }
}

static void
ulp_PrimaryCCPCH_RSCP_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSCP < -115dBm (0)");
  } else if (v == 91) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSCP >= -25dBm (91)");
  } else if (v > 91) {
    snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSCP < %ddBm (%u)", -116+v, -115+v, v);
  }
}

static void
ulp_CPICH_Ec_N0_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "CPICH Ec/N0 < -24dB (0)");
  } else if (v == 49) {
    snprintf(s, ITEM_LABEL_LENGTH, "CPICH Ec/N0 >= 0dB (49)");
  } else if (v > 49) {
    snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= CPICH Ec/N0 < %.1fdB (%u)", -24.5+((float)v/2), -24+((float)v/2), v);
  }
}

static void
ulp_CPICH_RSCP_fmt(char *s, uint32_t v)
{
  if (v == 123) {
    snprintf(s, ITEM_LABEL_LENGTH, "CPICH RSCP < -120dBm (123)");
  } else if (v > 123) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= CPICH RSCP < %ddBm (%u)", -244+v, -243+v, v);
  } else if (v == 91) {
    snprintf(s, ITEM_LABEL_LENGTH, "CPICH RSCP >= -25dBm (91)");
  } else if (v < 91) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm < CPICH RSCP <= %ddBm (%u)", -116+v, -115+v, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  }
}

static void
ulp_QoP_horacc_fmt(char *s, uint32_t v)
{
  double uncertainty = 10*(pow(1.1, (double)v)-1);

  if (uncertainty < 1000) {
    snprintf(s, ITEM_LABEL_LENGTH, "%fm (%u)", uncertainty, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%fkm (%u)", uncertainty/1000, v);
  }
}

static void
ulp_QoP_veracc_fmt(char *s, uint32_t v)
{
  double uncertainty = 45*(pow(1.025, (double)v)-1);

  snprintf(s, ITEM_LABEL_LENGTH, "%fm (%u)", uncertainty, v);
}

static void
ulp_QoP_delay_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%u)", pow(2, (double)v), v);
}

static const true_false_string ulp_vertical_dir_val = {
  "Downward",
  "Upward"
};

static void
ulp_RelativeTime_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fs (%u)", 0.01*v, v);
}

static void
ulp_RSRP_Range_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRP < -140dBm (0)");
  } else if (v == 97) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRP >= -44dBm (97)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSRP < %ddBm (%u)", -141+v, -140+v, v);
  }
}

static void
ulp_RSRQ_Range_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRQ < -19.5dB (0)");
  } else if (v == 64) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRQ >= -3dB (34)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= RSRQ < %.1fdB (%u)", -20+((float)v/2), -19.5+((float)v/2), v);
  }
}

static void
ulp_SignalDelta_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%sdB (%u)", v ? "0.5" : "0", v);
}

static void
ulp_locationAccuracy_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fm (%u)", 0.1*v, v);
}

static void
ulp_WimaxRTD_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fus (%u)", 0.01*v, v);
}

static void
ulp_WimaxNMR_rssi_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fdBm (%u)", -103.75+(0.25*v), v);
}

static void
ulp_UTRAN_gpsReferenceTimeUncertainty_fmt(char *s, uint32_t v)
{
  double uncertainty = 0.0022*(pow(1.18, (double)v)-1);

  snprintf(s, ITEM_LABEL_LENGTH, "%fus (%u)", uncertainty, v);
}

static const value_string ulp_ganss_time_id_vals[] = {
  {  0, "Galileo"},
  {  1, "QZSS"},
  {  2, "GLONASS"},
  {  3, "BDS"},
  {  0, NULL},
};

static void
ulp_utran_GANSSTimingOfCell_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fus (%u)", 0.25*v, v);
}

static void
ulp_Coordinate_latitude_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%u)",
             ((float)v/8388607.0)*90, v);
}

static void
ulp_Coordinate_longitude_fmt(char *s, uint32_t v)
{
  int32_t longitude = (int32_t) v;

  snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%d)",
             ((float)longitude/8388608.0)*180, longitude);
}

/* Include constants */
#include "packet-ulp-val.h"

typedef struct
{
  uint8_t notif_enc_type;
  uint8_t ganss_req_gen_data_ganss_id;
} ulp_private_data_t;

static ulp_private_data_t* ulp_get_private_data(asn1_ctx_t *actx)
{
  if (actx->private_data == NULL) {
    actx->private_data = wmem_new0(actx->pinfo->pool, ulp_private_data_t);
  }
  return (ulp_private_data_t*)actx->private_data;
}

#include "packet-ulp-fn.c"


static unsigned
get_ulp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  /* PDU length = Message length */
  return tvb_get_ntohs(tvb,offset);
}

static int
dissect_ulp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, ulp_desegment, ULP_HEADER_SIZE,
                   get_ulp_pdu_len, dissect_ULP_PDU_PDU, data);
  return tvb_captured_length(tvb);
}

void proto_reg_handoff_ulp(void);

/*--- proto_register_ulp -------------------------------------------*/
void proto_register_ulp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-ulp-hfarr.c"
    { &hf_ulp_mobile_directory_number,
      { "Mobile Directory Number", "ulp.mobile_directory_number",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit0,
      { "GPS", "ulp.ganssTimeModels.gps",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit1,
      { "Galileo", "ulp.ganssTimeModels.galileo",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit2,
      { "QZSS", "ulp.ganssTimeModels.qzss",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x2000,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit3,
      { "GLONASS", "ulp.ganssTimeModels.glonass",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x1000,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit4,
      { "BDS", "ulp.ganssTimeModels.bds",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0800,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_spare,
      { "Spare", "ulp.ganssTimeModels.spare",
        FT_UINT16, BASE_HEX, NULL, 0x07ff,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ulp,
    &ett_ulp_setid,
    &ett_ulp_thirdPartyId,
    &ett_ulp_ganssTimeModels,
#include "packet-ulp-ettarr.c"
  };

  module_t *ulp_module;


  /* Register protocol */
  proto_ulp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  ulp_tcp_handle = register_dissector("ulp", dissect_ulp_tcp, proto_ulp);
  ulp_pdu_handle = register_dissector("ulp.pdu", dissect_ULP_PDU_PDU, proto_ulp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ulp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ulp_module = prefs_register_protocol(proto_ulp, NULL);

  prefs_register_bool_preference(ulp_module, "desegment_ulp_messages",
    "Reassemble ULP messages spanning multiple TCP segments",
    "Whether the ULP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &ulp_desegment);
}


/*--- proto_reg_handoff_ulp ---------------------------------------*/
void
proto_reg_handoff_ulp(void)
{
    rrlp_handle = find_dissector_add_dependency("rrlp", proto_ulp);
    lpp_handle = find_dissector_add_dependency("lpp", proto_ulp);

    dissector_add_string("media_type","application/oma-supl-ulp", ulp_pdu_handle);
    dissector_add_string("media_type","application/vnd.omaloc-supl-init", ulp_pdu_handle);
    dissector_add_uint_with_preference("tcp.port", ULP_PORT, ulp_tcp_handle);
    dissector_add_uint_with_preference("udp.port", ULP_PORT, ulp_pdu_handle);
}

