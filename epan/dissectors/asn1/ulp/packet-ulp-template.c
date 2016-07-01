/* packet-ulp.c
 * Routines for OMA UserPlane Location Protocol packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * ref OMA-TS-ULP-V2_0_2-20140708-A
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
static guint gbl_ulp_tcp_port = 7275;
static guint gbl_ulp_udp_port = 7275;

/* Initialize the protocol and registered fields */
static int proto_ulp = -1;


#define ULP_HEADER_SIZE 2

static gboolean ulp_desegment = TRUE;

#include "packet-ulp-hf.c"
static int hf_ulp_mobile_directory_number = -1;
static int hf_ulp_ganssTimeModels_bit0 = -1;
static int hf_ulp_ganssTimeModels_bit1 = -1;
static int hf_ulp_ganssTimeModels_bit2 = -1;
static int hf_ulp_ganssTimeModels_bit3 = -1;
static int hf_ulp_ganssTimeModels_bit4 = -1;
static int hf_ulp_ganssTimeModels_spare = -1;

/* Initialize the subtree pointers */
static gint ett_ulp = -1;
static gint ett_ulp_setid = -1;
static gint ett_ulp_thirdPartyId = -1;
static gint ett_ulp_ganssTimeModels = -1;
#include "packet-ulp-ett.c"

static dissector_handle_t ulp_tcp_handle;

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
ulp_ganssDataBitInterval_fmt(gchar *s, guint32 v)
{
  if (v == 15) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Time interval is not specified (15)");
  } else {
    double interval = (0.1*pow(2, (double)v));

    g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%u)", interval, v);
  }
}

static void
ulp_ExtendedEphemeris_validity_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u h (%u)", 4*v, v);
}

static void
ulp_PositionEstimate_latitude_fmt(gchar *s, guint32 v)
{
  double latitude = ((double)v*90)/pow(2,23);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g degrees (%u)", latitude, v);
}

static void
ulp_PositionEstimate_longitude_fmt(gchar *s, guint32 v)
{
  double longitude = ((double)(gint32)v*360)/pow(2,24);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g degrees (%u)", longitude, v);
}

static void
ulp_NMRelement_rxLev_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RxLev < -110 dBm (0)");
  } else if (v == 63) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RxLev >= -48 dBm (63)");
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d dBm <= RxLev < %d dBm (%u)", -111+v, -110+v, v);
  }
}

static void
ulp_UTRA_CarrierRSSI_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSSI < -100 dBm (0)");
  } else if (v == 76) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSSI >= -25 dBm (76)");
  } else if (v > 76) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d dBm <= RSSI < %d dBm (%u)", -101+v, -100+v, v);
  }
}

static void
ulp_PrimaryCCPCH_RSCP_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSCP < -115 dBm (0)");
  } else if (v == 91) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSCP >= -25 dBm (91)");
  } else if (v > 91) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d dBm <= RSCP < %d dBm (%u)", -116+v, -115+v, v);
  }
}

static void
ulp_CPICH_Ec_N0_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "CPICH Ec/N0 < -24 dB (0)");
  } else if (v == 49) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "CPICH Ec/N0 >= 0 dB (49)");
  } else if (v > 49) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f dB <= CPICH Ec/N0 < %.1f dB (%u)", -24.5+((float)v/2), -24+((float)v/2), v);
  }
}

static void
ulp_CPICH_RSCP_fmt(gchar *s, guint32 v)
{
  if (v == 123) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "CPICH RSCP < -120 dBm (123)");
  } else if (v > 123) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d dBm <= CPICH RSCP < %d dBm (%u)", -244+v, -243+v, v);
  } else if (v == 91) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "CPICH RSCP >= -25 dBm (91)");
  } else if (v < 91) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d dBm < CPICH RSCP <= %d dBm (%u)", -116+v, -115+v, v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  }
}

static void
ulp_QoP_horacc_fmt(gchar *s, guint32 v)
{
  double uncertainty = 10*(pow(1.1, (double)v)-1);

  if (uncertainty < 1000) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%f m (%u)", uncertainty, v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%f km (%u)", uncertainty/1000, v);
  }
}

static void
ulp_QoP_veracc_fmt(gchar *s, guint32 v)
{
  double uncertainty = 45*(pow(1.025, (double)v)-1);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m (%u)", uncertainty, v);
}

static void
ulp_QoP_delay_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%u)", pow(2, (double)v), v);
}

static const true_false_string ulp_vertical_dir_val = {
  "Downward",
  "Upward"
};

static void
ulp_RelativeTime_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f s (%u)", 0.01*v, v);
}

static void
ulp_RSRP_Range_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSRP < -140 dBm (0)");
  } else if (v == 97) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSRP >= -44 dBm (97)");
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d dBm <= RSRP < %d dBm (%u)", -141+v, -140+v, v);
  }
}

static void
ulp_RSRQ_Range_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSRQ < -19.5dB (0)");
  } else if (v == 64) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSRQ >= -3 dB (34)");
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f dB <= RSRQ < %.1f dB (%u)", -20+((float)v/2), -19.5+((float)v/2), v);
  }
}

static void
ulp_SignalDelta_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%s dB (%u)", v ? "0.5" : "0", v);
}

static void
ulp_locationAccuracy_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f m (%u)", 0.1*v, v);
}

static void
ulp_WimaxRTD_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f us (%u)", 0.01*v, v);
}

static void
ulp_WimaxNMR_rssi_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f dBm (%u)", -103.75+(0.25*v), v);
}

static void
ulp_UTRAN_gpsReferenceTimeUncertainty_fmt(gchar *s, guint32 v)
{
  double uncertainty = 0.0022*(pow(1.18, (double)v)-1);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f us (%u)", uncertainty, v);
}

static const value_string ulp_ganss_time_id_vals[] = {
  {  0, "Galileo"},
  {  1, "QZSS"},
  {  2, "GLONASS"},
  {  3, "BDS"},
  {  0, NULL},
};

static void
ulp_utran_GANSSTimingOfCell_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f us (%u)", 0.25*v, v);
}

static void
ulp_Coordinate_latitude_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%u)",
             ((float)v/8388607.0)*90, v);
}

static void
ulp_Coordinate_longitude_fmt(gchar *s, guint32 v)
{
  gint32 longitude = (gint32) v;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%d)",
             ((float)longitude/8388608.0)*180, longitude);
}

/* Include constants */
#include "packet-ulp-val.h"

typedef struct
{
  guint8 notif_enc_type;
  guint8 ganss_req_gen_data_ganss_id;
} ulp_private_data_t;

static ulp_private_data_t* ulp_get_private_data(asn1_ctx_t *actx)
{
  if (actx->private_data == NULL) {
    actx->private_data = wmem_new0(wmem_packet_scope(), ulp_private_data_t);
  }
  return (ulp_private_data_t*)actx->private_data;
}

#include "packet-ulp-fn.c"


static guint
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
  static gint *ett[] = {
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

  /* Register fields and subtrees */
  proto_register_field_array(proto_ulp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ulp_module = prefs_register_protocol(proto_ulp,proto_reg_handoff_ulp);

  prefs_register_bool_preference(ulp_module, "desegment_ulp_messages",
    "Reassemble ULP messages spanning multiple TCP segments",
    "Whether the ULP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &ulp_desegment);

  /* Register a configuration option for port */
  prefs_register_uint_preference(ulp_module, "tcp.port",
                                 "ULP TCP Port",
                                 "Set the TCP port for ULP messages (IANA registered port is 7275)",
                                 10,
                                 &gbl_ulp_tcp_port);
  prefs_register_uint_preference(ulp_module, "udp.port",
                                 "ULP UDP Port",
                                 "Set the UDP port for ULP messages (IANA registered port is 7275)",
                                 10,
                                 &gbl_ulp_udp_port);

}


/*--- proto_reg_handoff_ulp ---------------------------------------*/
void
proto_reg_handoff_ulp(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t ulp_udp_handle;
  static guint local_ulp_tcp_port, local_ulp_udp_port;

  if (!initialized) {
    dissector_add_string("media_type","application/oma-supl-ulp", ulp_tcp_handle);
    dissector_add_string("media_type","application/vnd.omaloc-supl-init", ulp_tcp_handle);
    ulp_udp_handle = create_dissector_handle(dissect_ULP_PDU_PDU, proto_ulp);
    rrlp_handle = find_dissector_add_dependency("rrlp", proto_ulp);
    lpp_handle = find_dissector_add_dependency("lpp", proto_ulp);
    initialized = TRUE;
  } else {
    dissector_delete_uint("tcp.port", local_ulp_tcp_port, ulp_tcp_handle);
    dissector_delete_uint("udp.port", local_ulp_udp_port, ulp_udp_handle);
  }

  local_ulp_tcp_port = gbl_ulp_tcp_port;
  dissector_add_uint("tcp.port", gbl_ulp_tcp_port, ulp_tcp_handle);
  local_ulp_udp_port = gbl_ulp_udp_port;
  dissector_add_uint("udp.port", gbl_ulp_udp_port, ulp_udp_handle);
}

