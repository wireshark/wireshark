/* packet-rtp-ed137.c
 *
 * Routines for RTP ED-137 extensions dissection
 * RTP = Real time Transport Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <h323@ramdyne.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector tries to dissect the RTP extension headers by ED-137, ED-137A, ED-137B and ED-137C specification
 * of EUROCAE (The European Organisation for Civil Aviation Equipment)
 *
 * There are two packet header extension signatures. One for ED-137 and second ED-137A and later releases. Even some extensions are same in ED-137 and ED-137A, constants and code are duplicated because there are slight differences between standard release.
 * ED-137A and later standards share some extensions (e. g. SQI is defined in ED-137A and repeated without change in ED-137B and C). Naming convention use first standard release where extension was introduced (ED-137A in SQI case).
 *
 * Each ED-137 header extension consists of fixed part and variable part (called "extension for additional features" in standard). The code decodes fixed part and some variable part headers. The code decode only additional headers we seen (we have samples) even standard defines more of it.
 * To allow other developers and vendors to introduce custom decoders, there are dissector tables rtp.hdr_ext.ed137 and rtp.hdr_ext.ed137a which registers dissector for each "additional feature" header by type/length key. It allows anyone extending decoding capabilites just by adding plugin and register dissector in the table - without modifying this source.
 * rtp.hdr_ext.ed137 table is used for ED-137 standard release. rtp.hdr_ext.ed137a table is used for ED-137A and later standard releases.
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>

#include "packet-rtp.h"

static int proto_rtp_ed137      = -1;

static dissector_handle_t rtp_hdr_ext_ed137_handle;
static dissector_handle_t rtp_hdr_ext_ed137a_handle;
static dissector_handle_t rtp_hdr_ext_ed137a_feature_sqi_handle;
static dissector_handle_t rtp_hdr_ext_ed137a_feature_climax_tdly_handle;
static dissector_handle_t rtp_hdr_ext_ed137b_feature_rrc_single_handle;
static dissector_handle_t rtp_hdr_ext_ed137b_feature_climax_ddc_rmm_handle;
static dissector_handle_t rtp_hdr_ext_ed137b_feature_climax_ddc_mam_handle;
static dissector_handle_t rtp_hdr_ext_ed137c_feature_climax_ddc_mam_handle;

static dissector_table_t rtp_hdr_ext_ed137a_add_features_table;

/* RTP header ED-137 extension fields   */
static int hf_rtp_hdr_ed137s    = -1;
static int hf_rtp_hdr_ed137     = -1;
static int hf_rtp_hdr_ed137_add = -1;
static int hf_rtp_hdr_ed137_ptt_type  = -1;
static int hf_rtp_hdr_ed137_squ       = -1;
static int hf_rtp_hdr_ed137_ptt_id    = -1;
static int hf_rtp_hdr_ed137_sct       = -1;
static int hf_rtp_hdr_ed137_x         = -1;
static int hf_rtp_hdr_ed137_x_nu      = -1;
static int hf_rtp_hdr_ed137_ft_type   = -1;
static int hf_rtp_hdr_ed137_ft_len    = -1;
static int hf_rtp_hdr_ed137_ft_value  = -1;
static int hf_rtp_hdr_ed137_ft_bss_qidx  = -1;
static int hf_rtp_hdr_ed137_ft_bss_rssi_qidx  = -1;
static int hf_rtp_hdr_ed137_ft_bss_qidx_ml  = -1;
static int hf_rtp_hdr_ed137_vf  = -1;
static int hf_rtp_hdr_ed137_ft_climax_delay_value = -1;

/* RTP header ED-137A extension fields   */
static int hf_rtp_hdr_ed137a     = -1;
static int hf_rtp_hdr_ed137a_add = -1;
static int hf_rtp_hdr_ed137a_ptt_type  = -1;
static int hf_rtp_hdr_ed137a_squ       = -1;
static int hf_rtp_hdr_ed137a_ptt_id    = -1;
static int hf_rtp_hdr_ed137a_pm        = -1;
static int hf_rtp_hdr_ed137a_ptts      = -1;
static int hf_rtp_hdr_ed137a_sct       = -1;
static int hf_rtp_hdr_ed137a_reserved  = -1;
static int hf_rtp_hdr_ed137a_x         = -1;
static int hf_rtp_hdr_ed137a_x_nu      = -1;
static int hf_rtp_hdr_ed137a_ft_type   = -1;
static int hf_rtp_hdr_ed137a_ft_len    = -1;
static int hf_rtp_hdr_ed137a_ft_value  = -1;
static int hf_rtp_hdr_ed137a_ft_padding  = -1;
static int hf_rtp_hdr_ed137a_ft_sqi_qidx  = -1;
static int hf_rtp_hdr_ed137a_ft_sqi_rssi_qidx  = -1;
static int hf_rtp_hdr_ed137a_ft_sqi_qidx_ml  = -1;
static int hf_rtp_hdr_ed137a_ft_climax_delay_mode  = -1;
static int hf_rtp_hdr_ed137a_ft_climax_delay_relative_value = -1;
static int hf_rtp_hdr_ed137a_ft_climax_delay_absolute_value = -1;

/* RTP header ED-137B extension fields   */
static int hf_rtp_hdr_ed137b_ft_rrc_single = -1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_ms_tx_f1 = -1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_ms_rx_f1 = -1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_ms_tx_f2 = -1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_ms_rx_f2 = -1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_sel_tx_f1 = -1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_sel_tx_f2 = -1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_mu_rx_f1 = -1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_mu_rx_f2 = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_unknown = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_rmm = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_tqv = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_t1 = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tqg = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t1 = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_nmr = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t2 = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tsd = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tj1 = -1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tid = -1;

/* RTP header ED-137C extension fields   */
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam = -1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tqg = -1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t1 = -1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_nmr = -1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t2 = -1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tsd = -1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tj1 = -1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tid = -1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_ts2 = -1;

static gint ett_hdr_ext_ed137s  = -1;
static gint ett_hdr_ext_ed137   = -1;
static gint ett_hdr_ext_ed137_add = -1;
static gint ett_hdr_ext_ed137a  = -1;
static gint ett_hdr_ext_ed137a_add = -1;

/* Forward declaration we need below */
void proto_register_rtp_ed137(void);
void proto_reg_handoff_rtp_ed137(void);

/* Combine 4 bits of type with 4 bits of length to 8 bit key */
#define MAKE_KEY(type, len) \
    ( ( type & 0x0F ) << 4 | ( len & 0x0f ) )

/* ED-137 signature */
#define RTP_ED137_SIG    0x0067

/* ED-137A signature */
#define RTP_ED137A_SIG   0x0167

/* ED-137 PTT */
#define RTP_ED137_ptt_mask(octet)   ((octet) & 0xE0000000)
#define RTP_ED137A_ptt_mask(octet)   ((octet) & 0xE000)
#define RTP_ED137_squ_mask(octet)   ((octet) & 0x10000000)
#define RTP_ED137A_squ_mask(octet)   ((octet) & 0x1000)

/* ED-137 extended information */
#define RTP_ED137_extended_information(octet)   ((octet) & 0x00400000)
#define RTP_ED137A_extended_information(octet)  ((octet) & 0x0001)

/* ED-137 feature type */
#define RTP_ED137_feature_type(octet)  (((octet) & 0x003C0000) >> 18)
#define RTP_ED137A_feature_type(octet) (((octet) & 0x0000F000) >> 12)

/* ED-137 feature length */
#define RTP_ED137_feature_length(octet)  (((octet) & 0x0003C000) >> 14)
#define RTP_ED137A_feature_length(octet) (((octet) & 0x00000F00) >> 8)

/* ED-137 feature value */
#define RTP_ED137_feature_value(octet)  (((octet) & 0x00003FFE) >> 1)
#define RTP_ED137A_feature_value(octet) (((octet) & 0x000000FF) >> 0)

/* ED_137 None constants */
#define RTP_ED137_feature_none_type    0x0

/* ED-137 BSS constants */
#define RTP_ED137_feature_bss_type    0x1
#define RTP_ED137_feature_bss_qidx(octet)   (((octet) & 0x00003FC0) >> 6)
#define RTP_ED137_feature_bss_qidx_ml(octet)   (((octet) & 0x00000038) >> 2)
#define RTP_ED137_feature_bss_qidx_ml_rssi      0
#define RTP_ED137_feature_bss_qidx_rssi_max     15

/* ED-137 CLIMAX-Time Delay */
#define RTP_ED137_feature_climax_ot_type   0x2
#define RTP_ED137_feature_climax_ot_value(octet)  (((octet) & 0x00003F00) >> 8)

/* ED-137A SQI constants */
#define RTP_ED137A_feature_sqi_type             0x1
#define RTP_ED137A_feature_sqi_len              1
#define RTP_ED137A_feature_sqi_key              MAKE_KEY( RTP_ED137A_feature_sqi_type, RTP_ED137A_feature_sqi_len )
#define RTP_ED137A_feature_sqi_qidx(octet)  (((octet) & 0x000000F8) >> 3)
#define RTP_ED137A_feature_sqi_qidx_ml(octet)  (((octet) & 0x00000007) >> 0)
#define RTP_ED137A_feature_sqi_qidx_ml_rssi     0
#define RTP_ED137A_feature_sqi_qidx_rssi_max    15

/* ED-137A CLIMAX-Time Delay */
#define RTP_ED137A_feature_climax_tdly_type     0x2
#define RTP_ED137A_feature_climax_tdly_len      1
#define RTP_ED137A_feature_climax_tdly_key      MAKE_KEY( RTP_ED137A_feature_climax_tdly_type, RTP_ED137A_feature_climax_tdly_len )
#define RTP_ED137A_feature_climax_tdly_mode(octet)  (((octet) & 0x00000080) >> 7)
#define RTP_ED137A_feature_climax_tdly_value(octet)  (((octet) & 0x0000007F) >> 0)
#define RTP_ED137A_feature_climax_tdly_mode_relative    0
#define RTP_ED137A_feature_climax_tdly_mode_absolute    1

/* ED-137B RRC single */
#define RTP_ED137B_feature_rrc_single_type      0x3
#define RTP_ED137B_feature_rrc_single_len   1
#define RTP_ED137B_feature_rrc_single_key   MAKE_KEY( RTP_ED137B_feature_rrc_single_type, RTP_ED137B_feature_rrc_single_len )

/* ED-137B CLIMAX dynamic delay compensation */
#define RTP_ED137B_feature_climax_ddc_type      0x4
#define RTP_ED137B_feature_climax_ddc_rmm_len   3
#define RTP_ED137B_feature_climax_ddc_mam_len   12
#define RTP_ED137B_feature_climax_ddc_rmm_key   MAKE_KEY( RTP_ED137B_feature_climax_ddc_type, RTP_ED137B_feature_climax_ddc_rmm_len )
#define RTP_ED137B_feature_climax_ddc_mam_key   MAKE_KEY( RTP_ED137B_feature_climax_ddc_type, RTP_ED137B_feature_climax_ddc_mam_len )
#define RTP_ED137B_feature_climax_ddc_rmm_tqv(octet)  (((octet) & 0x00800000) >> 23)
#define RTP_ED137B_feature_climax_ddc_rmm_t1(octet)   (((octet) & 0x007FFFFF) >> 0)
#define RTP_ED137B_feature_climax_ddc_mam_tqg(octet)  (((octet) & 0x00800000) >> 23)
#define RTP_ED137B_feature_climax_ddc_mam_t1(octet)   (((octet) & 0x007FFFFF) >> 0)
#define RTP_ED137B_feature_climax_ddc_mam_nmr(octet)  (((octet) & 0x00800000) >> 23)
#define RTP_ED137B_feature_climax_ddc_mam_t2(octet)   (((octet) & 0x007FFFFF) >> 0)
#define RTP_ED137B_feature_climax_ddc_mam_tsd(octet)  (((octet) & 0xFFFF) >> 0)
#define RTP_ED137B_feature_climax_ddc_mam_tj1(octet)  (((octet) & 0xFFFF) >> 0)
#define RTP_ED137B_feature_climax_ddc_mam_tid(octet)  (((octet) & 0xFFFF) >> 0)
#define RTP_ED137B_feature_climax_ddc_rmm_tqv_relative  0
#define RTP_ED137B_feature_climax_ddc_rmm_tqv_absolute  1
#define RTP_ED137B_feature_climax_ddc_mam_tqg_relative  0
#define RTP_ED137B_feature_climax_ddc_mam_tqg_absolute  1

/* ED-137C CLIMAX dynamic delay compensation*/
#define RTP_ED137C_feature_climax_ddc_type      0x4
#define RTP_ED137C_feature_climax_ddc_mam_len   14
#define RTP_ED137C_feature_climax_ddc_mam_key   MAKE_KEY( RTP_ED137C_feature_climax_ddc_type, RTP_ED137C_feature_climax_ddc_mam_len )
#define RTP_ED137C_feature_climax_ddc_rmm_tqv(octet)  (((octet) & 0x00800000) >> 23)
#define RTP_ED137C_feature_climax_ddc_rmm_t1(octet)   (((octet) & 0x007FFFFF) >> 0)
#define RTP_ED137C_feature_climax_ddc_mam_tqg(octet)  (((octet) & 0x00800000) >> 23)
#define RTP_ED137C_feature_climax_ddc_mam_t1(octet)   (((octet) & 0x007FFFFF) >> 0)
#define RTP_ED137C_feature_climax_ddc_mam_nmr(octet)  (((octet) & 0x00800000) >> 23)
#define RTP_ED137C_feature_climax_ddc_mam_t2(octet)   (((octet) & 0x007FFFFF) >> 0)
#define RTP_ED137C_feature_climax_ddc_mam_tsd(octet)  (((octet) & 0xFFFF) >> 0)
#define RTP_ED137C_feature_climax_ddc_mam_tj1(octet)  (((octet) & 0xFFFF) >> 0)
#define RTP_ED137C_feature_climax_ddc_mam_tid(octet)  (((octet) & 0xFFFF) >> 0)
#define RTP_ED137C_feature_climax_ddc_mam_ts2(octet)  (((octet) & 0xFFFF) >> 0)
#define RTP_ED137C_feature_climax_ddc_rmm_tqv_relative  0
#define RTP_ED137C_feature_climax_ddc_rmm_tqv_absolute  1
#define RTP_ED137C_feature_climax_ddc_mam_tqg_relative  0
#define RTP_ED137C_feature_climax_ddc_mam_tqg_absolute  1


static const value_string rtp_ext_ed137_ptt_type[] =
{
    { 0x00, "PTT OFF" },
    { 0x01, "Normal PTT ON" },
    { 0x02, "Coupling PTT ON" },
    { 0x03, "Priority PTT ON" },
    { 0x04, "Emergency PTT ON" },
    { 0x05, "Reserved" },
    { 0x06, "Reserved" },
    { 0x07, "Reserved" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137_squ[] =
{
    { 0x00, "SQ OFF" },
    { 0x01, "SQ ON" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137_ft_type[] =
{
    { 0x0, "No features" },
    { 0x1, "Best signal selection" },
    { 0x2, "CLIMAX time delay" },
    { 0x3, "Reserved" },
    { 0x4, "Reserved" },
    { 0x5, "Reserved" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0x8, "Reserved" },
    { 0x9, "Reserved" },
    { 0xA, "Reserved" },
    { 0xB, "Vendor reserved" },
    { 0xC, "Vendor reserved" },
    { 0xD, "Vendor reserved" },
    { 0xE, "Vendor reserved" },
    { 0xF, "Vendor reserved" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137_x[] =
{
    { 0x00, "No extended information with additional features is used" },
    { 0x01, "Extended information with additional features is used" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137_vf[] =
{
    { 0x00, "VF OFF" },
    { 0x01, "VF ON" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137_ft_bss_rssi_qidx[] =
{
    { 0x00, "lower than -100.00 dBm" },
    { 0x01, "lower than or equal to -97.86 dBm" },
    { 0x02, "lower than or equal to -95.71 dBm" },
    { 0x03, "lower than or equal to -93.57 dBm" },
    { 0x04, "lower than or equal to -91.43 dBm" },
    { 0x05, "lower than or equal to -89.29 dBm" },
    { 0x06, "lower than or equal to -87.14 dBm" },
    { 0x07, "lower than or equal to -85.00 dBm" },
    { 0x08, "lower than or equal to -82.86 dBm" },
    { 0x09, "lower than or equal to -80.71 dBm" },
    { 0x0a, "lower than or equal to -78.57 dBm" },
    { 0x0b, "lower than or equal to -76.43 dBm" },
    { 0x0c, "lower than or equal to -74.29 dBm" },
    { 0x0d, "lower than or equal to -72.14 dBm" },
    { 0x0e, "lower than or equal to -70.00 dBm" },
    { 0x0f, "higher than -70.00 dBm" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137_ft_bss_qidx_ml[] =
{
    { 0x00, "RSSI" },
    { 0x01, "AGC Level" },
    { 0x02, "C/N" },
    { 0x03, "Standardized PSD" },
    { 0x04, "Vendor specific method" },
    { 0x05, "Vendor specific method" },
    { 0x06, "Vendor specific method" },
    { 0x07, "Vendor specific method" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137a_ptt_type[] =
{
    { 0x00, "PTT OFF" },
    { 0x01, "Normal PTT ON" },
    { 0x02, "Coupling PTT ON" },
    { 0x03, "Priority PTT ON" },
    { 0x04, "Emergency PTT ON" },
    { 0x05, "Test PTT ON" },
    { 0x06, "Reserved" },
    { 0x07, "Reserved" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137a_squ[] =
{
    { 0x00, "SQ OFF" },
    { 0x01, "SQ ON" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137a_ft_type[] =
{
    { 0x0, "No features" },
    { 0x1, "Signal Quality Information" },
    { 0x2, "CLIMAX time delay" },
    { 0x3, "Radio remote control" },
    { 0x4, "CLIMAX dynamic delay compensation" },
    { 0x5, "Reserved" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0x8, "Reserved" },
    { 0x9, "Reserved" },
    { 0xA, "Reserved" },
    { 0xB, "Vendor reserved" },
    { 0xC, "Vendor reserved" },
    { 0xD, "Vendor reserved" },
    { 0xE, "Vendor reserved" },
    { 0xF, "Vendor reserved" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137a_ft_sqi_rssi_qidx[] =
{
    { 0x00, "lower than -100.00 dBm" },
    { 0x01, "lower than or equal to -97.86 dBm" },
    { 0x02, "lower than or equal to -95.71 dBm" },
    { 0x03, "lower than or equal to -93.57 dBm" },
    { 0x04, "lower than or equal to -91.43 dBm" },
    { 0x05, "lower than or equal to -89.29 dBm" },
    { 0x06, "lower than or equal to -87.14 dBm" },
    { 0x07, "lower than or equal to -85.00 dBm" },
    { 0x08, "lower than or equal to -82.86 dBm" },
    { 0x09, "lower than or equal to -80.71 dBm" },
    { 0x0a, "lower than or equal to -78.57 dBm" },
    { 0x0b, "lower than or equal to -76.43 dBm" },
    { 0x0c, "lower than or equal to -74.29 dBm" },
    { 0x0d, "lower than or equal to -72.14 dBm" },
    { 0x0e, "lower than or equal to -70.00 dBm" },
    { 0x0f, "higher than -70.00 dBm" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137a_ft_sqi_qidx_ml[] =
{
    { 0x00, "RSSI" },
    { 0x01, "AGC Level" },
    { 0x02, "C/N" },
    { 0x03, "Standardized PSD" },
    { 0x04, "Vendor specific method" },
    { 0x05, "Vendor specific method" },
    { 0x06, "Vendor specific method" },
    { 0x07, "Vendor specific method" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137a_ft_climax_delay_mode[] =
{
    { 0x00, "relative" },
    { 0x01, "absolute" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_single_ms_tx_f1[] =
{
    { 0x00, "Main transmitter for F1 is used" },
    { 0x01, "Standby transmitter for F1 is used" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_single_ms_rx_f1[] =
{
    { 0x00, "Main receiver for F1 is used" },
    { 0x01, "Standby receiver for F1 is used" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_single_ms_tx_f2[] =
{
    { 0x00, "Main transmitter for F2 is used" },
    { 0x01, "Standby transmitter for F2 is used" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_single_ms_rx_f2[] =
{
    { 0x00, "Main receiver for F2 is used" },
    { 0x01, "Standby receiver for F2 is used" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_single_sel_tx_f1[] =
{
    { 0x00, "Active transmitter for F1 shall not be used" },
    { 0x01, "Active transmitter for F1 shall be used" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_single_sel_tx_f2[] =
{
    { 0x00, "Active transmitter for F2 shall not be used" },
    { 0x01, "Active transmitter for F2 shall be used" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_single_mu_rx_f1[] =
{
    { 0x00, "Active receiver for F1 shall be unmuted" },
    { 0x01, "Active receiver for F1 shall be muted" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_single_mu_rx_f2[] =
{
    { 0x00, "Active receiver for F2 shall be unmuted" },
    { 0x01, "Active receiver for F2 shall be muted" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_climax_ddc_time_quality[] =
{
    { 0x00, "Not synchronized" },
    { 0x01, "Synchronized" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137b_ft_climax_ddc_mam_nmr[] =
{
    { 0x00, "No request" },
    { 0x01, "GRS requests a new RTT measurement" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137c_ft_climax_ddc_time_quality[] =
{
    { 0x00, "Not synchronized" },
    { 0x01, "Synchronized" },
    { 0, NULL },
};

static const value_string rtp_ext_ed137c_ft_climax_ddc_mam_nmr[] =
{
    { 0x00, "No request" },
    { 0x01, "GRS requests a new RTT measurement" },
    { 0, NULL },
};

/* We do not need to allocate/free strings */
static char *ed137_ptt_only = "PTT";
static char *ed137_squ_only = "SQU";
static char *ed137_ptt_and_squ = "PTT+SQU";

/* Note:
 * Only seen/tested headers are decoded
 */
static int
dissect_rtp_hdr_ext_ed137(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    unsigned int hdr_extension_len;
    struct _rtp_info *rtp_info=(struct _rtp_info *)data;
    proto_tree *rtp_hext_tree = NULL;
    unsigned int hdrext_offset = 0;
    gboolean ed137_ptt = FALSE;
    gboolean ed137_squ = FALSE;

    hdr_extension_len = tvb_reported_length(tvb);

    if ( hdr_extension_len > 0 ) {

        if (rtp_info != NULL) {
            rtp_info->info_is_ed137 = TRUE;
        }
        if ( tree ) {
            proto_item *ti;
            ti = proto_tree_add_item(tree, hf_rtp_hdr_ed137s, tvb, 0, hdr_extension_len, ENC_NA);
            rtp_hext_tree = proto_item_add_subtree( ti, ett_hdr_ext_ed137s );
        }

        while ( hdr_extension_len > 0 ) {
            proto_item *ti2;
            proto_tree *rtp_hext_tree2;
            proto_item *ti3;
            proto_tree *rtp_hext_tree3;
            unsigned int ft_type;
            guint32 ext_value = tvb_get_ntohl( tvb, hdrext_offset );

            if (RTP_ED137_ptt_mask(ext_value)) {
                col_append_str(pinfo->cinfo, COL_INFO, ", PTT");
                ed137_ptt = TRUE;
            }
            if (RTP_ED137_squ_mask(ext_value)) {
                col_append_str(pinfo->cinfo, COL_INFO, ", SQU");
                ed137_squ = TRUE;
            }

            /* Map PTT/SQU bits to string */
            if (rtp_info != NULL) {
                if (ed137_ptt) {
                    if (ed137_squ) {
                        rtp_info->info_ed137_info = ed137_ptt_and_squ;
                    } else {
                        rtp_info->info_ed137_info = ed137_ptt_only;
                    }
                } else {
                    if (ed137_squ) {
                        rtp_info->info_ed137_info = ed137_squ_only;
                    } else {
                        rtp_info->info_ed137_info = NULL;
                    }
                }
            }

            if ( rtp_hext_tree ) {
                ti2 = proto_tree_add_item(rtp_hext_tree, hf_rtp_hdr_ed137, tvb, hdrext_offset, 4, ENC_NA);
                rtp_hext_tree2 = proto_item_add_subtree( ti2, ett_hdr_ext_ed137 );

                /* There are multiple formats of header - depends on direction of a flow. As it is not possible to quess flow direction, we use items from RTPRx because unused fields are empty in other formats */
                proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137_ptt_type, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137_squ, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137_ptt_id, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137_sct, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137_x, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137_vf, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
            }

            ft_type = RTP_ED137_feature_type(ext_value);

            ti3 = proto_tree_add_item(rtp_hext_tree, hf_rtp_hdr_ed137_add, tvb, hdrext_offset, 4, ENC_NA);
            rtp_hext_tree3 = proto_item_add_subtree( ti3, ett_hdr_ext_ed137_add );

            if (RTP_ED137_extended_information(ext_value)) {
                /* Extended information is used */

                if ( rtp_hext_tree ) {
                    proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137_ft_type, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137_ft_len, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                }

                if ( rtp_hext_tree ) {
                    switch (ft_type) {
                        case RTP_ED137_feature_bss_type:
                        {
                            unsigned int bss_qidx;
                            unsigned int bss_qidx_ml;

                            bss_qidx    = RTP_ED137_feature_bss_qidx(ext_value);
                            bss_qidx_ml = RTP_ED137_feature_bss_qidx_ml(ext_value);
                            if (RTP_ED137_feature_bss_qidx_ml_rssi == bss_qidx_ml) {
                                /* Special handling for RSSI method */
                                if (bss_qidx <= RTP_ED137_feature_bss_qidx_rssi_max) {
                                    /* Correct range */
                                    proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137_ft_bss_rssi_qidx, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                                }
                                else {
                                    /* Handle as other method */
                                    proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137_ft_bss_qidx, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                                }
                            }
                            else {
                                /* Other BSS method handling */
                                proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137_ft_bss_qidx, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                            }
                            proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137_ft_bss_qidx_ml, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                            break;
                        }
                        case RTP_ED137_feature_climax_ot_type:
                        {
                            unsigned int climax_ot_value;
                            unsigned int climax_ot_value_calc;

                            climax_ot_value = RTP_ED137_feature_climax_ot_value(ext_value);

                            /* Relative delay, in 2ms steps */
                            climax_ot_value_calc=2*climax_ot_value;
                            proto_tree_add_uint_format_value( rtp_hext_tree3, hf_rtp_hdr_ed137_ft_climax_delay_value, tvb, hdrext_offset, 4, climax_ot_value, "%d ms", climax_ot_value_calc);

                            break;
                        }
                        default:
                            proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137_ft_value, tvb, hdrext_offset, 4, ENC_NA);
                            break;
                    }
                }

                /* Shift behind header */
                hdrext_offset += 4;
                hdr_extension_len -= 4;
            }
            else {
                /* Extended information is not used */
                if ( rtp_hext_tree ) {
                    proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137_x_nu, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN);
                }

                /* Shift behind empty additional feature header */
                hdrext_offset += 4;
                hdr_extension_len -= 4;
            }
        }
    }
    return tvb_captured_length(tvb);
}


#define NSTIME_INIT_USEC(nstime, usecs) \
    nstime.secs = usecs / 1000000; \
    nstime.nsecs = (usecs % 1000000) * 1000;

/* Decodes and calculates relative/absolute time item */
static void process_time_value(tvbuff_t *tvb, proto_tree *tree, int time_item, unsigned int hdrext_offset, gboolean time_relative _U_, unsigned int time_value)
{
    /* Note: even there is relative/absolute flag, value is shown same way because it is relative value derived from relative/absolute start point */
    unsigned int time_calc;
    nstime_t tmp_time;
    gchar *tmp;

    /* Value is stored as count of 125 us ticks */
    time_calc = time_value * 125;
    NSTIME_INIT_USEC(tmp_time, time_calc);
    tmp = rel_time_to_secs_str(wmem_packet_scope(), &tmp_time);

    proto_tree_add_uint_format_value( tree, time_item, tvb, hdrext_offset, 3, time_value, "%s s", tmp);
}

/* Decodes and calculates value based on 125us tick*/
static void process_125us_based_value(tvbuff_t *tvb, proto_tree *tree, int value_item, unsigned int hdrext_offset)
{
    guint32 value;
    guint32 value_calc;

    /* Values is stored as count of 125 us ticks */
    value = tvb_get_ntohs( tvb, hdrext_offset );
    value_calc = value * 125;

    proto_tree_add_uint_format_value( tree, value_item, tvb, hdrext_offset, 2, value, "%d us", value_calc);
}

static int
dissect_rtp_hdr_ext_ed137a_feature_sqi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    guint32 ext_value;
    guint32 sqi_qidx;
    guint32 sqi_qidx_ml;

    ext_value = tvb_get_guint8( tvb, 0 );
    sqi_qidx    = RTP_ED137A_feature_sqi_qidx(ext_value);
    sqi_qidx_ml = RTP_ED137A_feature_sqi_qidx_ml(ext_value);
    if (RTP_ED137A_feature_sqi_qidx_ml_rssi == sqi_qidx_ml) {
        /* Special handling for RSSI method */
        if (sqi_qidx <= RTP_ED137A_feature_sqi_qidx_rssi_max) {
            /* Correct range */
            proto_tree_add_item( tree, hf_rtp_hdr_ed137a_ft_sqi_rssi_qidx, tvb, 0, 1, ENC_BIG_ENDIAN);
        }
        else {
            /* Handle as other method */
            proto_tree_add_item( tree, hf_rtp_hdr_ed137a_ft_sqi_qidx, tvb, 0, 1, ENC_BIG_ENDIAN);
        }
    }
    else {
        /* Other SQI method handling */
        proto_tree_add_item( tree, hf_rtp_hdr_ed137a_ft_sqi_qidx, tvb, 0, 1, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item( tree, hf_rtp_hdr_ed137a_ft_sqi_qidx_ml, tvb, 0, 1, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

static int
dissect_rtp_hdr_ext_ed137a_feature_climax_tdly(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    guint32 ext_value;
    guint32 climax_tdly_mode;
    guint32 climax_tdly_value;
    guint32 climax_tdly_value_calc;

    ext_value = tvb_get_guint8( tvb, 0 );

    climax_tdly_mode = RTP_ED137A_feature_climax_tdly_mode(ext_value);
    climax_tdly_value = RTP_ED137A_feature_climax_tdly_value(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137a_ft_climax_delay_mode, tvb, 0, 1, ENC_BIG_ENDIAN);
    if (RTP_ED137A_feature_climax_tdly_mode_relative == climax_tdly_mode) {
        /* Relative delay, in 2ms steps */
        climax_tdly_value_calc=2*climax_tdly_value;

        proto_tree_add_uint_format_value( tree, hf_rtp_hdr_ed137a_ft_climax_delay_relative_value, tvb, 0, 1, climax_tdly_value, "%d ms", climax_tdly_value_calc);

    }
    else {
        /* Absolute delay, in 2ms steps */
        climax_tdly_value_calc=2*climax_tdly_value;

        proto_tree_add_uint_format_value( tree, hf_rtp_hdr_ed137a_ft_climax_delay_absolute_value, tvb, 0, 1, climax_tdly_value, "%d ms", climax_tdly_value_calc);

    }

    return tvb_captured_length(tvb);
}

static int
dissect_rtp_hdr_ext_ed137b_feature_rrc_single(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_tree *item;

    /* Generated item points really to previous byte */
    item = proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_rrc_single, tvb, -1, 1, ENC_NA);
    proto_item_set_generated(item);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_rrc_single_ms_tx_f1, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_rrc_single_ms_rx_f1, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_rrc_single_ms_tx_f2, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_rrc_single_ms_rx_f2, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_rrc_single_sel_tx_f1, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_rrc_single_sel_tx_f2, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_rrc_single_mu_rx_f1, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_rrc_single_mu_rx_f2, tvb, 0, 1, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

static int
dissect_rtp_hdr_ext_ed137b_feature_climax_ddc_rmm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    guint32 ext_value;
    proto_tree *item;
    guint32 climax_ddc_rmm_tqv;
    guint32 climax_ddc_rmm_t1;

    /* Generated item points really to previous byte */
    item = proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_rmm, tvb, -1, 1, ENC_NA);
    proto_item_set_generated(item);

    ext_value = tvb_get_ntoh24( tvb, 0 );
    climax_ddc_rmm_tqv = RTP_ED137B_feature_climax_ddc_rmm_tqv(ext_value);
    climax_ddc_rmm_t1 = RTP_ED137B_feature_climax_ddc_rmm_t1(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_tqv, tvb, 0, 3, ENC_BIG_ENDIAN);
    process_time_value(tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_t1, 0, (RTP_ED137B_feature_climax_ddc_rmm_tqv_relative == climax_ddc_rmm_tqv), climax_ddc_rmm_t1);

    return tvb_captured_length(tvb);
}

static int
dissect_rtp_hdr_ext_ed137b_feature_climax_ddc_mam(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    guint32 ext_value;
    proto_tree *item;
    guint32 climax_ddc_mam_tqg;
    guint32 climax_ddc_mam_t1;
    guint32 climax_ddc_mam_t2;

    /* Generated item points really to previous byte */
    item = proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam, tvb, -1, 1, ENC_NA);
    proto_item_set_generated(item);

    ext_value = tvb_get_ntoh24( tvb, 0 + 0 );
    climax_ddc_mam_tqg = RTP_ED137B_feature_climax_ddc_mam_tqg(ext_value);
    climax_ddc_mam_t1 = RTP_ED137B_feature_climax_ddc_mam_t1(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tqg, tvb, 0, 3, ENC_BIG_ENDIAN);
    process_time_value(tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t1, 0, (RTP_ED137B_feature_climax_ddc_mam_tqg_relative == climax_ddc_mam_tqg), climax_ddc_mam_t1);

    ext_value = tvb_get_ntoh24( tvb, 0 + 3 );
    climax_ddc_mam_t2 = RTP_ED137B_feature_climax_ddc_mam_t2(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_nmr, tvb, 0 + 3, 3, ENC_BIG_ENDIAN);
    process_time_value(tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t2, 0 + 3, (RTP_ED137B_feature_climax_ddc_mam_tqg_relative == climax_ddc_mam_tqg), climax_ddc_mam_t2);

    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tsd, 0 + 6);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tj1, 0 + 8);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tid, 0 + 10);

    return tvb_captured_length(tvb);
}

static int
dissect_rtp_hdr_ext_ed137c_feature_climax_ddc_mam(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    guint32 ext_value;
    proto_tree *item;
    guint32 climax_ddc_mam_tqg;
    guint32 climax_ddc_mam_t1;
    guint32 climax_ddc_mam_t2;

    /* Generated item points really to previous byte */
    item = proto_tree_add_item( tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam, tvb, -1, 1, ENC_NA);
    proto_item_set_generated(item);

    ext_value = tvb_get_ntoh24( tvb, 0 + 0 );
    climax_ddc_mam_tqg = RTP_ED137C_feature_climax_ddc_mam_tqg(ext_value);
    climax_ddc_mam_t1 = RTP_ED137C_feature_climax_ddc_mam_t1(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tqg, tvb, 0, 3, ENC_BIG_ENDIAN);
    process_time_value(tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t1, 0, (RTP_ED137C_feature_climax_ddc_mam_tqg_relative == climax_ddc_mam_tqg), climax_ddc_mam_t1);

    ext_value = tvb_get_ntoh24( tvb, 0 + 3 );
    climax_ddc_mam_t2 = RTP_ED137C_feature_climax_ddc_mam_t2(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_nmr, tvb, 0 + 3, 3, ENC_BIG_ENDIAN);
    process_time_value(tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t2, 0 + 3, (RTP_ED137C_feature_climax_ddc_mam_tqg_relative == climax_ddc_mam_tqg), climax_ddc_mam_t2);

    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tsd, 0 + 6);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tj1, 0 + 8);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tid, 0 + 10);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_ts2, 0 + 12);

    return tvb_captured_length(tvb);
}

/* Decode ED-137A fixed part and call dissectors for variable part */
static int
dissect_rtp_hdr_ext_ed137a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint32 hdr_extension_len;
    struct _rtp_info *rtp_info=(struct _rtp_info *)data;
    proto_tree *rtp_hext_tree = NULL;
    guint32 hdrext_offset = 0;
    gboolean ed137_ptt = FALSE;
    gboolean ed137_squ = FALSE;

    hdr_extension_len = tvb_reported_length(tvb);

    if ( hdr_extension_len > 0 ) {
        proto_item *ti2;
        proto_tree *rtp_hext_tree2;
        guint32 ext_value = tvb_get_ntohs( tvb, hdrext_offset );

        if (rtp_info != NULL) {
            rtp_info->info_is_ed137 = TRUE;
        }
        if ( tree ) {
            proto_item *ti;
            ti = proto_tree_add_item(tree, hf_rtp_hdr_ed137s, tvb, 0, hdr_extension_len, ENC_NA);
            rtp_hext_tree = proto_item_add_subtree( ti, ett_hdr_ext_ed137s );
        }

        if (RTP_ED137A_ptt_mask(ext_value)) {
            col_append_str(pinfo->cinfo, COL_INFO, ", PTT");
            ed137_ptt = TRUE;
        }
        if (RTP_ED137A_squ_mask(ext_value)) {
            col_append_str(pinfo->cinfo, COL_INFO, ", SQU");
            ed137_squ = TRUE;
        }

        /* Map PTT/SQU bits to string */
        if (rtp_info != NULL) {
            if (ed137_ptt) {
                if (ed137_squ) {
                    rtp_info->info_ed137_info = ed137_ptt_and_squ;
                } else {
                    rtp_info->info_ed137_info = ed137_ptt_only;
                }
            } else {
                if (ed137_squ) {
                    rtp_info->info_ed137_info = ed137_squ_only;
                } else {
                    rtp_info->info_ed137_info = NULL;
                }
            }
        }

        if ( rtp_hext_tree ) {
            ti2 = proto_tree_add_item(rtp_hext_tree, hf_rtp_hdr_ed137a, tvb, hdrext_offset, 2, ENC_NA);
            rtp_hext_tree2 = proto_item_add_subtree( ti2, ett_hdr_ext_ed137a );

            /* There are multiple formats of header - depends on direction of a flow. As it is not possible to quess flow direction, we use items from RTPRx because unused fields are empty in other formats */
            proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137a_ptt_type, tvb, hdrext_offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137a_squ, tvb, hdrext_offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137a_ptt_id, tvb, hdrext_offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137a_pm, tvb, hdrext_offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137a_ptts, tvb, hdrext_offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137a_sct, tvb, hdrext_offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137a_reserved, tvb, hdrext_offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( rtp_hext_tree2, hf_rtp_hdr_ed137a_x, tvb, hdrext_offset, 2, ENC_BIG_ENDIAN);
        }

        /* Shift behind standard ED-137A header */
        hdrext_offset += 2;
        hdr_extension_len -= 2;

        /* Do we have additional feature blocks? */
        if (RTP_ED137A_extended_information(ext_value)) {

            /* Loop over all additional feature blocks */
            /* The shortest header lenght is 2, anything shorter is padding */
            while ( hdr_extension_len >= 2 ) {
                proto_item *ti3;
                proto_tree *rtp_hext_tree3;
                guint32 ft_type;
                guint32 ft_len;

                ext_value = tvb_get_ntohs( tvb, hdrext_offset );
                ft_type = RTP_ED137A_feature_type(ext_value);
                ft_len = RTP_ED137A_feature_length(ext_value);

                /* Is it header or padding? */
                if ( RTP_ED137_feature_none_type != ft_type ) {
                    ti3 = proto_tree_add_item(rtp_hext_tree, hf_rtp_hdr_ed137a_add, tvb, hdrext_offset, (ft_len > 0 ? ft_len + 1 : 2), ENC_NA);
                    rtp_hext_tree3 = proto_item_add_subtree( ti3, ett_hdr_ext_ed137a_add );

                    if ( rtp_hext_tree ) {
                        proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137a_ft_type, tvb, hdrext_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137a_ft_len, tvb, hdrext_offset, 1, ENC_BIG_ENDIAN);
                    }

                    /* Shift behind feature header */
                    hdrext_offset += 1;
                    hdr_extension_len -= 1;

                    if ( rtp_hext_tree ) {
                        tvbuff_t   *newtvb;
                        guint32     ft_table_key;

                        /* join 4 bit type and 4 bit lenght to 8 bit key */
                        ft_table_key = MAKE_KEY( ft_type, ft_len );

                        /* pass interpretation of header extension to a registered subdissector */
                        /* new subset points to value (starts behind type/length pair) */
                        newtvb = tvb_new_subset_length(tvb, hdrext_offset, hdr_extension_len);

                        /* try to find a dissector by type/len key and dissect additional feature header */
                        if ( !(dissector_try_uint(rtp_hdr_ext_ed137a_add_features_table, ft_table_key, newtvb, pinfo, rtp_hext_tree3)) ) {
                            proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137a_ft_value, tvb, hdrext_offset, ft_len, ENC_NA);
                        }
                    }

                    /* Shift behind feature data */
                    hdrext_offset += ft_len;
                    hdr_extension_len -= ft_len;
                }
                else {
                    /* Padding, exit while loop */
                    break;
                }

            }

            /* Process padding if any */
            guint32 hdr_extension_padding;

            hdr_extension_padding = hdr_extension_len & 0x03;

            /* Calculate padding size */
            if ( hdr_extension_padding > 0 ) {
                if ( rtp_hext_tree ) {
                    proto_tree_add_item( rtp_hext_tree, hf_rtp_hdr_ed137a_ft_padding, tvb, hdrext_offset, hdr_extension_padding, ENC_NA);
                }
            }

        }
        else {
            /* Extended information is not used */
            if ( rtp_hext_tree ) {
                proto_item *ti3;
                proto_tree *rtp_hext_tree3;

                ti3 = proto_tree_add_item(rtp_hext_tree, hf_rtp_hdr_ed137a_add, tvb, hdrext_offset, 2, ENC_NA);
                rtp_hext_tree3 = proto_item_add_subtree( ti3, ett_hdr_ext_ed137a_add );
                proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137a_x_nu, tvb, hdrext_offset, 2, ENC_BIG_ENDIAN);
            }
        }
    }
    return tvb_captured_length(tvb);
}

/* Register RTP ED-137 */
void
proto_register_rtp_ed137(void)
{
    static hf_register_info hf[] =
    {
/* ED-137 and ED-137A common structures */
        {
            &hf_rtp_hdr_ed137s,
            {
                "ED137 extensions",
                "rtp.ext.ed137s",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
/* ED-137 only structures */
        {
            &hf_rtp_hdr_ed137,
            {
                "ED137 extension",
                "rtp.ext.ed137",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_add,
            {
                "ED137 extension additional feature",
                "rtp.ext.ed137.ft",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ptt_type,
            {
                "PTT Type",
                "rtp.ext.ed137.ptt_type",
                FT_UINT32,
                BASE_DEC,
                VALS(rtp_ext_ed137_ptt_type),
                0xE0000000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_squ,
            {
                "SQU",
                "rtp.ext.ed137.squ",
                FT_UINT32,
                BASE_DEC,
                VALS(rtp_ext_ed137_squ),
                0x10000000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ptt_id,
            {
                "PTT-id",
                "rtp.ext.ed137.ptt_id",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0F000000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_sct,
            {
                "Simultaneous Call Transmissions",
                "rtp.ext.ed137.sct",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00800000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_x,
            {
                "X",
                "rtp.ext.ed137.x",
                FT_UINT32,
                BASE_DEC,
                VALS(rtp_ext_ed137_x),
                0x00400000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_x_nu,
            {
                "Not used",
                "rtp.ext.ed137.x-nu",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x003FFFFE,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_type,
            {
                "Feature type",
                "rtp.ext.ed137.ft.type",
                FT_UINT32,
                BASE_HEX_DEC,
                VALS(rtp_ext_ed137_ft_type),
                0x003C0000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_len,
            {
                "Feature length",
                "rtp.ext.ed137.ft.len",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0003C000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_value,
            {
                "Feature value",
                "rtp.ext.ed137.ft.value",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x00003FFE,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_vf,
            {
                "VF",
                "rtp.ext.ed137.vf",
                FT_UINT32,
                BASE_DEC,
                VALS(rtp_ext_ed137_vf),
                0x00000001,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_bss_qidx,
            {
                "BSS Quality Index",
                "rtp.ext.ed137.ft.bss.qidx",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00003FC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_bss_rssi_qidx,
            {
                "BSS Quality Index",
                "rtp.ext.ed137.ft.bss.qidx",
                FT_UINT32,
                BASE_DEC,
                VALS(rtp_ext_ed137_ft_bss_rssi_qidx),
                0x00003FC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_bss_qidx_ml,
            {
                "BSS Quality Index Method",
                "rtp.ext.ed137.ft.bss.qidx-ml",
                FT_UINT32,
                BASE_DEC,
                VALS(rtp_ext_ed137_ft_bss_qidx_ml),
                0x00000038,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_climax_delay_value,
            {
                "CLIMAX-Time Delay",
                "rtp.ext.ed137.ft.climax_delay.value",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00003F00,
                NULL, HFILL
            }
        },
/* ED-137A/B only structures */
        {
            &hf_rtp_hdr_ed137a,
            {
                "ED137A extension",
                "rtp.ext.ed137a",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_add,
            {
                "ED137A extension additional feature",
                "rtp.ext.ed137a.ft",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ptt_type,
            {
                "PTT Type",
                "rtp.ext.ed137a.ptt_type",
                FT_UINT16,
                BASE_DEC,
                VALS(rtp_ext_ed137a_ptt_type),
                0xE000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_squ,
            {
                "SQU",
                "rtp.ext.ed137a.squ",
                FT_UINT16,
                BASE_DEC,
                VALS(rtp_ext_ed137a_squ),
                0x1000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ptt_id,
            {
                "PTT-id",
                "rtp.ext.ed137a.ptt_id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0FC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_pm,
            {
                "PTT Mute",
                "rtp.ext.ed137a.pm",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0020,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ptts,
            {
                "PTT Summation",
                "rtp.ext.ed137a.ptts",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0010,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_sct,
            {
                "Simultaneous Call Transmissions",
                "rtp.ext.ed137a.sct",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0008,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_reserved,
            {
                "Reserved",
                "rtp.ext.ed137a.reserved",
                FT_UINT16,
                BASE_HEX_DEC,
                NULL,
                0x0006,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_x,
            {
                "X",
                "rtp.ext.ed137a.x",
                FT_UINT16,
                BASE_DEC,
                VALS(rtp_ext_ed137_x),
                0x0001,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_x_nu,
            {
                "Not used",
                "rtp.ext.ed137a.x-nu",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0xFFFF,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_type,
            {
                "Feature type",
                "rtp.ext.ed137a.ft.type",
                FT_UINT8,
                BASE_HEX_DEC,
                VALS(rtp_ext_ed137a_ft_type),
                0xF0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_len,
            {
                "Feature length",
                "rtp.ext.ed137a.ft.len",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_value,
            {
                "Feature value",
                "rtp.ext.ed137a.ft.value",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_padding,
            {
                "Padding",
                "rtp.ext.ed137a.ft.padding",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_sqi_qidx,
            {
                "SQI Quality Index",
                "rtp.ext.ed137a.ft.sqi.qidx",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xF8,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_sqi_rssi_qidx,
            {
                "SQI Quality Index",
                "rtp.ext.ed137a.ft.sqi.qidx",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137a_ft_sqi_rssi_qidx),
                0xF8,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_sqi_qidx_ml,
            {
                "SQI Quality Index Method",
                "rtp.ext.ed137a.ft.sqi.qidx-ml",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137a_ft_sqi_qidx_ml),
                0x07,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_climax_delay_mode,
            {
                "CLIMAX-Time Delay Mode",
                "rtp.ext.ed137a.ft.climax_delay.mode",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137a_ft_climax_delay_mode),
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_climax_delay_relative_value,
            {
                "CLIMAX-Time Delay Relative",
                "rtp.ext.ed137a.ft.climax_delay.relative_value",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7F,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137a_ft_climax_delay_absolute_value,
            {
                "CLIMAX-Time Delay Absolute",
                "rtp.ext.ed137a.ft.climax_delay.absolute_value",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7F,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_rrc_single,
            {
                "RRC for single frequency",
                "rtp.ext.ed137b.ft.rrc.single",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_rrc_single_ms_tx_f1,
            {
                "MSTxF1",
                "rtp.ext.ed137b.ft.rrc.mstxf1",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_single_ms_tx_f1),
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_rrc_single_ms_rx_f1,
            {
                "MSRxF1",
                "rtp.ext.ed137b.ft.rrc.msrxf1",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_single_ms_rx_f1),
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_rrc_single_ms_tx_f2,
            {
                "MSTxF2",
                "rtp.ext.ed137b.ft.rrc.mstxf2",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_single_ms_tx_f2),
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_rrc_single_ms_rx_f2,
            {
                "MSRxF2",
                "rtp.ext.ed137b.ft.rrc.msrxf2",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_single_ms_rx_f2),
                0x10,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_rrc_single_sel_tx_f1,
            {
                "SelTxF1",
                "rtp.ext.ed137b.ft.rrc.seltxf1",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_single_sel_tx_f1),
                0x08,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_rrc_single_sel_tx_f2,
            {
                "SelTxF2",
                "rtp.ext.ed137b.ft.rrc.seltxf2",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_single_sel_tx_f2),
                0x04,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_rrc_single_mu_rx_f1,
            {
                "MuRxF1",
                "rtp.ext.ed137b.ft.rrc.murxf1",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_single_mu_rx_f1),
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_rrc_single_mu_rx_f2,
            {
                "MuRxF2",
                "rtp.ext.ed137b.ft.rrc.murxf2",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_single_mu_rx_f2),
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_unknown,
            {
                "CLIMAX Dynamic Delay Compensation Unknown Method",
                "rtp.ext.ed137b.ft.climax_ddc.unknown",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_rmm,
            {
                "CLIMAX Dynamic Delay Compensation RMM Request",
                "rtp.ext.ed137b.ft.climax_ddc.rmm",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_tqv,
            {
                "Time Quality VCS",
                "rtp.ext.ed137b.ft.climax_ddc.rmm_tqv",
                FT_UINT24,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_climax_ddc_time_quality),
                0x800000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_t1,
            {
                "T1",
                "rtp.ext.ed137b.ft.climax_ddc.rmm_t1",
                FT_UINT24,
                BASE_DEC,
                NULL,
                0x7FFFFF,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_mam,
            {
                "CLIMAX Dynamic Delay Compensation MAM Response (ED-137B)",
                "rtp.ext.ed137b.ft.climax_ddc.mam",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tqg,
            {
                "Time Quality GRS",
                "rtp.ext.ed137b.ft.climax_ddc.mam_tqg",
                FT_UINT24,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_climax_ddc_time_quality),
                0x800000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t1,
            {
                "T1",
                "rtp.ext.ed137b.ft.climax_ddc.mam_t1",
                FT_UINT24,
                BASE_DEC,
                NULL,
                0x7FFFFF,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_mam_nmr,
            {
                "New measurement requested",
                "rtp.ext.ed137b.ft.climax_ddc.mam_nmr",
                FT_UINT24,
                BASE_DEC,
                VALS(rtp_ext_ed137b_ft_climax_ddc_mam_nmr),
                0x800000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t2,
            {
                "T2",
                "rtp.ext.ed137b.ft.climax_ddc.mam_t2",
                FT_UINT24,
                BASE_DEC,
                NULL,
                0x7FFFFF,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tsd,
            {
                "Tsd",
                "rtp.ext.ed137b.ft.climax_ddc.mam_tsd",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tj1,
            {
                "Tj1",
                "rtp.ext.ed137b.ft.climax_ddc.mam_tj1",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tid,
            {
                "Tid",
                "rtp.ext.ed137b.ft.climax_ddc.mam_tid",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137c_ft_climax_ddc_mam,
            {
                "CLIMAX Dynamic Delay Compensation MAM Response (ED-137C)",
                "rtp.ext.ed137c.ft.climax_ddc.mam",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tqg,
            {
                "Time Quality GRS",
                "rtp.ext.ed137c.ft.climax_ddc.mam_tqg",
                FT_UINT24,
                BASE_DEC,
                VALS(rtp_ext_ed137c_ft_climax_ddc_time_quality),
                0x800000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t1,
            {
                "T1",
                "rtp.ext.ed137c.ft.climax_ddc.mam_t1",
                FT_UINT24,
                BASE_DEC,
                NULL,
                0x7FFFFF,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137c_ft_climax_ddc_mam_nmr,
            {
                "New measurement requested",
                "rtp.ext.ed137c.ft.climax_ddc.mam_nmr",
                FT_UINT24,
                BASE_DEC,
                VALS(rtp_ext_ed137c_ft_climax_ddc_mam_nmr),
                0x800000,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t2,
            {
                "T2",
                "rtp.ext.ed137c.ft.climax_ddc.mam_t2",
                FT_UINT24,
                BASE_DEC,
                NULL,
                0x7FFFFF,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tsd,
            {
                "Tsd",
                "rtp.ext.ed137c.ft.climax_ddc.mam_tsd",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tj1,
            {
                "Tj1",
                "rtp.ext.ed137c.ft.climax_ddc.mam_tj1",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tid,
            {
                "Tid",
                "rtp.ext.ed137c.ft.climax_ddc.mam_tid",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137c_ft_climax_ddc_mam_ts2,
            {
                "Ts2",
                "rtp.ext.ed137c.ft.climax_ddc.mam_ts2",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0,
                NULL, HFILL
            }
        },
    };

    static gint *ett[] =
    {
        &ett_hdr_ext_ed137s,
        &ett_hdr_ext_ed137,
        &ett_hdr_ext_ed137_add,
        &ett_hdr_ext_ed137a,
        &ett_hdr_ext_ed137a_add,
    };

    proto_rtp_ed137 = proto_register_protocol("Real-Time Transport Protocol ED137 Extensions", "RTP-ED137", "rtp.ext.ed137");
    proto_register_field_array(proto_rtp_ed137, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    rtp_hdr_ext_ed137_handle = register_dissector("rtp.ext.ed137", dissect_rtp_hdr_ext_ed137, proto_rtp_ed137);
    rtp_hdr_ext_ed137a_handle = register_dissector("rtp.ext.ed137a", dissect_rtp_hdr_ext_ed137a, proto_rtp_ed137);

    /* Table for ED-137A additional feature dissectors */
    rtp_hdr_ext_ed137a_add_features_table = register_dissector_table("rtp.hdr_ext.ed137a",
                                "RTP header ED137A additional features", proto_rtp_ed137, FT_UINT8, BASE_HEX);

    /* Register dissectors for tested additional headers */
    /* ED-137A signal quality information */
    rtp_hdr_ext_ed137a_feature_sqi_handle = register_dissector("rtp.hdr_ext.ed137a.ed137a_feature_sqi", dissect_rtp_hdr_ext_ed137a_feature_sqi, proto_rtp_ed137);
    dissector_add_uint("rtp.hdr_ext.ed137a", RTP_ED137A_feature_sqi_key, rtp_hdr_ext_ed137a_feature_sqi_handle);

    /* ED-137A CLIMAX time delay */
    rtp_hdr_ext_ed137a_feature_climax_tdly_handle = register_dissector("rtp.hdr_ext.ed137a.ed137a_feature_climax_tdly", dissect_rtp_hdr_ext_ed137a_feature_climax_tdly, proto_rtp_ed137);
    dissector_add_uint("rtp.hdr_ext.ed137a", RTP_ED137A_feature_climax_tdly_key, rtp_hdr_ext_ed137a_feature_climax_tdly_handle);

    /* ED-137B RRC for single frequency */
    rtp_hdr_ext_ed137b_feature_rrc_single_handle = register_dissector("rtp.hdr_ext.ed137a.ed137b_feature_rrc_single", dissect_rtp_hdr_ext_ed137b_feature_rrc_single, proto_rtp_ed137);
    dissector_add_uint("rtp.hdr_ext.ed137a", RTP_ED137B_feature_rrc_single_key, rtp_hdr_ext_ed137b_feature_rrc_single_handle);

    /* ED-137B CLIMAX request for measurement message (RMM) */
    rtp_hdr_ext_ed137b_feature_climax_ddc_rmm_handle = register_dissector("rtp.hdr_ext.ed137a.ed137b_feature_climax_ddc_rmm", dissect_rtp_hdr_ext_ed137b_feature_climax_ddc_rmm, proto_rtp_ed137);
    dissector_add_uint("rtp.hdr_ext.ed137a", RTP_ED137B_feature_climax_ddc_rmm_key, rtp_hdr_ext_ed137b_feature_climax_ddc_rmm_handle);

    /* ED-137B CLIMAX response message (MAM) */
    rtp_hdr_ext_ed137b_feature_climax_ddc_mam_handle = register_dissector("rtp.hdr_ext.ed137a.ed137b_feature_climax_ddc_mam", dissect_rtp_hdr_ext_ed137b_feature_climax_ddc_mam, proto_rtp_ed137);
    dissector_add_uint("rtp.hdr_ext.ed137a", RTP_ED137B_feature_climax_ddc_mam_key, rtp_hdr_ext_ed137b_feature_climax_ddc_mam_handle);

    /* ED-137C CLIMAX response message (MAM) */
    rtp_hdr_ext_ed137c_feature_climax_ddc_mam_handle = register_dissector("rtp.hdr_ext.ed137a.ed137c_feature_climax_ddc_mam", dissect_rtp_hdr_ext_ed137c_feature_climax_ddc_mam, proto_rtp_ed137);
    dissector_add_uint("rtp.hdr_ext.ed137a", RTP_ED137C_feature_climax_ddc_mam_key, rtp_hdr_ext_ed137c_feature_climax_ddc_mam_handle);
}

void
proto_reg_handoff_rtp_ed137(void)
{
    static gboolean prefs_initialized = FALSE;

    if (!prefs_initialized) {

        dissector_add_uint("rtp.hdr_ext", RTP_ED137_SIG, rtp_hdr_ext_ed137_handle);
        dissector_add_uint("rtp.hdr_ext", RTP_ED137A_SIG, rtp_hdr_ext_ed137a_handle);

        prefs_initialized = TRUE;
    }
}

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
