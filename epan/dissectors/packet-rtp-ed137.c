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
#include <epan/expert.h>
#include <epan/conversation.h>

#include "packet-rtp.h"

/* ED137 conversation proto data structure */
typedef struct _ed137_conv_info_t {
    wmem_tree_t *unmatched_pdus;
    wmem_tree_t *matched_pdus;
} ed137_conv_info_t;

/* ED137 RMM transaction data structure */
typedef struct _ed137rmm_transaction_t {
    uint32_t rqst_frame;
    uint32_t resp_frame;
    nstime_t rqst_time;
    nstime_t resp_time;
    uint8_t  time_quality;
} ed137rmm_transaction_t;

static int proto_rtp_ed137;

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
static int hf_rtp_hdr_ed137s;
static int hf_rtp_hdr_ed137;
static int hf_rtp_hdr_ed137_add;
static int hf_rtp_hdr_ed137_ptt_type;
static int hf_rtp_hdr_ed137_squ;
static int hf_rtp_hdr_ed137_ptt_id;
static int hf_rtp_hdr_ed137_sct;
static int hf_rtp_hdr_ed137_x;
static int hf_rtp_hdr_ed137_x_nu;
static int hf_rtp_hdr_ed137_ft_type;
static int hf_rtp_hdr_ed137_ft_len;
static int hf_rtp_hdr_ed137_ft_value;
static int hf_rtp_hdr_ed137_ft_bss_qidx;
static int hf_rtp_hdr_ed137_ft_bss_rssi_qidx;
static int hf_rtp_hdr_ed137_ft_bss_qidx_ml;
static int hf_rtp_hdr_ed137_vf;
static int hf_rtp_hdr_ed137_ft_climax_delay_value;

/* RTP header ED-137A extension fields   */
static int hf_rtp_hdr_ed137a;
static int hf_rtp_hdr_ed137a_add;
static int hf_rtp_hdr_ed137a_ptt_type;
static int hf_rtp_hdr_ed137a_squ;
static int hf_rtp_hdr_ed137a_ptt_id;
static int hf_rtp_hdr_ed137a_pm;
static int hf_rtp_hdr_ed137a_ptts;
static int hf_rtp_hdr_ed137a_sct;
static int hf_rtp_hdr_ed137a_reserved;
static int hf_rtp_hdr_ed137a_x;
static int hf_rtp_hdr_ed137a_x_nu;
static int hf_rtp_hdr_ed137a_ft_type;
static int hf_rtp_hdr_ed137a_ft_len;
static int hf_rtp_hdr_ed137a_ft_value;
static int hf_rtp_hdr_ed137a_ft_padding;
static int hf_rtp_hdr_ed137a_ft_sqi_qidx;
static int hf_rtp_hdr_ed137a_ft_sqi_rssi_qidx;
static int hf_rtp_hdr_ed137a_ft_sqi_qidx_ml;
static int hf_rtp_hdr_ed137a_ft_climax_delay_mode;
static int hf_rtp_hdr_ed137a_ft_climax_delay_relative_value;
static int hf_rtp_hdr_ed137a_ft_climax_delay_absolute_value;

/* RTP header ED-137B extension fields   */
static int hf_rtp_hdr_ed137b_ft_rrc_single;
static int hf_rtp_hdr_ed137b_ft_rrc_single_ms_tx_f1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_ms_rx_f1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_ms_tx_f2;
static int hf_rtp_hdr_ed137b_ft_rrc_single_ms_rx_f2;
static int hf_rtp_hdr_ed137b_ft_rrc_single_sel_tx_f1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_sel_tx_f2;
static int hf_rtp_hdr_ed137b_ft_rrc_single_mu_rx_f1;
static int hf_rtp_hdr_ed137b_ft_rrc_single_mu_rx_f2;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_rmm;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_tqv;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_t1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tqg;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_nmr;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t2;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tsd;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tj1;
static int hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tid;

/* RTP header ED-137C extension fields   */
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tqg;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_nmr;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t2;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tsd;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tj1;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tid;
static int hf_rtp_hdr_ed137c_ft_climax_ddc_mam_ts2;

static int hf_rtp_hdr_ed137_ft_climax_ddc_rmm_response_in;
static int hf_rtp_hdr_ed137_ft_climax_ddc_rmm_no_resp;
static int hf_rtp_hdr_ed137_ft_climax_ddc_mam_request_in;
static int hf_rtp_hdr_ed137_ft_climax_ddc_mam_time;

static expert_field ei_rtp_hdr_ed137_ft_climax_ddc_rmm_resp_not_found;
static expert_field ei_rtp_hdr_ed137_ft_sqi_rssi_out_of_range;

static int ett_hdr_ext_ed137s;
static int ett_hdr_ext_ed137;
static int ett_hdr_ext_ed137_add;
static int ett_hdr_ext_ed137a;
static int ett_hdr_ext_ed137a_add;

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
    bool ed137_ptt = false;
    bool ed137_squ = false;

    hdr_extension_len = tvb_reported_length(tvb);

    if ( hdr_extension_len > 0 ) {

        if (rtp_info != NULL) {
            rtp_info->info_is_ed137 = true;
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
            uint32_t ext_value = tvb_get_ntohl( tvb, hdrext_offset );

            if (RTP_ED137_ptt_mask(ext_value)) {
                col_append_str(pinfo->cinfo, COL_INFO, ", PTT");
                ed137_ptt = true;
            }
            if (RTP_ED137_squ_mask(ext_value)) {
                col_append_str(pinfo->cinfo, COL_INFO, ", SQU");
                ed137_squ = true;
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
static void process_time_value(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, int time_item, unsigned int hdrext_offset, bool time_relative _U_, unsigned int time_value)
{
    /* Note: even there is relative/absolute flag, value is shown same way because it is relative value derived from relative/absolute start point */
    unsigned int time_calc;
    nstime_t tmp_time;
    char *tmp;

    /* Value is stored as count of 125 us ticks */
    time_calc = time_value * 125;
    NSTIME_INIT_USEC(tmp_time, time_calc);
    tmp = rel_time_to_secs_str(pinfo->pool, &tmp_time);

    proto_tree_add_uint_format_value( tree, time_item, tvb, hdrext_offset, 3, time_value, "%s s", tmp);
}

/* Decodes and calculates value based on 125us tick*/
static void process_125us_based_value(tvbuff_t *tvb, proto_tree *tree, int value_item, unsigned int hdrext_offset)
{
    uint32_t value;
    uint32_t value_calc;

    /* Values is stored as count of 125 us ticks */
    value = tvb_get_ntohs( tvb, hdrext_offset );
    value_calc = value * 125;

    proto_tree_add_uint_format_value( tree, value_item, tvb, hdrext_offset, 2, value, "%d us", value_calc);
}

static int
dissect_rtp_hdr_ext_ed137a_feature_sqi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    uint32_t ext_value;
    uint32_t sqi_qidx;
    uint32_t sqi_qidx_ml;
    proto_item *it;

    ext_value = tvb_get_uint8( tvb, 0 );
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
            it = proto_tree_add_item( tree, hf_rtp_hdr_ed137a_ft_sqi_qidx, tvb, 0, 1, ENC_BIG_ENDIAN);
            expert_add_info_format(pinfo, it, &ei_rtp_hdr_ed137_ft_sqi_rssi_out_of_range, "RSSI index out of range");
        }
    }
    else {
        /* Other SQI method handling */
        proto_tree_add_item( tree, hf_rtp_hdr_ed137a_ft_sqi_qidx, tvb, 0, 1, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item( tree, hf_rtp_hdr_ed137a_ft_sqi_qidx_ml, tvb, 0, 1, ENC_BIG_ENDIAN);

    if (sqi_qidx>0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", SQI=%u", sqi_qidx);
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, ", SQI N/A");
    }

    return tvb_captured_length(tvb);
}

static int
dissect_rtp_hdr_ext_ed137a_feature_climax_tdly(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    uint32_t ext_value;
    uint32_t climax_tdly_mode;
    uint32_t climax_tdly_value;
    uint32_t climax_tdly_value_calc;

    ext_value = tvb_get_uint8( tvb, 0 );

    climax_tdly_mode = RTP_ED137A_feature_climax_tdly_mode(ext_value);
    climax_tdly_value = RTP_ED137A_feature_climax_tdly_value(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137a_ft_climax_delay_mode, tvb, 0, 1, ENC_BIG_ENDIAN);
    if (RTP_ED137A_feature_climax_tdly_mode_relative == climax_tdly_mode) {
        /* Relative delay, in 2ms steps */
        climax_tdly_value_calc=2*climax_tdly_value;

        proto_tree_add_uint_format_value( tree, hf_rtp_hdr_ed137a_ft_climax_delay_relative_value, tvb, 0, 1, climax_tdly_value, "%d ms", climax_tdly_value_calc);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", CMX=%ums rel", climax_tdly_value_calc);

    }
    else {
        /* Absolute delay, in 2ms steps */
        climax_tdly_value_calc=2*climax_tdly_value;

        proto_tree_add_uint_format_value( tree, hf_rtp_hdr_ed137a_ft_climax_delay_absolute_value, tvb, 0, 1, climax_tdly_value, "%d ms", climax_tdly_value_calc);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", CMX=%ums abs", climax_tdly_value_calc);

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

    col_append_str(pinfo->cinfo, COL_INFO, ", RRC");

    return tvb_captured_length(tvb);
}

/* ======================================================================= */
/*
    Note: We are tracking conversations via the T1 key as response shall contain a copy of this field
*/
static ed137rmm_transaction_t *transaction_start(packet_info * pinfo,
                         proto_tree * tree,
                         uint32_t * key,
                         uint8_t time_quality_vcs)
{
    conversation_t *conversation;
    ed137_conv_info_t *ed137_info;
    ed137rmm_transaction_t *ed137rmm_trans;
    wmem_tree_key_t ed137rmm_key[3];
    proto_item *it;

    /* Handle the conversation tracking */
    conversation = find_or_create_conversation(pinfo);
    ed137_info = (ed137_conv_info_t *)conversation_get_proto_data(conversation, proto_rtp_ed137);
    if (ed137_info == NULL) {
        ed137_info = wmem_new(wmem_file_scope(), ed137_conv_info_t);
        ed137_info->unmatched_pdus = wmem_tree_new(wmem_file_scope());
        ed137_info->matched_pdus   = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_rtp_ed137,
                        ed137_info);
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        /* this is a new request, create a new transaction structure and map it to the
           unmatched table
         */
        ed137rmm_key[0].length = 1;
        ed137rmm_key[0].key = key;
        ed137rmm_key[1].length = 0;
        ed137rmm_key[1].key = NULL;

        ed137rmm_trans = wmem_new(wmem_file_scope(), ed137rmm_transaction_t);
        ed137rmm_trans->rqst_frame = pinfo->num;
        ed137rmm_trans->resp_frame = 0;
        ed137rmm_trans->rqst_time = pinfo->abs_ts;
        ed137rmm_trans->time_quality = time_quality_vcs;
        nstime_set_zero(&ed137rmm_trans->resp_time);
        wmem_tree_insert32_array(ed137_info->unmatched_pdus, ed137rmm_key,
                       (void *) ed137rmm_trans);
    } else {
        /* Already visited this frame */
        uint32_t frame_num = pinfo->num;

        ed137rmm_key[0].length = 1;
        ed137rmm_key[0].key = key;
        ed137rmm_key[1].length = 1;
        ed137rmm_key[1].key = &frame_num;
        ed137rmm_key[2].length = 0;
        ed137rmm_key[2].key = NULL;

        ed137rmm_trans =
            (ed137rmm_transaction_t *)wmem_tree_lookup32_array(ed137_info->matched_pdus,
                       ed137rmm_key);
    }
    if (ed137rmm_trans == NULL) {
        if (PINFO_FD_VISITED(pinfo)) {
            /* No response found - add field and expert info */
            it = proto_tree_add_item(tree, hf_rtp_hdr_ed137_ft_climax_ddc_rmm_no_resp, NULL, 0, 0,
                         ENC_NA);
            proto_item_set_generated(it);

            col_append_fstr(pinfo->cinfo, COL_INFO, ", RMM (no response found!)");

            /* Expert info. */
            expert_add_info_format(pinfo, it, &ei_rtp_hdr_ed137_ft_climax_ddc_rmm_resp_not_found,
                           "No response seen to RMM request");
        }

        return NULL;
    }

    /* Print state tracking in the tree */
    if (ed137rmm_trans->resp_frame) {
        it = proto_tree_add_uint(tree, hf_rtp_hdr_ed137_ft_climax_ddc_rmm_response_in, NULL, 0, 0,
                     ed137rmm_trans->resp_frame);
        proto_item_set_generated(it);

        col_append_frame_number(pinfo, COL_INFO, ", RMM (reply in %u)",
                ed137rmm_trans->resp_frame);
    }

    return ed137rmm_trans;

}                /* transaction_start() */

/* ======================================================================= */
static ed137rmm_transaction_t *transaction_end(packet_info * pinfo,
                       proto_tree * tree,
                       uint32_t * key,
                       uint8_t time_quality_grs,
                       uint32_t delta_t,
                       uint32_t tsd,
                       uint32_t internal_t)
{
    conversation_t *conversation;
    ed137_conv_info_t *ed137_info;
    ed137rmm_transaction_t *ed137rmm_trans;
    wmem_tree_key_t ed137rmm_key[3];
    proto_item *it;
    nstime_t ns;
    double resp_time;

    conversation =
            find_conversation_pinfo(pinfo,0);
    if (conversation == NULL) {
        return NULL;
    }

    ed137_info = (ed137_conv_info_t *)conversation_get_proto_data(conversation, proto_rtp_ed137);
    if (ed137_info == NULL) {
        return NULL;
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        uint32_t frame_num;

        ed137rmm_key[0].length = 1;
        ed137rmm_key[0].key = key;
        ed137rmm_key[1].length = 0;
        ed137rmm_key[1].key = NULL;
        ed137rmm_trans =
            (ed137rmm_transaction_t *)wmem_tree_lookup32_array(ed137_info->unmatched_pdus,
                       ed137rmm_key);
        if (ed137rmm_trans == NULL) {
            return NULL;
        }

        /* we have already seen this response, or an identical one */
        if (ed137rmm_trans->resp_frame != 0) {
            return NULL;
        }

        ed137rmm_trans->resp_frame = pinfo->num;
        ed137rmm_trans->time_quality |= time_quality_grs<<1;

        /* we found a match. Add entries to the matched table for both request and reply frames
         */
        ed137rmm_key[0].length = 1;
        ed137rmm_key[0].key = key;
        ed137rmm_key[1].length = 1;
        ed137rmm_key[1].key = &frame_num;
        ed137rmm_key[2].length = 0;
        ed137rmm_key[2].key = NULL;

        frame_num = ed137rmm_trans->rqst_frame;
        wmem_tree_insert32_array(ed137_info->matched_pdus, ed137rmm_key,
                       (void *) ed137rmm_trans);

        frame_num = ed137rmm_trans->resp_frame;
        wmem_tree_insert32_array(ed137_info->matched_pdus, ed137rmm_key,
                       (void *) ed137rmm_trans);
    } else {
        /* Already visited this frame */
        uint32_t frame_num = pinfo->num;

        ed137rmm_key[0].length = 1;
        ed137rmm_key[0].key = key;
        ed137rmm_key[1].length = 1;
        ed137rmm_key[1].key = &frame_num;
        ed137rmm_key[2].length = 0;
        ed137rmm_key[2].key = NULL;

        ed137rmm_trans =
            (ed137rmm_transaction_t *)wmem_tree_lookup32_array(ed137_info->matched_pdus,
                       ed137rmm_key);

        if (ed137rmm_trans == NULL) {
            return NULL;
        }
    }


    it = proto_tree_add_uint(tree, hf_rtp_hdr_ed137_ft_climax_ddc_mam_request_in, NULL, 0, 0,
                 ed137rmm_trans->rqst_frame);
    proto_item_set_generated(it);

    nstime_delta(&ns, &pinfo->abs_ts, &ed137rmm_trans->rqst_time);
    ed137rmm_trans->resp_time = ns;
    resp_time = nstime_to_msec(&ns);
    it = proto_tree_add_double_format_value(tree, hf_rtp_hdr_ed137_ft_climax_ddc_mam_time,
                        NULL, 0, 0, resp_time,
                        "%.3f ms", resp_time);
    proto_item_set_generated(it);

    if (ed137rmm_trans->time_quality == 3) {
        // All sync, delta t is accurate, add internal delta t, multiply by 0.125
        col_append_fstr(pinfo->cinfo, COL_INFO, ", MAM=%.3f ms",(double)(delta_t+internal_t)*0.125); // 125 us ticks
    }
    else {
        // No sync, estimated delay only. Formula is delta t = (T4-T1-tsd)/2 where T4 is the local time at which the VCS endpoint receives the MAM message.
        // We have T1 but NOT T4, so we use the frame capture time and delta t = resp_time in this case.
        // TODO Test whether resp_time + 2 * (t(RMM)-T1) is accurate.
        // resp_time is in msec, while tsd and internal_t are 125 usec ticks!
        col_append_fstr(pinfo->cinfo, COL_INFO, ", MAM>%.3f ms",(resp_time - (tsd*0.125)) / 2 + internal_t*0.125);
    }

    col_append_frame_number(pinfo, COL_INFO, " (request in %u)",
            ed137rmm_trans->rqst_frame);

    return ed137rmm_trans;

}                /* transaction_end() */

static int
dissect_rtp_hdr_ext_ed137b_feature_climax_ddc_rmm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    uint32_t ext_value;
    proto_tree *item;
    uint32_t climax_ddc_rmm_tqv;
    uint32_t climax_ddc_rmm_t1;

    /* Generated item points really to previous byte */
    item = proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_rmm, tvb, -1, 1, ENC_NA);
    proto_item_set_generated(item);

    ext_value = tvb_get_ntoh24( tvb, 0 );
    climax_ddc_rmm_tqv = RTP_ED137B_feature_climax_ddc_rmm_tqv(ext_value);
    climax_ddc_rmm_t1 = RTP_ED137B_feature_climax_ddc_rmm_t1(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_tqv, tvb, 0, 3, ENC_BIG_ENDIAN);
    process_time_value(pinfo, tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_rmm_t1, 0, (RTP_ED137B_feature_climax_ddc_rmm_tqv_relative == climax_ddc_rmm_tqv), climax_ddc_rmm_t1);

    transaction_start(pinfo,tree,&climax_ddc_rmm_t1,climax_ddc_rmm_tqv);

    return tvb_captured_length(tvb);
}

static int
dissect_rtp_hdr_ext_ed137b_feature_climax_ddc_mam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    uint32_t ext_value;
    proto_tree *item;
    uint32_t climax_ddc_mam_tqg;
    uint32_t climax_ddc_mam_t1;
    uint32_t climax_ddc_mam_t2;

    /* Generated item points really to previous byte */
    item = proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam, tvb, -1, 1, ENC_NA);
    proto_item_set_generated(item);

    ext_value = tvb_get_ntoh24( tvb, 0 + 0 );
    climax_ddc_mam_tqg = RTP_ED137B_feature_climax_ddc_mam_tqg(ext_value);
    climax_ddc_mam_t1 = RTP_ED137B_feature_climax_ddc_mam_t1(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tqg, tvb, 0, 3, ENC_BIG_ENDIAN);
    process_time_value(pinfo, tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t1, 0, (RTP_ED137B_feature_climax_ddc_mam_tqg_relative == climax_ddc_mam_tqg), climax_ddc_mam_t1);

    ext_value = tvb_get_ntoh24( tvb, 0 + 3 );
    climax_ddc_mam_t2 = RTP_ED137B_feature_climax_ddc_mam_t2(ext_value);

    if (RTP_ED137B_feature_climax_ddc_mam_nmr(ext_value)) {
        col_append_str(pinfo->cinfo, COL_INFO, ", NMR");
    }

    proto_tree_add_item( tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_nmr, tvb, 0 + 3, 3, ENC_BIG_ENDIAN);
    process_time_value(pinfo, tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_t2, 0 + 3, (RTP_ED137B_feature_climax_ddc_mam_tqg_relative == climax_ddc_mam_tqg), climax_ddc_mam_t2);

    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tsd, 0 + 6);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tj1, 0 + 8);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137b_ft_climax_ddc_mam_tid, 0 + 10);

    if (climax_ddc_mam_t2 < climax_ddc_mam_t1) {
        climax_ddc_mam_t2 += 0x800000; // t1 and t2 are 23 bits long
    }
    transaction_end(pinfo,tree,&climax_ddc_mam_t1,climax_ddc_mam_tqg,climax_ddc_mam_t2-climax_ddc_mam_t1,tvb_get_ntohs( tvb, 0+6 ),tvb_get_ntohs( tvb, 0+8 ) + tvb_get_ntohs( tvb, 0+10 ));

    return tvb_captured_length(tvb);
}

static int
dissect_rtp_hdr_ext_ed137c_feature_climax_ddc_mam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    uint32_t ext_value;
    proto_tree *item;
    uint32_t climax_ddc_mam_tqg;
    uint32_t climax_ddc_mam_t1;
    uint32_t climax_ddc_mam_t2;

    /* Generated item points really to previous byte */
    item = proto_tree_add_item( tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam, tvb, -1, 1, ENC_NA);
    proto_item_set_generated(item);

    ext_value = tvb_get_ntoh24( tvb, 0 + 0 );
    climax_ddc_mam_tqg = RTP_ED137C_feature_climax_ddc_mam_tqg(ext_value);
    climax_ddc_mam_t1 = RTP_ED137C_feature_climax_ddc_mam_t1(ext_value);

    proto_tree_add_item( tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tqg, tvb, 0, 3, ENC_BIG_ENDIAN);
    process_time_value(pinfo, tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t1, 0, (RTP_ED137C_feature_climax_ddc_mam_tqg_relative == climax_ddc_mam_tqg), climax_ddc_mam_t1);

    ext_value = tvb_get_ntoh24( tvb, 0 + 3 );
    climax_ddc_mam_t2 = RTP_ED137C_feature_climax_ddc_mam_t2(ext_value);

    if (RTP_ED137B_feature_climax_ddc_mam_nmr(ext_value)) {
        // New measurement request is sent in case of some unexpected event requiring a new measurement
        col_append_str(pinfo->cinfo, COL_INFO, ", NMR");
    }

    proto_tree_add_item( tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_nmr, tvb, 0 + 3, 3, ENC_BIG_ENDIAN);
    process_time_value(pinfo, tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_t2, 0 + 3, (RTP_ED137C_feature_climax_ddc_mam_tqg_relative == climax_ddc_mam_tqg), climax_ddc_mam_t2);

    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tsd, 0 + 6);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tj1, 0 + 8);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_tid, 0 + 10);
    process_125us_based_value( tvb, tree, hf_rtp_hdr_ed137c_ft_climax_ddc_mam_ts2, 0 + 12);

    if (climax_ddc_mam_t2 < climax_ddc_mam_t1) {
        climax_ddc_mam_t2 += 0x800000; // t1 and t2 are 23 bits long
    }
    transaction_end(pinfo,tree,&climax_ddc_mam_t1,climax_ddc_mam_tqg,climax_ddc_mam_t2-climax_ddc_mam_t1,tvb_get_ntohs( tvb, 0+6 ),tvb_get_ntohs( tvb, 0+8 ) + tvb_get_ntohs( tvb, 0+10 ));

    return tvb_captured_length(tvb);
}

/* Decode ED-137A fixed part and call dissectors for variable part */
static int
dissect_rtp_hdr_ext_ed137a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    uint32_t hdr_extension_len;
    struct _rtp_info *rtp_info=(struct _rtp_info *)data;
    proto_tree *rtp_hext_tree = NULL;
    uint32_t hdrext_offset = 0;
    bool ed137_ptt = false;
    bool ed137_squ = false;

    hdr_extension_len = tvb_reported_length(tvb);

    if ( hdr_extension_len > 0 ) {
        proto_item *ti2;
        proto_tree *rtp_hext_tree2;
        uint32_t ext_value = tvb_get_ntohs( tvb, hdrext_offset );

        if (rtp_info != NULL) {
            rtp_info->info_is_ed137 = true;
        }
        if ( tree ) {
            proto_item *ti;
            ti = proto_tree_add_item(tree, hf_rtp_hdr_ed137s, tvb, 0, hdr_extension_len, ENC_NA);
            rtp_hext_tree = proto_item_add_subtree( ti, ett_hdr_ext_ed137s );
        }

        if (RTP_ED137A_ptt_mask(ext_value)) {
            col_append_str(pinfo->cinfo, COL_INFO, ", PTT");
            ed137_ptt = true;
        }
        if (RTP_ED137A_squ_mask(ext_value)) {
            col_append_str(pinfo->cinfo, COL_INFO, ", SQU");
            ed137_squ = true;
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
            /* The shortest header length is 2, anything shorter is padding */
            while ( hdr_extension_len >= 2 ) {
                proto_item *ti3;
                proto_tree *rtp_hext_tree3;
                uint32_t ft_type;
                uint32_t ft_len;

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

                    tvbuff_t   *newtvb;
                    uint32_t    ft_table_key;

                    /* join 4 bit type and 4 bit length to 8 bit key */
                    ft_table_key = MAKE_KEY( ft_type, ft_len );

                    /* pass interpretation of header extension to a registered subdissector */
                    /* new subset points to value (starts behind type/length pair) */
                    newtvb = tvb_new_subset_length(tvb, hdrext_offset, hdr_extension_len);

                    /* try to find a dissector by type/len key and dissect additional feature header */
                    if ( !(dissector_try_uint(rtp_hdr_ext_ed137a_add_features_table, ft_table_key, newtvb, pinfo, rtp_hext_tree3)) ) {
                        proto_tree_add_item( rtp_hext_tree3, hf_rtp_hdr_ed137a_ft_value, tvb, hdrext_offset, ft_len, ENC_NA);
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
            uint32_t hdr_extension_padding;

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
        {
            &hf_rtp_hdr_ed137_ft_climax_ddc_rmm_no_resp,
            {
                "No response seen",
                "rtp.ext.ed137.ft.climax_ddc.rmm.no_resp",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                "No corresponding response frame was seen", HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_climax_ddc_rmm_response_in,
            {
                "Response in frame",
                "rtp.ext.ed137.ft.climax_ddc.rmm.response_in",
                FT_FRAMENUM,
                BASE_NONE,
                FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE),
                0,
                "This packet will be responded in the packet with this number", HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_climax_ddc_mam_request_in,
            {
                "Request in frame",
                "rtp.ext.ed137.ft.climax_ddc.mam.request_in",
                FT_FRAMENUM,
                BASE_NONE,
                FRAMENUM_TYPE(FT_FRAMENUM_REQUEST),
                0,
                "This packet is a response to the packet with this number", HFILL
            }
        },
        {
            &hf_rtp_hdr_ed137_ft_climax_ddc_mam_time,
            {
                "Response time",
                "rtp.ext.ed137.ft.climax_ddc.rmm.resptime",
                FT_DOUBLE,
                BASE_NONE,
                NULL,
                0x0,
                "The time between the request and the response, in ms.", HFILL
            }
        },
    };

    static int *ett[] =
    {
        &ett_hdr_ext_ed137s,
        &ett_hdr_ext_ed137,
        &ett_hdr_ext_ed137_add,
        &ett_hdr_ext_ed137a,
        &ett_hdr_ext_ed137a_add,
    };

    static ei_register_info ei[] =
    {
        { &ei_rtp_hdr_ed137_ft_climax_ddc_rmm_resp_not_found, { "rtp.ext.ed137a.resp_not_found", PI_SEQUENCE, PI_WARN, "Response not found", EXPFILL }},
        { &ei_rtp_hdr_ed137_ft_sqi_rssi_out_of_range, { "rtp.ext.ed137a.sqi.out_of_range", PI_MALFORMED, PI_ERROR, "Index out of range", EXPFILL }},
    };

    expert_module_t* expert_rtp_ed137;

    proto_rtp_ed137 = proto_register_protocol("Real-Time Transport Protocol ED137 Extensions", "RTP-ED137", "rtp.ext.ed137");
    proto_register_field_array(proto_rtp_ed137, hf, array_length(hf));
    expert_rtp_ed137 = expert_register_protocol(proto_rtp_ed137);
    expert_register_field_array(expert_rtp_ed137, ei, array_length(ei));
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
    static bool prefs_initialized = false;

    if (!prefs_initialized) {

        dissector_add_uint("rtp.hdr_ext", RTP_ED137_SIG, rtp_hdr_ext_ed137_handle);
        dissector_add_uint("rtp.hdr_ext", RTP_ED137A_SIG, rtp_hdr_ext_ed137a_handle);

        prefs_initialized = true;
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
