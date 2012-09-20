/* packet-homeplug.c
 * Routines for homeplug dissection
 *
 * Copyright 2006, Sebastien Tandel <sebastien[AT]tandel.be>
 * Copyright 2009, Luca Ceresoli <luca[AT]lucaceresoli.net>
 *
 * $Id$
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
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include <epan/etypes.h>

#include <epan/ptvcursor.h>

static int proto_homeplug                     = -1;

static int hf_homeplug_mctrl                  = -1;
static int hf_homeplug_mctrl_reserved         = -1;
static int hf_homeplug_mctrl_ne               = -1;
static int hf_homeplug_mehdr                  = -1;
static int hf_homeplug_mehdr_mev              = -1;
static int hf_homeplug_mehdr_metype           = -1;
static int hf_homeplug_melen                  = -1;
static int hf_homeplug_mme                    = -1;
  /* Request Channel Estimation */
static int hf_homeplug_rce                    = -1;
static int hf_homeplug_rce_cev                = -1;
static int hf_homeplug_rce_rsvd               = -1;
  /* Channel Estimation Response */
static int hf_homeplug_cer                    = -1;
static int hf_homeplug_cer_cerv               = -1;
static int hf_homeplug_cer_rsvd1              = -1;
static int hf_homeplug_cer_rxtmi              = -1;
static int hf_homeplug_cer_vt                 = -1;
static int hf_homeplug_cer_rate               = -1;
static int hf_homeplug_cer_bp                 = -1;
static int hf_homeplug_cer_mod                = -1;
static int hf_homeplug_cer_vt11               = -1;
static int hf_homeplug_cer_rsvd2              = -1;
static int hf_homeplug_cer_nbdas              = -1;
static int hf_homeplug_cer_bda                = -1;
  /* Replace Bridge Address */
static int hf_homeplug_rba                    = -1;
  /* Vendor Specific */
static int hf_homeplug_vs                     = -1;
static int hf_homeplug_vs_oui                 = -1;
static int hf_homeplug_vs_dir                 = -1;
static int hf_homeplug_vs_mid                 = -1;
  /* Set Network Encryption Key */
static int hf_homeplug_snk                    = -1;
static int hf_homeplug_snk_eks                = -1;
static int hf_homeplug_snk_nek                = -1;
  /* Multicast With Response */
static int hf_homeplug_mwr                    = -1;
  /* Confirm Network Encryption Key */
static int hf_homeplug_cnk                    = -1;
  /* Host Tag */
static int hf_homeplug_htag                   = -1;
  /* Request Parameters and Statistics */
static int hf_homeplug_rps                    = -1;
  /* Parameters and Statistics Response */
static int hf_homeplug_psr                    = -1;
static int hf_homeplug_psr_txack              = -1;
static int hf_homeplug_psr_txnack             = -1;
static int hf_homeplug_psr_txfail             = -1;
static int hf_homeplug_psr_txcloss            = -1;
static int hf_homeplug_psr_txcoll             = -1;
static int hf_homeplug_psr_txca3lat           = -1;
static int hf_homeplug_psr_txca2lat           = -1;
static int hf_homeplug_psr_txca1lat           = -1;
static int hf_homeplug_psr_txca0lat           = -1;
static int hf_homeplug_psr_rxbp40             = -1;
  /* Set Local Parameters */
static int hf_homeplug_slp                    = -1;
static int hf_homeplug_slp_ma                 = -1;
  /* Loader */
static int hf_homeplug_loader                 = -1;
static int hf_homeplug_loader_mid             = -1;
static int hf_homeplug_loader_length          = -1;
static int hf_homeplug_loader_status          = -1;
static int hf_homeplug_loader_version         = -1;
static int hf_homeplug_loader_gdfv            = -1;
static int hf_homeplug_loader_lsf             = -1;
static int hf_homeplug_loader_lwm             = -1;
static int hf_homeplug_loader_lrm             = -1;
static int hf_homeplug_loader_lrnvm           = -1;
static int hf_homeplug_loader_lwnvm           = -1;
static int hf_homeplug_loader_lreset          = -1;
static int hf_homeplug_loader_gmd             = -1;
static int hf_homeplug_loader_smd             = -1;
static int hf_homeplug_loader_module_id       = -1;
static int hf_homeplug_loader_module_offset   = -1;
static int hf_homeplug_loader_module_size     = -1;
static int hf_homeplug_loader_data_length     = -1;
static int hf_homeplug_loader_data_address    = -1;
static int hf_homeplug_loader_data            = -1;
static int hf_homeplug_loader_cm              = -1;
static int hf_homeplug_loader_lemd            = -1;
static int hf_homeplug_loader_lenvms          = -1;
static int hf_homeplug_loader_gnvmp           = -1;
static int hf_homeplug_loader_snvmp           = -1;
static int hf_homeplug_loader_nvmp_type       = -1;
static int hf_homeplug_loader_nvmp_pagesize   = -1;
static int hf_homeplug_loader_nvmp_blocksize  = -1;
static int hf_homeplug_loader_nvmp_memorysize = -1;
  /* Host Request */
static int hf_homeplug_hreq                   = -1;
static int hf_homeplug_hreq_mid               = -1;
static int hf_homeplug_hreq_gdv               = -1;
static int hf_homeplug_hreq_gfv               = -1;
static int hf_homeplug_hreq_gnek              = -1;
static int hf_homeplug_hreq_gclbpl            = -1;
static int hf_homeplug_hreq_nvds              = -1;
static int hf_homeplug_hreq_grbt              = -1;
static int hf_homeplug_hreq_gslnm             = -1;
static int hf_homeplug_hreq_gsss              = -1;
static int hf_homeplug_hreq_rsl               = -1;
static int hf_homeplug_hreq_reset             = -1;
static int hf_homeplug_hreq_reset_type        = -1;
static int hf_homeplug_hreq_reset_delay       = -1;
  /* Host Response */
static int hf_homeplug_hrsp                   = -1;
static int hf_homeplug_hrsp_mid               = -1;
static int hf_homeplug_hrsp_gdvr              = -1;
static int hf_homeplug_hrsp_gfvr              = -1;
static int hf_homeplug_hrsp_gnekr             = -1;
static int hf_homeplug_hrsp_gnekr_select      = -1;
static int hf_homeplug_hrsp_gnekr_key         = -1;
static int hf_homeplug_hrsp_invalid           = -1;
static int hf_homeplug_hrsp_version           = -1;
  /* Network Statistics */
static int hf_homeplug_ns                     = -1;
static int hf_homeplug_ns_extended            = -1;
    /* Basic */
static int hf_homeplug_ns_netw_ctrl_ac        = -1;
static int hf_homeplug_ns_netw_ctrl_icid      = -1;
static int hf_homeplug_ns_bytes40_robo        = -1;
static int hf_homeplug_ns_fails_robo          = -1;
static int hf_homeplug_ns_drops_robo          = -1;
static int hf_homeplug_ns_netw_da             = -1;
static int hf_homeplug_ns_bytes40             = -1;
static int hf_homeplug_ns_fails               = -1;
static int hf_homeplug_ns_drops               = -1;
    /* Extended */
static int hf_homeplug_ns_tx_bfr_state        = -1;
static int hf_homeplug_ns_buf_in_use          = -1;
static int hf_homeplug_ns_prio                = -1;
static int hf_homeplug_ns_msdu_len            = -1;
static int hf_homeplug_ns_seqn                = -1;
static int hf_homeplug_ns_toneidx             = -1;
  /* Bridging Characteristics Network */
static int hf_homeplug_bcn                    = -1;
static int hf_homeplug_bcn_network            = -1;
static int hf_homeplug_bcn_return             = -1;
static int hf_homeplug_bcn_rsvd               = -1;
static int hf_homeplug_bcn_fbn                = -1;
static int hf_homeplug_bcn_brda               = -1;
static int hf_homeplug_bcn_bp_das             = -1;
static int hf_homeplug_bcn_bp_da              = -1;
  /* Bridging Characteristics Local */
static int hf_homeplug_bcl                    = -1;
static int hf_homeplug_bcl_network            = -1;
static int hf_homeplug_bcl_return             = -1;
static int hf_homeplug_bcl_rsvd               = -1;
static int hf_homeplug_bcl_hprox_das          = -1;
static int hf_homeplug_bcl_hpbda              = -1;
  /* Set Transmit Characteristics */
static int hf_homeplug_stc                    = -1;
static int hf_homeplug_stc_lco                = -1;
static int hf_homeplug_stc_encf               = -1;
static int hf_homeplug_stc_txprio             = -1;
static int hf_homeplug_stc_rexp               = -1;
static int hf_homeplug_stc_txcf               = -1;
static int hf_homeplug_stc_cftop              = -1;
static int hf_homeplug_stc_rsvd1              = -1;
static int hf_homeplug_stc_retry              = -1;
static int hf_homeplug_stc_rsvd2              = -1;
static int hf_homeplug_stc_dder               = -1;
static int hf_homeplug_stc_dur                = -1;
static int hf_homeplug_stc_ebp                = -1;
static int hf_homeplug_stc_dees               = -1;
static int hf_homeplug_stc_txeks              = -1;
static int hf_homeplug_data                   = -1;

static gint ett_homeplug                      = -1;
static gint ett_homeplug_mctrl                = -1;
static gint ett_homeplug_mehdr                = -1;
static gint ett_homeplug_vs_mid               = -1;
static gint ett_homeplug_rce                  = -1;
static gint ett_homeplug_cer                  = -1;
static gint ett_homeplug_vs                   = -1;
static gint ett_homeplug_snk                  = -1;
static gint ett_homeplug_rps                  = -1;
static gint ett_homeplug_psr                  = -1;
static gint ett_homeplug_slp                  = -1;
static gint ett_homeplug_loader               = -1;
static gint ett_homeplug_hreq                 = -1;
static gint ett_homeplug_hrsp                 = -1;
static gint ett_homeplug_ns                   = -1;
static gint ett_homeplug_tone                 = -1;
static gint ett_homeplug_tx_bfr_state         = -1;
static gint ett_homeplug_bridge               = -1;
static gint ett_homeplug_bcn                  = -1;
static gint ett_homeplug_bcl                  = -1;
static gint ett_homeplug_stc                  = -1;


static guint8  homeplug_ne     = 0;
static guint8  homeplug_melen  = 0;
static guint8  homeplug_metype = 0;

static guint32 homeplug_offset = 0;


/* METYPE Values */
#define HOMEPLUG_MME_RCE      0x00
#define HOMEPLUG_MME_CER      0x01
#define HOMEPLUG_MME_VS       0x02
#define HOMEPLUG_MME_RBA      0x03
#define HOMEPLUG_MME_SNK      0x04
#define HOMEPLUG_MME_MWR      0x05
#define HOMEPLUG_MME_CNK      0x06
#define HOMEPLUG_MME_RPS      0x07
#define HOMEPLUG_MME_PSR      0x08
#define HOMEPLUG_MME_SLP      0x19
#define HOMEPLUG_MME_LOADER   0x10
#define HOMEPLUG_MME_HREQ     0x12
#define HOMEPLUG_MME_HRSP     0x13
#define HOMEPLUG_MME_HTAG     0x14
#define HOMEPLUG_MME_NS       0x1A
#define HOMEPLUG_MME_RES      0x1B
#define HOMEPLUG_MME_PS       0x1C
#define HOMEPLUG_MME_SLO      0x1D
#define HOMEPLUG_MME_BC       0x1E
#define HOMEPLUG_MME_STC      0x1F
static const value_string homeplug_metype_vals[] = {
    { HOMEPLUG_MME_RCE, "Request Channel Estimation" },
    { HOMEPLUG_MME_CER, "Channel Estimation Response" },
    { HOMEPLUG_MME_VS , "Vendor Specific" },
    { HOMEPLUG_MME_RBA, "Replace Bridge Address" },
    { HOMEPLUG_MME_SNK, "Set Network Encryption Key" },
    { HOMEPLUG_MME_MWR, "Multicast With Response" },
    { HOMEPLUG_MME_CNK, "Confirm Network Encryption Key" },
    { HOMEPLUG_MME_RPS, "Request Parameters and Statistics" },
    { HOMEPLUG_MME_PSR, "Parameters and Statistics Response" },
    { HOMEPLUG_MME_SLP, "Set Local Parameters" },
    { HOMEPLUG_MME_NS , "Network Statistics" },
    { HOMEPLUG_MME_RES, "Reserved" },
    { HOMEPLUG_MME_PS , "Performance Statistics" },
    { HOMEPLUG_MME_SLO, "Set Local Overrides" },
    { HOMEPLUG_MME_BC , "Bridging Characteristics" },
    { HOMEPLUG_MME_STC, "Set Transmit Characteristics" },
    { 0, NULL }
};

/* MID Values, second field is METYPE they occur in */
#define HOMEPLUG_MID_GDD      16 /* 0x02 */
#define HOMEPLUG_MID_GCC      24 /* 0x02 */
#define HOMEPLUG_MID_GEC      25 /* 0x02 */
#define HOMEPLUG_MID_PRE      96 /* 0x02 */
#define HOMEPLUG_MID_PSI      97 /* 0x02 */

#define HOMEPLUG_MID_LGDFV     1 /* 0x10 */
#define HOMEPLUG_MID_LSF       2 /* 0x10 */
#define HOMEPLUG_MID_LWM       4 /* 0x10 */
#define HOMEPLUG_MID_LRM       9 /* 0x10 */
#define HOMEPLUG_MID_LRNVM    21 /* 0x10 */
#define HOMEPLUG_MID_LWNVM    22 /* 0x10 */
#define HOMEPLUG_MID_LRESET  127 /* 0x10 */
#define HOMEPLUG_MID_GMD     128 /* 0x10 */
#define HOMEPLUG_MID_SMD     129 /* 0x10 */
#define HOMEPLUG_MID_CM      130 /* 0x10 */
#define HOMEPLUG_MID_LEMD    132 /* 0x10 */
#define HOMEPLUG_MID_LENVMS  140 /* 0x10 */
#define HOMEPLUG_MID_GNVMP   141 /* 0x10 */
#define HOMEPLUG_MID_SNVMP   142 /* 0x10 */

#define HOMEPLUG_MID_GDV       1 /* 0x12 */
#define HOMEPLUG_MID_GFV      32 /* 0x12 */
#define HOMEPLUG_MID_GNEK     33 /* 0x12 */
#define HOMEPLUG_MID_GCLBPL   39 /* 0x12 */
#define HOMEPLUG_MID_NVDS     64 /* 0x12 */
#define HOMEPLUG_MID_GRBT     66 /* 0x12 */
#define HOMEPLUG_MID_GSLNM    68 /* 0x12 */
#define HOMEPLUG_MID_GSSS     72 /* 0x12 */
#define HOMEPLUG_MID_RSL     103 /* 0x12 */
#define HOMEPLUG_MID_RESET   127 /* 0x12 */

#define HOMEPLUG_MID_GDVR      1 /* 0x13 */
#define HOMEPLUG_MID_GFVR     32 /* 0x13 */
#define HOMEPLUG_MID_GNEKR    33 /* 0x13 */
#define HOMEPLUG_MID_INVALID 128 /* 0x13 */

#define HOMEPLUG_MID_EKT       1 /* 0x14 */



/* Bit mask Operation */
#define HOMEPLUG_MCTRL_RSVD    0x80
#define HOMEPLUG_MCTRL_NE      0x7F

#define HOMEPLUG_MEHDR_MEV     0xE0
#define HOMEPLUG_MEHDR_METYPE  0x1F

#define HOMEPLUG_VS_DIR        0x80
#define HOMEPLUG_VS_MID        0x3F

#define HOMEPLUG_NS_AC         0x80
#define HOMEPLUG_NS_ICID       0x7F
#define HOMEPLUG_NS_BUF_IN_USE 0x80
#define HOMEPLUG_NS_PRIO       0x60
#define HOMEPLUG_NS_MSDU_LEN   0x1F
#define HOMEPLUG_NS_SEQN       0xF0
#define HOMEPLUG_NS_TONEIDX    0x0F

/* string values in function of AC */
static const true_false_string homeplug_ns_ac_vals = {
  "(from host) Return basic network statistics",
  "(from host) Clear basic network statistics"
};

/* string values in function of BUF_IN_USE */
static const true_false_string homeplug_ns_buf_in_use_vals = {
  "Buffer is in use",
  "Buffer is available"
};

#define HOMEPLUG_RCE_CEV      0xF0
#define HOMEPLUG_RCE_RSVD     0x0F

#define HOMEPLUG_CER_CERV     0xF0
#define HOMEPLUG_CER_RSVD     0x0FE0
#define HOMEPLUG_CER_RXTMI    0x1F
#define HOMEPLUG_CER_RATE     0x80
#define HOMEPLUG_CER_BP       0x40
#define HOMEPLUG_CER_VT11     0x0F
#define HOMEPLUG_CER_RSVD2    0x80
#define HOMEPLUG_CER_NBDAS    0x7F

#define HOMEPLUG_BC_NETWORK   0x80
#define HOMEPLUG_BC_RETURN    0x40
#define HOMEPLUG_BCL_RSVD     0x3F
#define HOMEPLUG_BCN_RSVD     0x30
#define HOMEPLUG_BCN_FBN      0x0F

/* string values in function of BC_NETWORK */
static const true_false_string homeplug_bc_network_vals = {
  "Network bridge information",
  "Local bridge information"
};

/* string values in function of BC_RETURN */
static const true_false_string homeplug_bc_return_vals = {
  "Return bridging characteristics",
  "Set bridging characteristics"
};

#define HOMEPLUG_STC_LCO      0x80
#define HOMEPLUG_STC_ENCF     0x40
#define HOMEPLUG_STC_TXPRIO   0x30
#define HOMEPLUG_STC_REXP     0x08
#define HOMEPLUG_STC_TXCF     0x04
#define HOMEPLUG_STC_CFTOP    0x02
#define HOMEPLUG_STC_RSVD1    0x01
#define HOMEPLUG_STC_RETRY    0xC0
#define HOMEPLUG_STC_RSVD2    0x30
#define HOMEPLUG_STC_DDER     0x08
#define HOMEPLUG_STC_DUR      0x04
#define HOMEPLUG_STC_EBP      0x02
#define HOMEPLUG_STC_DEES     0x01

/* string values in function of CFTOP */
static const true_false_string homeplug_stc_cftop_vals = {
  "CA2",
  "CA3"
};

/* string values in function of RETRY */
static const value_string homeplug_stc_retry_vals[] = {
  { 0, "No retries"},
  { 1, "One retry only"},
  { 2, "Normal retries based on specification"},
  { 3, "Reserved"},
  { 0, NULL}
};

/*  Length of Network Statistics Response defines whether it is the Basic or
 *  the Extended Response */
#define HOMEPLUG_NS_BASIC_LEN 187
#define HOMEPLUG_NS_EXT_LEN   199

/* IC_ID Values */
#define HOMEPLUG_NS_ICID5130A1          0x00
#define HOMEPLUG_NS_ICID51X1USB         0x01
#define HOMEPLUG_NS_ICID51X1PHY         0x02
#define HOMEPLUG_NS_ICID51X1HOST        0x03
#define HOMEPLUG_NS_ICID5130A2          0x04
#define HOMEPLUG_NS_ICID_RSVD_MIN       0x05
#define HOMEPLUG_NS_ICID_RSVD_MAX       0x7F
/* string values in function of IC_ID values */
static const range_string homeplug_ns_icid_vals[] = {
    { HOMEPLUG_NS_ICID5130A1,    HOMEPLUG_NS_ICID5130A1,    "INT5130A1" },
    { HOMEPLUG_NS_ICID51X1USB,   HOMEPLUG_NS_ICID51X1USB,   "INT51X1 (USB Option)" },
    { HOMEPLUG_NS_ICID51X1PHY,   HOMEPLUG_NS_ICID51X1PHY,   "INT51X1 (PHY Option)" },
    { HOMEPLUG_NS_ICID51X1HOST,  HOMEPLUG_NS_ICID51X1HOST,  "INT51X1 (Host/DTE Option)" },
    { HOMEPLUG_NS_ICID5130A2,    HOMEPLUG_NS_ICID5130A2,    "INT5130A2" },
    { HOMEPLUG_NS_ICID_RSVD_MIN, HOMEPLUG_NS_ICID_RSVD_MAX, "Reserved"},
    { 0, 0, NULL }
};

/* Modulation Method Bit Mask */
#define HOMEPLUG_CER_MOD_MASK           0x30
/* Modulation Method Values */
#define HOMEPLUG_CER_MOD_ROBO           0x00
#define HOMEPLUG_CER_MOD_DBPSK          0x01
#define HOMEPLUG_CER_MOD_DQPSK          0x02
#define HOMEPLUG_CER_MOD_RSVD           0x03
/* string values in function of Modulation Method Values */
static const value_string homeplug_cer_mod_vals[] = {
  { HOMEPLUG_CER_MOD_ROBO,  "ROBO Modulation"},
  { HOMEPLUG_CER_MOD_DBPSK, "DBPSK Modulation"},
  { HOMEPLUG_CER_MOD_DQPSK, "DQPSK Modulation"},
  { HOMEPLUG_CER_MOD_RSVD,  "Reserved"},
  { 0, NULL}
};

/* Constants used by various MMEs */

#define HOMEPLUG_ADDR_INEXISTANT G_GINT64_CONSTANT(010000000000U)

/* string values in function of TXPRIO */
static const value_string homeplug_txprio_vals[] = {
  { 0, "CA0"},
  { 1, "CA1"},
  { 2, "CA2"},
  { 3, "CA3"},
  { 0, NULL}
};

#define HOMEPLUG_MCTRL_LEN 1
#define HOMEPLUG_MEHDR_LEN 1
#define HOMEPLUG_MELEN_LEN 1


/* Dissection of MCTRL */
static void dissect_homeplug_mctrl(ptvcursor_t * cursor)
{
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_mctrl, 1, ENC_NA);
  /* Extract Number Of MAC Data Entries */
  homeplug_ne = tvb_get_guint8(ptvcursor_tvbuff(cursor),
      ptvcursor_current_offset(cursor)) & HOMEPLUG_MCTRL_NE;

  ptvcursor_push_subtree(cursor, it, ett_homeplug_mctrl);
  {
    ptvcursor_add_no_advance(cursor, hf_homeplug_mctrl_reserved, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_mctrl_ne, 1, ENC_BIG_ENDIAN);
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of MEHDR */
static void dissect_homeplug_mehdr(ptvcursor_t * cursor)
{
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_mehdr, 1, ENC_NA);
  homeplug_metype = tvb_get_guint8(ptvcursor_tvbuff(cursor),
      ptvcursor_current_offset(cursor)) & HOMEPLUG_MEHDR_METYPE;

  ptvcursor_push_subtree(cursor, it, ett_homeplug_mehdr);
  {
    ptvcursor_add_no_advance(cursor, hf_homeplug_mehdr_mev, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_mehdr_metype, 1, ENC_BIG_ENDIAN);
  }
  ptvcursor_pop_subtree(cursor);
}

/* dissection of MELEN */
static void dissect_homeplug_melen(ptvcursor_t * cursor)
{
  if (!ptvcursor_tree(cursor))
    return;

  homeplug_melen = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_homeplug_melen, 1, ENC_BIG_ENDIAN);

}

/* Dissection of Request Channel Estimation MME */
static void dissect_homeplug_rce(ptvcursor_t * cursor)
{
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_rce, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_rce);
  {
    ptvcursor_add_no_advance(cursor, hf_homeplug_rce_cev, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_rce_rsvd, 1, ENC_BIG_ENDIAN);
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of Channel Estimation Response MME */
static void dissect_homeplug_cer(ptvcursor_t * cursor)
{
  proto_item * it = NULL;
  guint8 iTone = 0;
  guint8 BP = 0;
  guint8 iNBDA = 0;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_cer, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_cer);
  {
    ptvcursor_add_no_advance(cursor, hf_homeplug_cer_cerv, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_cer_rsvd1, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_cer_rxtmi, 1, ENC_BIG_ENDIAN);

    for (;iTone < 10; iTone++) {
      ptvcursor_add(cursor, hf_homeplug_cer_vt, 1, ENC_BIG_ENDIAN);
    }

    ptvcursor_add_no_advance(cursor, hf_homeplug_cer_rate, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_cer_bp, 1, ENC_BIG_ENDIAN);
    BP = tvb_get_guint8(ptvcursor_tvbuff(cursor),
        ptvcursor_current_offset(cursor)) & HOMEPLUG_CER_BP;
    ptvcursor_add_no_advance(cursor, hf_homeplug_cer_mod, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_cer_vt11, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_cer_rsvd2, 1, ENC_BIG_ENDIAN);

    if (BP) {
      iNBDA = tvb_get_guint8(ptvcursor_tvbuff(cursor),
          ptvcursor_current_offset(cursor)) & HOMEPLUG_CER_NBDAS;
      ptvcursor_add(cursor, hf_homeplug_cer_nbdas, 1, ENC_BIG_ENDIAN);
      /* TODO : Check on iNBDA! INT51X1 up to 16 dba. But up to 32 for INT51X1 (Host/DTE) */
      for (;iNBDA > 0; iNBDA--) {
        ptvcursor_add(cursor, hf_homeplug_cer_bda, 6, ENC_NA);
      }
    }
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of Vendor Specific MME */
static void dissect_homeplug_vs(ptvcursor_t * cursor)
{
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_vs, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_vs);
  {
    ptvcursor_add(cursor, hf_homeplug_vs_oui, 3, ENC_BIG_ENDIAN);

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_vs_mid, 1, ENC_BIG_ENDIAN);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_vs_mid);
    {
      ptvcursor_add_no_advance(cursor, hf_homeplug_vs_dir, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_vs_mid, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);

#if 0 /* XXX: ToDo ?? */
    switch(mid) {
    }
#endif
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of Replace Bridge Address MME */
static void dissect_homeplug_rba(ptvcursor_t * cursor)
{
  if (!ptvcursor_tree(cursor))
    return;

  ptvcursor_add_no_advance(cursor, hf_homeplug_rba, homeplug_melen, ENC_NA);
}

/* Dissection of Request Parameters and Statistics MME */
static void dissect_homeplug_rps(ptvcursor_t * cursor)
{
  if (!ptvcursor_tree(cursor))
    return;

  ptvcursor_add(cursor, hf_homeplug_rps, homeplug_melen, ENC_NA);
}

/* Dissection of Set Network Encryption Key MME */
static void dissect_homeplug_snk(ptvcursor_t * cursor)
{
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_snk, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_snk);
  {
    ptvcursor_add(cursor, hf_homeplug_snk_eks, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_snk_nek, 8, ENC_NA);
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of Multicast with Response MME */
static void dissect_homeplug_mwr(ptvcursor_t * cursor)
{
  if (!ptvcursor_tree(cursor))
    return;

  ptvcursor_add_no_advance(cursor, hf_homeplug_mwr, homeplug_melen, ENC_NA);
}

/* Dissection of Confirm Network Encryption Key MME */
static void dissect_homeplug_cnk(ptvcursor_t * cursor)
{
  if (!ptvcursor_tree(cursor))
    return;

  ptvcursor_add_no_advance(cursor, hf_homeplug_cnk, homeplug_melen, ENC_NA);
}

/* Dissection of Parameters and Statistics Response MME */
static void dissect_homeplug_psr(ptvcursor_t * cursor)
{
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_psr, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_psr);
  {
    ptvcursor_add(cursor, hf_homeplug_psr_txack, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_psr_txnack, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_psr_txfail, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_psr_txcloss, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_psr_txcoll, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_psr_txca3lat, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_psr_txca2lat, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_psr_txca1lat, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_psr_txca0lat, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_psr_rxbp40, 4, ENC_BIG_ENDIAN);
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of the Set Local Parameters MME */
static void dissect_homeplug_slp(ptvcursor_t * cursor)
{
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_slp, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_slp);
  {
    ptvcursor_add(cursor, hf_homeplug_slp_ma, 6, ENC_NA);
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of Load MME */
static void dissect_homeplug_loader(ptvcursor_t * cursor, packet_info * pinfo)
{
  int mid, length, dlen;
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_loader, -1, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_loader);
  {
    mid = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                         ptvcursor_current_offset(cursor));

    length = tvb_get_ntohs(ptvcursor_tvbuff(cursor),
                           ptvcursor_current_offset(cursor) + 1);

    switch(mid) {
    case HOMEPLUG_MID_LGDFV:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Get Firmware Version");
      ptvcursor_add(cursor, hf_homeplug_loader_gdfv, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length != 0) {
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_loader_version, -1, ENC_ASCII|ENC_NA);
      }
      break;
    case HOMEPLUG_MID_LSF:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Start Firmware");
      ptvcursor_add(cursor, hf_homeplug_loader_lsf, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_LWM:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Write Memory");
      ptvcursor_add(cursor, hf_homeplug_loader_lwm, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length == 7)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_data_address, 4, ENC_BIG_ENDIAN);

      dlen = tvb_get_ntohs(ptvcursor_tvbuff(cursor),
                           ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_loader_data_length, 2, ENC_BIG_ENDIAN);
      if (length != 7)
        ptvcursor_add(cursor, hf_homeplug_loader_data, dlen, ENC_NA);
      break;
    case HOMEPLUG_MID_LRM:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Read Memory");
      ptvcursor_add(cursor, hf_homeplug_loader_lrm, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length != 6)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_data_address, 4, ENC_BIG_ENDIAN);
      dlen = tvb_get_ntohs(ptvcursor_tvbuff(cursor),
                           ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_loader_data_length, 2, ENC_BIG_ENDIAN);
      if (length != 6)
        ptvcursor_add(cursor, hf_homeplug_loader_data, dlen, ENC_NA);
      break;
    case HOMEPLUG_MID_LRNVM:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Read NVM");
      ptvcursor_add(cursor, hf_homeplug_loader_lrnvm, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length != 7)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_data_address, 4, ENC_BIG_ENDIAN);
      dlen = tvb_get_ntohs(ptvcursor_tvbuff(cursor),
                           ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_loader_data_length, 2, ENC_BIG_ENDIAN);
      if (length != 7)
        ptvcursor_add(cursor, hf_homeplug_loader_data, dlen, ENC_NA);
      break;
    case HOMEPLUG_MID_LWNVM:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Write NVM");
      ptvcursor_add(cursor, hf_homeplug_loader_lwnvm, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length == 7)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_data_address, 4, ENC_BIG_ENDIAN);
      dlen = tvb_get_ntohs(ptvcursor_tvbuff(cursor),
                           ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_loader_data_length, 2, ENC_BIG_ENDIAN);
      if (length != 7)
        ptvcursor_add(cursor, hf_homeplug_loader_data, dlen, ENC_NA);
      break;
    case HOMEPLUG_MID_LRESET:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Reset");
      ptvcursor_add(cursor, hf_homeplug_loader_lreset, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_GMD:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Get Module Data");
      ptvcursor_add(cursor, hf_homeplug_loader_gmd, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length != 10)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_module_id, 4, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_module_offset, 4, ENC_BIG_ENDIAN);
      if (length == 10) {
        ptvcursor_add(cursor, hf_homeplug_loader_data_length, 2, ENC_BIG_ENDIAN);
      } else {
        ptvcursor_add(cursor, hf_homeplug_loader_module_size, 4, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_loader_data, length - 13, ENC_NA);
      }
      break;
    case HOMEPLUG_MID_SMD:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Set Module Data");
      ptvcursor_add(cursor, hf_homeplug_loader_smd, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length == 13)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_module_id, 4, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_module_offset, 4, ENC_BIG_ENDIAN);
      dlen = tvb_get_ntohs(ptvcursor_tvbuff(cursor),
                           ptvcursor_current_offset(cursor));
      if (length != 13) {
        ptvcursor_add(cursor, hf_homeplug_loader_data_length, 2, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_loader_data, dlen, ENC_NA);
      } else
        ptvcursor_add(cursor, hf_homeplug_loader_module_size, 4, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_CM:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Commit Module");
      ptvcursor_add(cursor, hf_homeplug_loader_cm, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length == 5)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_module_id, 4, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_LEMD:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Erase Module Data");
      ptvcursor_add(cursor, hf_homeplug_loader_lemd, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length == 9)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_module_id, 4, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_LENVMS:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Erase NVM Sectors");
      ptvcursor_add(cursor, hf_homeplug_loader_lenvms, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length == 9)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_data_address, 4, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_module_size, 4, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_GNVMP:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Get NVM Parametes");
      ptvcursor_add(cursor, hf_homeplug_loader_gnvmp, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length == 17) {
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_loader_nvmp_type, 4, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_loader_nvmp_pagesize, 4, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_loader_nvmp_blocksize, 4, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_loader_nvmp_memorysize, 4, ENC_BIG_ENDIAN);
      }
      break;
    case HOMEPLUG_MID_SNVMP:
      col_set_str(pinfo->cinfo, COL_INFO, "Loader Set NVM Parametes");
      ptvcursor_add(cursor, hf_homeplug_loader_snvmp, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_length, 2, ENC_BIG_ENDIAN);
      if (length == 17)
        ptvcursor_add(cursor, hf_homeplug_loader_status, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_nvmp_type, 4, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_nvmp_pagesize, 4, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_nvmp_blocksize, 4, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_loader_nvmp_memorysize, 4, ENC_BIG_ENDIAN);
      break;
    default:
      ptvcursor_add(cursor, hf_homeplug_loader_mid, 1, ENC_BIG_ENDIAN);
      break;
    }
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of Host Request MME */
static void dissect_homeplug_hreq(ptvcursor_t * cursor, packet_info * pinfo)
{
  int mid, length;
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_hreq, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_hreq);
  {
    mid = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                         ptvcursor_current_offset(cursor));
    length = tvb_get_ntohs(ptvcursor_tvbuff(cursor),
                           ptvcursor_current_offset(cursor) + 1);

    switch(mid) {
    case HOMEPLUG_MID_GDV:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: Get Device Version");
      ptvcursor_add(cursor, hf_homeplug_hreq_gdv, 1, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_GFV:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: Get Firmware Version");
      ptvcursor_add(cursor, hf_homeplug_hreq_gfv, 1, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_GNEK:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: Get Network Encryption Key Request");
      ptvcursor_add(cursor, hf_homeplug_hreq_gnek, 1, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_GCLBPL:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: Get/ Clear Local Bridge Proxy List");
      ptvcursor_add(cursor, hf_homeplug_hreq_gclbpl, 1, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_NVDS:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: Non-volatile Database Status");
      ptvcursor_add(cursor, hf_homeplug_hreq_nvds, 1, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_GRBT:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: Get Remote Bridge Table");
      ptvcursor_add(cursor, hf_homeplug_hreq_grbt, 1, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_GSLNM:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: Get/Set Logical Network Mappings");
      ptvcursor_add(cursor, hf_homeplug_hreq_gslnm, 1, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_GSSS:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: Get/Set Spectral Scaling");
      ptvcursor_add(cursor, hf_homeplug_hreq_gsss, 1, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_RSL:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: MAC Reset to Secondary Loader");
      ptvcursor_add(cursor, hf_homeplug_hreq_rsl, 1, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_RESET:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request: MAC Reset");
      ptvcursor_add(cursor, hf_homeplug_hreq_reset, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_hreq_reset_type, 1, ENC_BIG_ENDIAN);
      if (length == 4)
        ptvcursor_add(cursor, hf_homeplug_hreq_reset_delay, 2, ENC_BIG_ENDIAN);
      break;
    default:
      ptvcursor_add(cursor, hf_homeplug_hreq_mid, 1, ENC_BIG_ENDIAN);
      break;
    }
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of Host Response MME */
static void dissect_homeplug_hrsp(ptvcursor_t * cursor, packet_info * pinfo)
{
  int mid;
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_hrsp, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_hrsp);
  {
    mid = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                         ptvcursor_current_offset(cursor));
    switch(mid) {
    case HOMEPLUG_MID_GDVR:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Response: Get Device Version");
      ptvcursor_add(cursor, hf_homeplug_hrsp_gdvr, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_hrsp_version, -1, ENC_ASCII|ENC_NA);
      break;
    case HOMEPLUG_MID_GFVR:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Response: Get Firmware Version");
      ptvcursor_add(cursor, hf_homeplug_hrsp_gfvr, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_hrsp_version, -1, ENC_ASCII|ENC_NA);
      break;
    case HOMEPLUG_MID_GNEKR:
      col_set_str(pinfo->cinfo, COL_INFO, "Get Network Encryption Key");
      ptvcursor_add(cursor, hf_homeplug_hrsp_gnekr, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_hrsp_gnekr_select, 1, ENC_BIG_ENDIAN);
      ptvcursor_add(cursor, hf_homeplug_hrsp_gnekr_key, 8, ENC_BIG_ENDIAN);
      break;
    case HOMEPLUG_MID_INVALID:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Response: Invalid MME");
      ptvcursor_add(cursor, hf_homeplug_hrsp_invalid, 1, ENC_BIG_ENDIAN);
      break;
    default:
      ptvcursor_add(cursor, hf_homeplug_hrsp_mid, 1, ENC_BIG_ENDIAN);
      break;
    }
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of Host Tag MME */
static void dissect_homeplug_htag(ptvcursor_t * cursor)
{
  if (!ptvcursor_tree(cursor))
    return;

  ptvcursor_add_no_advance(cursor, hf_homeplug_htag, homeplug_melen, ENC_NA);
}

/* Dissection of the Network Statistics MME */
static void dissect_homeplug_ns(ptvcursor_t * cursor, packet_info * pinfo)
{
  guint8 iTone = 0;
  guint8 i_buffer = 0;

  guint16 ns_bytes40 = 0;
  guint64 newt_da = 0;
  gboolean extended = (homeplug_melen >= HOMEPLUG_NS_EXT_LEN);
  proto_item * ti;

  /* Append Basic/Extender specifier to info column */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, extended ? " Extended" : " Basic");

  if (!ptvcursor_tree(cursor))
    return;

  ptvcursor_add_with_subtree(cursor, hf_homeplug_ns, homeplug_melen, ENC_BIG_ENDIAN,
      ett_homeplug_ns);
  {
    ti = proto_tree_add_boolean(ptvcursor_tree(cursor), hf_homeplug_ns_extended,
             ptvcursor_tvbuff(cursor), 0, 0, extended);
    PROTO_ITEM_SET_GENERATED(ti);

    ptvcursor_add_no_advance(cursor, hf_homeplug_ns_netw_ctrl_ac, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_ns_netw_ctrl_icid, 1, ENC_BIG_ENDIAN);

    ptvcursor_add_no_advance(cursor, hf_homeplug_ns_bytes40_robo, 2, ENC_LITTLE_ENDIAN);
    ns_bytes40 = tvb_get_letohs(ptvcursor_tvbuff(cursor),
        ptvcursor_current_offset(cursor));
    proto_tree_add_text(ptvcursor_tree(cursor), ptvcursor_tvbuff(cursor),
        ptvcursor_current_offset(cursor), 2, "MHz :  %.3f", (float)(ns_bytes40)/42);
    ptvcursor_advance(cursor, 2);

    ptvcursor_add(cursor, hf_homeplug_ns_fails_robo, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_ns_drops_robo, 2, ENC_LITTLE_ENDIAN);

    while (iTone < 15) {
      newt_da = ((gint64)tvb_get_ntoh24(ptvcursor_tvbuff(cursor),
      ptvcursor_current_offset(cursor))) << 24;
      newt_da |= tvb_get_ntoh24(ptvcursor_tvbuff(cursor),
      ptvcursor_current_offset(cursor)+3);

      if (newt_da != HOMEPLUG_ADDR_INEXISTANT) {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
            ett_homeplug_tone, "Tone Map #%d", iTone+1);
        {
          ptvcursor_add(cursor, hf_homeplug_ns_netw_da, 6, ENC_NA);

          ptvcursor_add_no_advance(cursor, hf_homeplug_ns_bytes40, 2, ENC_LITTLE_ENDIAN);
          ns_bytes40 = tvb_get_letohs(ptvcursor_tvbuff(cursor),
                                      ptvcursor_current_offset(cursor));
          proto_tree_add_text(ptvcursor_tree(cursor), ptvcursor_tvbuff(cursor),
                              ptvcursor_current_offset(cursor), 2, "MHz :  %.3f", (float)(ns_bytes40)/42);
          ptvcursor_advance(cursor, 2);

          ptvcursor_add(cursor, hf_homeplug_ns_fails, 2, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_homeplug_ns_drops, 2, ENC_LITTLE_ENDIAN);
        }
        ptvcursor_pop_subtree(cursor);
      } else {
        proto_tree_add_text(ptvcursor_tree(cursor), ptvcursor_tvbuff(cursor),
            ptvcursor_current_offset(cursor), 12, "Tone Map #%d does not exist", iTone+1);
      }

      iTone++;
    }
    if (extended) {
      while (i_buffer < 6) {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
            ett_homeplug_tx_bfr_state, "TX_BFR_%d_STATE", i_buffer);
        {
          ptvcursor_add_no_advance(cursor, hf_homeplug_ns_buf_in_use, 1, ENC_BIG_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_homeplug_ns_prio, 1, ENC_BIG_ENDIAN);
          ptvcursor_add(cursor, hf_homeplug_ns_msdu_len, 1, ENC_BIG_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_homeplug_ns_seqn, 1, ENC_BIG_ENDIAN);
          ptvcursor_add(cursor, hf_homeplug_ns_toneidx, 1, ENC_BIG_ENDIAN);
        }
        ptvcursor_pop_subtree(cursor);
        i_buffer++;
      }
    }
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of the Bridging Characteristics Network MME */
static void dissect_homeplug_bcn(ptvcursor_t * cursor)
{
  proto_item * it = NULL;
  guint8 i_bridge = 0;
  guint8 num_das;
  guint8 i_da;
  guint8 fbn;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_bcn, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_bcn);
  {
    ptvcursor_add_no_advance(cursor, hf_homeplug_bcn_network, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_bcn_return, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_bcn_rsvd, 1, ENC_BIG_ENDIAN);
    fbn = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor))
        & HOMEPLUG_BCN_FBN;
    ptvcursor_add(cursor, hf_homeplug_bcn_fbn, 1, ENC_BIG_ENDIAN);
    while (i_bridge < 2) {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
          ett_homeplug_bridge, "Bridge #%d", fbn + i_bridge);
      {
        ptvcursor_add(cursor, hf_homeplug_bcn_brda, 6, ENC_NA);
        num_das = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_bcn_bp_das, 1, ENC_BIG_ENDIAN);
        for (i_da = 0; i_da < num_das; i_da++) {
          ptvcursor_add(cursor, hf_homeplug_bcn_bp_da, 6, ENC_NA);
        }
      }
      ptvcursor_pop_subtree(cursor);
      i_bridge++;
    }
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of the Bridging Characteristics Local MME */
static void dissect_homeplug_bcl(ptvcursor_t * cursor)
{
  proto_item * it = NULL;
  guint8 num_das;
  guint8 i_da = 0;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_bcl, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_bcl);
  {
    ptvcursor_add_no_advance(cursor, hf_homeplug_bcl_network, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_bcl_return, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_bcl_rsvd, 1, ENC_BIG_ENDIAN);

    num_das = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_bcl_hprox_das, 1, ENC_BIG_ENDIAN);

    while (i_da < num_das) {
      ptvcursor_add(cursor, hf_homeplug_bcl_hpbda, 6, ENC_NA);
      i_da++;
    }
  }
  ptvcursor_pop_subtree(cursor);
}

/* Dissection of the Bridging Characteristics MME */
static void dissect_homeplug_bc(ptvcursor_t * cursor, packet_info * pinfo)
{
  gboolean network;

  if (!ptvcursor_tree(cursor))
    return;

  network = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor))
          & HOMEPLUG_BC_NETWORK;

  /* Append Network/Local specifier to info column */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, network ? " Network" : " Local");

  /* Call specific dissector */
  if (network)
    dissect_homeplug_bcn(cursor);
  else
    dissect_homeplug_bcl(cursor);
}

/* Dissection of the Set Transmit Characteristics MME */
static void dissect_homeplug_stc(ptvcursor_t * cursor)
{
  proto_item * it = NULL;

  if (!ptvcursor_tree(cursor))
    return;

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_stc, homeplug_melen, ENC_NA);

  ptvcursor_push_subtree(cursor, it, ett_homeplug_stc);
  {
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_lco, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_encf, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_txprio, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_rexp, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_txcf, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_cftop, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_stc_rsvd1, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_retry, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_rsvd2, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_dder, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_dur, 1, ENC_BIG_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_homeplug_stc_ebp, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_stc_dees, 1, ENC_BIG_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_stc_txeks, 1, ENC_BIG_ENDIAN);
  }
  ptvcursor_pop_subtree(cursor);

  return;
}

/* Dissection of unknown tags */
static void dissect_homeplug_unknown(ptvcursor_t * cursor)
{
  ptvcursor_add(cursor, hf_homeplug_data, homeplug_melen, ENC_NA);
}

static void dissect_homeplug_mme(ptvcursor_t * cursor, packet_info * pinfo)
{
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
        val_to_str(homeplug_metype, homeplug_metype_vals, "Unknown 0x%x"));
  }

  switch(homeplug_metype) {
    case HOMEPLUG_MME_RCE:
      dissect_homeplug_rce(cursor);
      break;
    case HOMEPLUG_MME_CER:
      dissect_homeplug_cer(cursor);
      break;
    case HOMEPLUG_MME_VS:
      col_set_str(pinfo->cinfo, COL_INFO, "Vendor Specific");
      dissect_homeplug_vs(cursor);
      break;
    case HOMEPLUG_MME_RBA:
      col_set_str(pinfo->cinfo, COL_INFO, "Replace Bridge Address");
      dissect_homeplug_rba(cursor);
      break;
    case HOMEPLUG_MME_SNK:
      col_set_str(pinfo->cinfo, COL_INFO, "Set Network Encryption Key");
      dissect_homeplug_snk(cursor);
      break;
    case HOMEPLUG_MME_MWR:
      col_set_str(pinfo->cinfo, COL_INFO, "Multicast With Response");
      dissect_homeplug_mwr(cursor);
      break;
    case HOMEPLUG_MME_CNK:
      col_set_str(pinfo->cinfo, COL_INFO, "Confirm Network Encryption Key");
      dissect_homeplug_cnk(cursor);
      break;
    case HOMEPLUG_MME_RPS:
      dissect_homeplug_rps(cursor);
      break;
    case HOMEPLUG_MME_PSR:
      dissect_homeplug_psr(cursor);
      break;
    case HOMEPLUG_MME_SLP:
      dissect_homeplug_slp(cursor);
      break;
    case HOMEPLUG_MME_LOADER:
      col_set_str(pinfo->cinfo, COL_INFO, "Load Firmware");
      dissect_homeplug_loader(cursor, pinfo);
      break;
    case HOMEPLUG_MME_HREQ:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Request");
      dissect_homeplug_hreq(cursor, pinfo);
      break;
    case HOMEPLUG_MME_HRSP:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Response");
      dissect_homeplug_hrsp(cursor, pinfo);
      break;
    case HOMEPLUG_MME_HTAG:
      col_set_str(pinfo->cinfo, COL_INFO, "Host Tag");
      dissect_homeplug_htag(cursor);
      break;
    case HOMEPLUG_MME_NS:
      dissect_homeplug_ns(cursor, pinfo);
      break;
    case HOMEPLUG_MME_BC:
      dissect_homeplug_bc(cursor, pinfo);
      break;
    case HOMEPLUG_MME_STC:
      dissect_homeplug_stc(cursor);
      break;
    default:
      dissect_homeplug_unknown(cursor);
      break;
  }
}

#define TVB_LEN_GREATEST  1
#define TVB_LEN_UNDEF     0
#define TVB_LEN_SHORTEST -1
static int check_tvb_length(ptvcursor_t *cursor, const gint length)
{
  if (!cursor)
    return TVB_LEN_UNDEF;

  if (tvb_reported_length_remaining(ptvcursor_tvbuff(cursor),
                                    ptvcursor_current_offset(cursor)) < length)
    return TVB_LEN_SHORTEST;

  return TVB_LEN_GREATEST;
}

static void
dissect_homeplug(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item * it= NULL;
  proto_tree * homeplug_tree= NULL;
  ptvcursor_t * cursor= NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HomePlug");
  /* Clear out stuff in the info column */
  col_set_str(pinfo->cinfo, COL_INFO, "MAC Management");

  homeplug_offset = 0;

  if (tree) {
    it = proto_tree_add_item(tree, proto_homeplug, tvb, homeplug_offset, -1, ENC_NA);
    homeplug_tree = proto_item_add_subtree(it, ett_homeplug);
    cursor = ptvcursor_new(homeplug_tree, tvb, 0);
  }

  /*  We do not have enough data to read mctrl field stop the dissection */
  if (check_tvb_length(cursor, HOMEPLUG_MCTRL_LEN) != TVB_LEN_SHORTEST) {

    dissect_homeplug_mctrl(cursor);

    /** homeplug_ne indicates the number of MME entries. This field is fetched
     *  from MCTRL.
     */
    if ((homeplug_ne > 0)) {
      col_clear(pinfo->cinfo, COL_INFO);
    }
    for (; homeplug_ne > 0; homeplug_ne--) {

      /* Check we have enough data in tvb to read MEHDR */
      if (check_tvb_length(cursor, HOMEPLUG_MEHDR_LEN) == TVB_LEN_SHORTEST)
        break;
      dissect_homeplug_mehdr(cursor);

      /* Check we have enough data in tvb to read MELEN */
      if (check_tvb_length(cursor, HOMEPLUG_MELEN_LEN) == TVB_LEN_SHORTEST)
        break;
      dissect_homeplug_melen(cursor);

      dissect_homeplug_mme(cursor, pinfo);
    }
  }

  if (cursor)
    ptvcursor_free(cursor);
}


void
proto_reg_handoff_homeplug(void)
{
  dissector_handle_t homeplug_handle;

  homeplug_handle = create_dissector_handle(dissect_homeplug, proto_homeplug);
  dissector_add_uint("ethertype", ETHERTYPE_HOMEPLUG, homeplug_handle);
}

void
proto_register_homeplug(void)
{

  static hf_register_info hf[] = {
    /* MAC Control Field */
    { &hf_homeplug_mctrl,
      { "MAC Control Field", "homeplug.mctrl",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_mctrl_reserved,
      { "Reserved", "homeplug.mctrl.rsvd",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_MCTRL_RSVD, NULL, HFILL }
    },

    { &hf_homeplug_mctrl_ne,
      { "Number of MAC Data Entries", "homeplug.mctrl.ne",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_MCTRL_NE, NULL, HFILL }
    },

    /* MAC Entry Header */
    { &hf_homeplug_mehdr,
      { "MAC Management Entry Header", "homeplug.mehdr",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_mehdr_mev,
      { "MAC Entry Version", "homeplug.mehdr.mev",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_MEHDR_MEV, NULL, HFILL }
    },

    { &hf_homeplug_mehdr_metype,
      { "MAC Entry Type", "homeplug.mehdr.metype",
      FT_UINT8, BASE_HEX, VALS(homeplug_metype_vals), HOMEPLUG_MEHDR_METYPE, NULL, HFILL }
    },

    /* MAC Entry Len */
    { &hf_homeplug_melen,
      { "MAC Management Entry Length", "homeplug.melen",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /* MAC Management Entry */
    { &hf_homeplug_mme,
      { "MAC Management Entry Data", "homeplug.mmentry",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /* Request Channel Estimation */
    { &hf_homeplug_rce,
      { "Request Channel Estimation", "homeplug.rce",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_rce_cev,
      { "Channel Estimation Version", "homeplug.rce.cev",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_RCE_CEV, NULL, HFILL }
    },

    { &hf_homeplug_rce_rsvd,
      { "Reserved", "homeplug.rce.rsvd",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_RCE_RSVD, NULL, HFILL }
    },

    /* Channel Estimation Response */
    { &hf_homeplug_cer,
      { "Channel Estimation Response", "homeplug.cer",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_cer_cerv,
      { "Channel Estimation Response Version", "homeplug.cer.cerv",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_CERV, NULL, HFILL }
    },

    { &hf_homeplug_cer_rsvd1,
      { "Reserved", "homeplug.cer.rsvd1",
      FT_UINT16, BASE_DEC, NULL, HOMEPLUG_CER_RSVD, NULL, HFILL }
    },

    { &hf_homeplug_cer_rxtmi,
      { "Receive Tone Map Index", "homeplug.cer.rxtmi",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_RXTMI, NULL, HFILL }
    },

    /* TODO must append vt[79-0] */

    { &hf_homeplug_cer_vt,
      {"Valid Tone Flags", "homeplug.cer.vt",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_cer_rate,
      { "FEC Rate", "homeplug.cer.rate",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_RATE, NULL, HFILL }
    },

    { &hf_homeplug_cer_bp,
      { "Bridge Proxy", "homeplug.cer.bp",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_BP, NULL, HFILL }
    },

    { &hf_homeplug_cer_mod,
      { "Modulation Method", "homeplug.cer.mod",
      FT_UINT8, BASE_DEC, VALS(homeplug_cer_mod_vals), HOMEPLUG_CER_MOD_MASK,
      NULL, HFILL }
    },

    { &hf_homeplug_cer_vt11,
      { "Valid Tone Flags [83-80]", "homeplug.cer.vt11",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_VT11, NULL, HFILL }
    },

    { &hf_homeplug_cer_rsvd2,
      { "Reserved", "homeplug.cer.rsvd2",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_RSVD2, NULL, HFILL }
    },

    { &hf_homeplug_cer_nbdas,
      { "Number Bridged Destination Addresses", "homeplug.cer.nbdas",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_NBDAS, NULL, HFILL }
    },

    { &hf_homeplug_cer_bda,
      { "Bridged Destination Address", "homeplug.cer.bda",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    /* Replace Bridge Address */
    { &hf_homeplug_rba,
      { "Replace Bridge Address", "homeplug.rba",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    /* Vendor Specific */
    { &hf_homeplug_vs,
      { "Vendor Specific", "homeplug.vs",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_vs_dir,
      { "Direction", "homeplug.vs.dir",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_VS_DIR, NULL, HFILL }
    },

    { &hf_homeplug_vs_mid,
      { "Message ID", "homeplug.vs.mid",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_VS_MID, NULL, HFILL }
    },

    { &hf_homeplug_vs_oui,
      { "OUI", "homeplug.vs.oui",
      FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },

    /* Set Network Encryption Key */
    { &hf_homeplug_snk,
      { "Set Network Encryption Key", "homeplug.snk",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_snk_eks,
      { "Encryption Key Select", "homeplug.snk.eks",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_snk_nek,
      { "Network Encryption Key", "homeplug.snk.nek",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

  /* Multicast With Response */
    { &hf_homeplug_mwr,
      { "Multicast With Response", "homeplug.mwr",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    /* Confirm Network Encryption Key */
    { &hf_homeplug_cnk,
      { "Confirm Network Encryption Key", "homeplug.cnk",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    /* Host Tag */
    { &hf_homeplug_htag,
      { "Host Tag", "homeplug.htag",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    /* Request Parameters and Statistics */
    { &hf_homeplug_rps,
      { "Request Parameters and Statistics", "homeplug.rps",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    /* Parameters and Statistics Response */
    { &hf_homeplug_psr,
      { "Parameters and Statistics Response", "homeplug.psr",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_psr_txack,
      { "Transmit ACK Counter", "homeplug.psr.txack",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_psr_txnack,
      { "Transmit NACK Counter", "homeplug.psr.txnack",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_psr_txfail,
      { "Transmit FAIL Counter", "homeplug.psr.txfail",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_psr_txcloss,
      { "Transmit Contention Loss Counter", "homeplug.psr.txcloss",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_psr_txcoll,
      { "Transmit Collision Counter", "homeplug.psr.txcoll",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_psr_txca3lat,
      { "Transmit CA3 Latency Counter", "homeplug.psr.txca3lat",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_psr_txca2lat,
      { "Transmit CA2 Latency Counter", "homeplug.psr.txca2lat",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_homeplug_psr_txca1lat,
      { "Transmit CA1 Latency Counter", "homeplug.psr.txca1lat",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_homeplug_psr_txca0lat,
      { "Transmit CA0 Latency Counter", "homeplug.psr.txca0lat",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_psr_rxbp40,
      { "Receive Cumulative Bytes per 40-symbol", "homeplug.psr.rxbp40",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /* Set Local Parameters */
    { &hf_homeplug_slp,
      { "Set Local Parameters", "homeplug.slp",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_slp_ma,
      { "MAC Address", "homeplug.slp.ma",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    /* LOAD */
    { &hf_homeplug_loader,
      { "Loader", "homeplug.leader",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_mid,
      { "Message ID", "homeplug.loader.mid",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_length,
      { "Length", "homeplug.loader.length",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_status,
      { "Status", "homeplug.loader.status",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_version,
      { "Version", "homeplug.loader.version",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_gdfv,
      { "Get Device/Firmware Version", "homeplug.loader.gdfv",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_lsf,
      { "Start Firmware", "homeplug.loader.lsf",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_lwm,
      { "Write Memory", "homeplug.loader.lwm",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_lrm,
      { "Read Memory", "homeplug.loader.lrm",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_lrnvm,
      { "Read NVM Data", "homeplug.loader.lrnvm",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_lwnvm,
      { "Write NVM Data", "homeplug.loader.lwnvm",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_lreset,
      { "Reset", "homeplug.loader.lreset",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_gmd,
      { "Get Module Data", "homeplug.loader.gmd",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_smd,
      { "Set Module Data", "homeplug.loader.smd",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_module_id,
      { "Module ID", "homeplug.loader.module.id",
      FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_module_offset,
      { "Offset", "homeplug.loader.module.offset",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_module_size,
      { "Module size", "homeplug.loader.module.size",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_data_length,
      { "Data length", "homeplug.loader.data.length",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_data_address,
      { "Address", "homeplug.loader.data.address",
      FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_data,
      { "Data", "homeplug.loader.data",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_cm,
      { "Commit Modules", "homeplug.loader.cm",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_lemd,
      { "Erase Module Data", "homeplug.loader.emd",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_lenvms,
      { "Erase NVM Sectors", "homeplug.loader.lenvms",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_gnvmp,
      { "Get NVM Parameters", "homeplug.loader.gnvmp",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_nvmp_type,
      { "Type", "homeplug.loader.nvmp.type",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_nvmp_pagesize,
      { "Page Size", "homeplug.loader.nvmp.pagesize",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_nvmp_blocksize,
      { "Block Size", "homeplug.loader.nvmp.blocksize",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_nvmp_memorysize,
      { "Memory Size", "homeplug.loader.nvmp.memorysize",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_loader_snvmp,
      { "Set NVM Parameters", "homeplug.loader.snvmp",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /* Host Request */
    { &hf_homeplug_hreq,
      { "Host Request", "homeplug.hreq",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_mid,
      { "Message ID", "homeplug.hreq.mid",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_gdv,
      { "Get Device Version", "homeplug.hreq.gdv",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_gfv,
      { "Get Firmware Version", "homeplug.hreq.gfv",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_gnek,
      { "Get Network Encryption Key", "homeplug.hreq.gnek",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_gclbpl,
      { "Get/Clear Local Bridge Proxy List", "homeplug.hreq.gclbpl",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_nvds,
      { "Non-volatile Database Status", "homeplug.hreq.nvds",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_grbt,
      { "Get Remote Bridge Table", "homeplug.hreq.grbt",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_gslnm,
      { "Get/Set Logical Network Mapping", "homeplug.hreq.gslnm",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_gsss,
      { "Get/Set Spectral Scaling", "homeplug.hreq.gsss",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_rsl,
      { "Reset Secondary Loader", "homeplug.hreq.rsl",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_reset,
      { "Reset", "homeplug.hreq.reset",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_reset_type,
      { "Type", "homeplug.hreq.reset.type",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hreq_reset_delay,
      { "Delay", "homeplug.hreq.reset.delay",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /* Host Response */
    { &hf_homeplug_hrsp,
      { "Host Response", "homeplug.hrsp",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hrsp_mid,
      { "Message ID", "homeplug.hrsp.mid",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hrsp_gdvr,
      { "Get Device Version", "homeplug.hrsp.gdvr",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hrsp_gfvr,
      { "Get Firmware Version", "homeplug.hrsp.gfvr",
      FT_UINT8, BASE_DEC, NULL, 0x0, "Get Firmwave Version", HFILL }
    },

    { &hf_homeplug_hrsp_gnekr,
      { "Get Network Encryption Key", "homeplug.hrsp.gnekr",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hrsp_gnekr_select,
      { "Key Select", "homeplug.hrsp.gnekr.select",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hrsp_gnekr_key,
      { "Key", "homeplug.hrsp.gnekr.key",
      FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hrsp_invalid,
      { "Invalid", "homeplug.hrsp.invalid",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_hrsp_version,
      { "Version", "homeplug.hrsp.version",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    /* Network Statistics */
    { &hf_homeplug_ns,
      { "Network Statistics", "homeplug.ns",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_ns_extended,
      { "Network Statistics is Extended", "homeplug.ns.extended",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Network Statistics is Extended (MELEN >= 199)", HFILL }
    },

    { &hf_homeplug_ns_netw_ctrl_ac,
      { "Action Control", "homeplug.ns.ac",
      FT_BOOLEAN, 8, TFS(&homeplug_ns_ac_vals), HOMEPLUG_NS_AC, NULL, HFILL }
    },

    { &hf_homeplug_ns_netw_ctrl_icid,
      { "IC_ID", "homeplug.ns.icid",
      FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(homeplug_ns_icid_vals), HOMEPLUG_NS_ICID, NULL, HFILL }
    },

    { &hf_homeplug_ns_bytes40_robo,
      { "Bytes in 40 symbols in ROBO", "homeplug.ns.bytes40_robo",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_ns_fails_robo,
      { "Fails Received in ROBO", "homeplug.ns.fails_robo",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_ns_drops_robo,
      { "Frame Drops in ROBO", "homeplug.ns.drops_robo",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_ns_netw_da,
      { "Address of Network DA", "homeplug.ns.netw_da",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_ns_bytes40,
      { "Bytes in 40 symbols", "homeplug.ns.bytes40",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_ns_fails,
      { "Fails Received", "homeplug.ns.fails",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_ns_drops,
      { "Frame Drops", "homeplug.ns.drops",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /* ... Extended */
    { &hf_homeplug_ns_tx_bfr_state,
      { "Transmit Buffer State", "homeplug.ns.tx_bfr_state",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_ns_buf_in_use,
      { "Buffer in use", "homeplug.ns.buf_in_use",
      FT_BOOLEAN, 8, TFS(&homeplug_ns_buf_in_use_vals), HOMEPLUG_NS_BUF_IN_USE,
      "Buffer in use (1) or Available (0)", HFILL }
    },

    { &hf_homeplug_ns_prio,
      { "Priority", "homeplug.ns.prio",
      FT_UINT8, BASE_DEC, VALS(homeplug_txprio_vals), HOMEPLUG_NS_PRIO,
      NULL, HFILL }
    },

    { &hf_homeplug_ns_msdu_len,
      { "MSDU Length", "homeplug.ns.msdu_len",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_NS_MSDU_LEN, NULL, HFILL }
    },

    { &hf_homeplug_ns_seqn,
      { "Sequence Number", "homeplug.ns.seqn",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_NS_SEQN, NULL, HFILL }
    },

    { &hf_homeplug_ns_toneidx,
      { "Transmit tone map index", "homeplug.ns.toneidx",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_NS_TONEIDX,
      "Maps to the 16 statistics occurring earlier in this MME", HFILL }
    },

    /* Bridging Characteristics Network */
    { &hf_homeplug_bcn,
      { "Bridging Characteristics Network", "homeplug.bcn",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_bcn_network,
      { "Network", "homeplug.bcn.network",
      FT_BOOLEAN, 8, TFS(&homeplug_bc_network_vals), HOMEPLUG_BC_NETWORK,
      "Local (0) or Network Bridge (1) Information", HFILL }
    },

    { &hf_homeplug_bcn_return,
      { "Return/Set", "homeplug.bcn.return",
      FT_BOOLEAN, 8, TFS(&homeplug_bc_return_vals), HOMEPLUG_BC_RETURN,
      "From host: Return (1) or set bridging characteristics (0)", HFILL }
    },

    { &hf_homeplug_bcn_rsvd,
      { "Reserved", "homeplug.bcn.rsvd",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_BCN_RSVD, NULL, HFILL }
    },

    { &hf_homeplug_bcn_fbn,
      { "First Bridge Number", "homeplug.bcn.fbn",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_BCN_FBN, NULL, HFILL }
    },

    { &hf_homeplug_bcn_brda,
      { "Address of Bridge", "homeplug.bcn.brda",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_bcn_bp_das,
      { "Number of bridge proxied DAs", "homeplug.bcn.bp_das",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Number of bridge proxied DAs supported", HFILL }
    },

    { &hf_homeplug_bcn_bp_da,
      { "Bridged DA", "homeplug.bcn.bp_da",
      FT_ETHER, BASE_NONE, NULL, 0x0, "Bridged Destination Address", HFILL }
    },

    /* Bridging Characteristics Local */
    { &hf_homeplug_bcl,
      { "Bridging Characteristics Local", "homeplug.bcl",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_bcl_network,
      { "Network/Local", "homeplug.bcl.network",
      FT_BOOLEAN, 8, TFS(&homeplug_bc_network_vals), HOMEPLUG_BC_NETWORK,
      "Local (0) or Network Bridge (1) Information", HFILL }
    },

    { &hf_homeplug_bcl_return,
      { "Return/Set", "homeplug.bcl.return",
      FT_BOOLEAN, 8, TFS(&homeplug_bc_return_vals), HOMEPLUG_BC_RETURN,
      "From host: Return (1) or set bridging characteristics (0)", HFILL }
    },

    { &hf_homeplug_bcl_rsvd,
      { "Reserved", "homeplug.bcl.rsvd",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_BCL_RSVD, NULL, HFILL }
    },

    { &hf_homeplug_bcl_hprox_das,
      { "Number of host proxied DAs", "homeplug.bcl.hprox_das",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Number of host proxied DAs supported by the bridge application", HFILL }
    },

    { &hf_homeplug_bcl_hpbda,
      { "Host Proxied DA", "homeplug.bcl.hpbda",
      FT_ETHER, BASE_NONE, NULL, 0x0, "Host Proxied Bridged Destination Address", HFILL }
    },

    /* Set Transmit Characteristics */
    { &hf_homeplug_stc,
      { "Set Transmit Characteristics", "homeplug.stc",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_homeplug_stc_lco,
      { "Local Consumption Only", "homeplug.stc.lco",
      FT_BOOLEAN, 8, NULL, HOMEPLUG_STC_LCO,
      "Do not transmit subsequent frames to medium", HFILL }
    },

    { &hf_homeplug_stc_encf,
      { "Encryption Flag", "homeplug.stc.encf",
      FT_BOOLEAN, 8, NULL, HOMEPLUG_STC_ENCF, "Encrypt subsequent frames", HFILL }
    },

    { &hf_homeplug_stc_txprio,
      { "Transmit Priority", "homeplug.stc.txprio",
      FT_UINT8, BASE_DEC, VALS(homeplug_txprio_vals), HOMEPLUG_STC_TXPRIO,
      NULL, HFILL }
    },

    { &hf_homeplug_stc_rexp,
      { "Response Expected", "homeplug.stc.rexp",
      FT_BOOLEAN, 8, NULL, HOMEPLUG_STC_REXP,
      "Mark subsequent frames to receive response", HFILL }
    },

    { &hf_homeplug_stc_txcf,
      { "Transmit Contention Free", "homeplug.stc.txcf",
      FT_BOOLEAN, 8, NULL, HOMEPLUG_STC_TXCF,
      "Mark subsequently transmitted frames as contention free", HFILL }
    },

    { &hf_homeplug_stc_cftop,
      { "Contention Free Transmit Override Priority", "homeplug.stc.cftop",
      FT_BOOLEAN, 8, TFS(&homeplug_stc_cftop_vals), HOMEPLUG_STC_CFTOP,
      "Transmit subsequent contention free frames with CA2/CA3 priority", HFILL }
    },

    { &hf_homeplug_stc_rsvd1,
      { "Reserved", "homeplug.stc.rsvd1",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_STC_RSVD1, NULL, HFILL }
    },

    { &hf_homeplug_stc_retry,
      { "Retry Control", "homeplug.stc.retry",
      FT_UINT8, BASE_DEC, VALS(homeplug_stc_retry_vals), HOMEPLUG_STC_RETRY,
      NULL, HFILL }
    },

    { &hf_homeplug_stc_rsvd2,
      { "Reserved", "homeplug.stc.rsvd2",
      FT_UINT8, BASE_DEC, NULL, HOMEPLUG_STC_RSVD2, NULL, HFILL }
    },

    { &hf_homeplug_stc_dder,
      { "Disable Default Encryption Receive", "homeplug.stc.dder",
      FT_BOOLEAN, 8, NULL, HOMEPLUG_STC_DDER, NULL, HFILL }
    },

    { &hf_homeplug_stc_dur,
      { "Disable Unencrypted Receive", "homeplug.stc.dur",
      FT_BOOLEAN, 8, NULL, HOMEPLUG_STC_DUR, NULL, HFILL }
    },

    { &hf_homeplug_stc_ebp,
      { "INT51X1 (Host/DTE Option) Enable Backpressure", "homeplug.stc.ebp",
      FT_BOOLEAN, 8, NULL, HOMEPLUG_STC_EBP,
      NULL, HFILL }
    },

    { &hf_homeplug_stc_dees,
      { "Disable EEPROM Save", "homeplug.stc.dees",
      FT_BOOLEAN, 8, NULL, HOMEPLUG_STC_DEES, NULL, HFILL }
    },

    { &hf_homeplug_stc_txeks,
      { "EKS to be used for encryption", "homeplug.stc.txeks",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /* Undecoded data */
    { &hf_homeplug_data,
      { "Data", "homeplug.data",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_homeplug,
    &ett_homeplug_mctrl,
    &ett_homeplug_mehdr,
    &ett_homeplug_rce,
    &ett_homeplug_cer,
    &ett_homeplug_vs,
    &ett_homeplug_vs_mid,
    &ett_homeplug_snk,
    &ett_homeplug_rps,
    &ett_homeplug_psr,
    &ett_homeplug_slp,
    &ett_homeplug_loader,
    &ett_homeplug_hreq,
    &ett_homeplug_hrsp,
    &ett_homeplug_ns,
    &ett_homeplug_tx_bfr_state,
    &ett_homeplug_tone,
    &ett_homeplug_bcn,
    &ett_homeplug_bridge,
    &ett_homeplug_bcl,
    &ett_homeplug_stc
  };

  proto_homeplug = proto_register_protocol("HomePlug protocol", "HomePlug", "homeplug");

  proto_register_field_array(proto_homeplug, hf, array_length(hf));

  proto_register_subtree_array(ett, array_length(ett));
}
