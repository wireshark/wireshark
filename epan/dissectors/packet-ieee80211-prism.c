/* packet-ieee80211-prism.c
 * Routines for Prism monitoring mode header dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 * Copyright 2016 Cisco Meraki
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <wiretap/wtap.h>
#include <wsutil/pint.h>
#include "packet-ieee80211.h"

void proto_register_ieee80211_prism(void);
void proto_reg_handoff_ieee80211_prism(void);

#define SHORT_STR 256

static dissector_handle_t wlancap_handle;
static dissector_handle_t ieee80211_handle;
static dissector_handle_t ieee80211_radio_handle;

static capture_dissector_handle_t ieee80211_cap_handle;
static capture_dissector_handle_t wlancap_cap_handle;

static int proto_prism = -1;

/* Prism radio header */

static int hf_ieee80211_prism_msgcode = -1;
static int hf_ieee80211_prism_msglen = -1;
static int hf_ieee80211_prism_devname = -1;
static int hf_ieee80211_prism_did = -1;
static int hf_ieee80211_prism_did_type = -1;
static int hf_ieee80211_prism_did_status = -1;
static int hf_ieee80211_prism_did_length = -1;
static int hf_ieee80211_prism_did_hosttime = -1;
static int hf_ieee80211_prism_did_mactime = -1;
static int hf_ieee80211_prism_did_channel = -1;
static int hf_ieee80211_prism_did_rssi = -1;
static int hf_ieee80211_prism_did_sq = -1;
static int hf_ieee80211_prism_did_signal = -1;
static int hf_ieee80211_prism_did_noise = -1;
static int hf_ieee80211_prism_did_rate = -1;
static int hf_ieee80211_prism_did_istx = -1;
static int hf_ieee80211_prism_did_frmlen = -1;
static int hf_ieee80211_prism_did_unknown = -1;

/* Qualcomm Extensions */
static int hf_ieee80211_prism_did_sig_a1 = -1;
static int hf_ieee80211_prism_did_sig_a2 = -1;
static int hf_ieee80211_prism_did_sig_b = -1;
static int hf_ieee80211_prism_did_sig_rate_field = -1;


static gint ett_prism = -1;
static gint ett_prism_did = -1;
static gint ett_sig_ab = -1;

static dissector_handle_t prism_handle;

/*
 * Prism II-based wlan devices have a monitoring mode that sticks
 * a proprietary header on each packet with lots of good
 * information.  This file is responsible for decoding that
 * data.
 *
 * Support by Tim Newsham
 *
 * A value from the header.
 *
 * It appears from looking at the linux-wlan-ng and Prism II HostAP
 * drivers, and various patches to the orinoco_cs drivers to add
 * Prism headers, that:
 *
 *      the "did" identifies what the value is (i.e., what it's the value
 *      of);
 *
 *      "status" is 0 if the value is present or 1 if it's absent;
 *
 *      "len" is the length of the value (always 4, in that code);
 *
 *      "data" is the value of the data (or 0 if not present).
 *
 * Note: all of those values are in the *host* byte order of the machine
 * on which the capture was written.
 */


/*
 * Header attached during Prism monitor mode.
 *
 * At least according to one paper I've seen, the Prism 2.5 chip set
 * provides:
 *
 *      RSSI (receive signal strength indication) is "the total power
 *      received by the radio hardware while receiving the frame,
 *      including signal, interfereence, and background noise";
 *
 *      "silence value" is "the total power observed just before the
 *      start of the frame".
 *
 * None of the drivers I looked at supply the "rssi" or "sq" value,
 * but they do supply "signal" and "noise" values, along with a "rate"
 * value that's 1/5 of the raw value from what is presumably a raw
 * HFA384x frame descriptor, with the comment "set to 802.11 units",
 * which presumably means the units are 500 Kb/s.
 *
 * I infer from the current NetBSD "wi" driver that "signal" and "noise"
 * are adjusted dBm values, with the dBm value having 100 added to it
 * for the Prism II cards (although the NetBSD code has an XXX comment
 * for the #define for WI_PRISM_DBM_OFFSET) and 149 (with no XXX comment)
 * for the Orinoco cards.
 *
 * XXX - what about other drivers that supply Prism headers, such as
 * old versions of the MadWifi driver?
 *
 * I'm not sure where these DID values come from, but they work with
 * at least one capture file.  However, in
 *
 *    https://ask.wireshark.org/questions/14963/how-to-get-the-field-did-unknown-4041-into-the-column
 *
 * somebody reports a capture where *different* DID values, corresponding
 * to
 *
 *    http://www.martin.cc/linux/prism
 *
 * are used (and that's not a byte-order issue, as those values are *not*
 * just byte-swapped versions of the other values).
 */

#define PRISM_HEADER_LENGTH     144             /* Default Prism Header Length */

/*
 * Message code values.
 *
 * Some Prism captures have headers that begin with 0x00000044; those
 * captures have the non-home.martin.cc values for the DID types,
 * while a capture with 0x00000041 as the message code have the
 * home.martin.cc values for the DID types, and the home.martin.cc
 * page has 0x00000041 as the message code.
 */
#define PRISM_TYPE1_MSGCODE      0x00000044      /* Monitor Frame */
#define PRISM_TYPE2_MSGCODE      0x00000041

/*
 * DID codes - PRISM_TYPE1_xxx are the non-home.martin.cc values, and
 * PRISM_TYPE2_xxx are the home.martin.cc values.
 */
#define PRISM_TYPE1_HOSTTIME     0x00010044      /* Host time element */
#define PRISM_TYPE2_HOSTTIME     0x00001041
#define PRISM_TYPE1_MACTIME      0x00020044      /* Mac time element */
#define PRISM_TYPE2_MACTIME      0x00002041
#define PRISM_TYPE1_CHANNEL      0x00030044      /* Channel element */
#define PRISM_TYPE2_CHANNEL      0x00003041
#define PRISM_TYPE1_RSSI         0x00040044      /* RSSI element */
#define PRISM_TYPE2_RSSI         0x00004041
#define PRISM_TYPE1_SQ           0x00050044      /* SQ element */
#define PRISM_TYPE2_SQ           0x00005041
#define PRISM_TYPE1_SIGNAL       0x00060044      /* Signal element */
#define PRISM_TYPE2_SIGNAL       0x00006041
#define PRISM_TYPE1_NOISE        0x00070044      /* Noise element */
#define PRISM_TYPE2_NOISE        0x00007041
#define PRISM_TYPE1_RATE         0x00080044      /* Rate element */
#define PRISM_TYPE2_RATE         0x00008041
#define PRISM_TYPE1_ISTX         0x00090044      /* Is Tx frame */
#define PRISM_TYPE2_ISTX         0x00009041
#define PRISM_TYPE1_FRMLEN       0x000A0044      /* Frame length */
#define PRISM_TYPE2_FRMLEN       0x0000A041

/* Qualcomm extensions */
#define PRISM_TYPE1_RATE_SIG_A1  0x000B0044      /* VHT SIGA1 element */
#define PRISM_TYPE2_RATE_SIG_A1  0x0000B044
#define PRISM_TYPE1_RATE_SIG_A2  0x000C0044      /* VHT SIGA2 element */
#define PRISM_TYPE2_RATE_SIG_A2  0x0000C044
#define PRISM_TYPE1_RATE_SIG_B   0x000D0044      /* VHT SIGB element */
#define PRISM_TYPE2_RATE_SIG_B   0x0000D044      /* VHT SIGB element */

static const value_string prism_did_vals[] =
{
    { PRISM_TYPE1_HOSTTIME,   "Host Time" },
    { PRISM_TYPE2_HOSTTIME,   "Host Time" },
    { PRISM_TYPE1_MACTIME,    "Mac Time" },
    { PRISM_TYPE2_MACTIME,    "Mac Time" },
    { PRISM_TYPE1_CHANNEL,    "Channel" },
    { PRISM_TYPE2_CHANNEL,    "Channel" },
    { PRISM_TYPE1_RSSI,       "RSSI" },
    { PRISM_TYPE2_RSSI,       "RSSI" },
    { PRISM_TYPE1_SQ,         "SQ" },
    { PRISM_TYPE2_SQ,         "SQ" },
    { PRISM_TYPE1_SIGNAL,     "Signal" },
    { PRISM_TYPE2_SIGNAL,     "Signal" },
    { PRISM_TYPE1_NOISE,      "Noise" },
    { PRISM_TYPE2_NOISE,      "Noise" },
    { PRISM_TYPE1_RATE,       "Rate" },
    { PRISM_TYPE2_RATE,       "Rate" },
    { PRISM_TYPE1_ISTX,       "Is Tx" },
    { PRISM_TYPE2_ISTX,       "Is Tx" },
    { PRISM_TYPE1_FRMLEN,     "Frame Length" },
    { PRISM_TYPE2_FRMLEN,     "Frame Length" },

    /* Qualcomm extensions */
    { PRISM_TYPE1_RATE_SIG_A1, "SIG A1" },
    { PRISM_TYPE2_RATE_SIG_A1, "SIG A1" },
    { PRISM_TYPE1_RATE_SIG_A2, "SIG A2" },
    { PRISM_TYPE2_RATE_SIG_A2, "SIG A2" },
    { PRISM_TYPE1_RATE_SIG_B,  "SIG B" },
    { PRISM_TYPE2_RATE_SIG_B,  "SIG B" },
    { 0, NULL}
};

/*
 * The header file mentioned above says 0 means "supplied" and 1 means
 * "not supplied".  I haven't seen a capture file with anything other
 * than 0 there, but there is at least one driver that appears to use
 * 1 for values it doesn't supply (the Linux acx-20080210 driver).
 */
static const value_string prism_status_vals[] =
{
    { 0, "Supplied" },
    { 1, "Not Supplied" },
    { 0, NULL}
};

static const value_string prism_istx_vals[] =
{
    { 0, "Rx Packet" },
    { 1, "Tx Packet" },
    { 0, NULL}
};

static void
prism_rate_base_custom(gchar *result, guint32 rate)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "%u.%u", rate /2, rate & 1 ? 5 : 0);
}

static gchar *
prism_rate_return(guint32 rate)
{
    gchar *result=NULL;
    result = (gchar *)wmem_alloc(wmem_packet_scope(), SHORT_STR);
    result[0] = '\0';
    prism_rate_base_custom(result, rate);

    return result;
}


/* HT20 Rate table MAX NSS = 4 */
static unsigned int ht_20_tbl[32][2] =
{
    { 65,   72   },   /* MCS 0 */
    { 130,  144  },   /* MCS 1 */
    { 195,  217  },   /* MCS 2 */
    { 260,  289  },   /* MCS 3 */
    { 390,  433  },   /* MCS 4 */
    { 520,  578  },   /* MCS 5 */
    { 585,  650  },   /* MCS 6 */
    { 650,  722  },   /* MCS 7 */
    { 130,  144  },   /* MCS 8 */
    { 260,  289  },   /* MCS 9 */
    { 390,  433  },   /* MCS 10 */
    { 520,  578  },   /* MCS 11 */
    { 780,  867  },   /* MCS 12 */
    { 1040, 1156 },   /* MCS 13 */
    { 1170, 1300 },   /* MCS 14 */
    { 1300, 1444 },   /* MCS 15 */
    { 195,  217  },   /* MCS 16 */
    { 390,  433  },   /* MCS 17 */
    { 585,  650  },   /* MCS 18 */
    { 780,  867  },   /* MCS 19 */
    { 1170, 1300 },   /* MCS 20 */
    { 1560, 1733 },   /* MCS 21 */
    { 1755, 1950 },   /* MCS 22 */
    { 1950, 2167 },   /* MCS 23 */
    { 260,  289  },   /* MCS 24 */
    { 520,  578  },   /* MCS 25 */
    { 780,  867  },   /* MCS 26 */
    { 1040, 1156 },   /* MCS 27 */
    { 1560, 1733 },   /* MCS 28 */
    { 2080, 2311 },   /* MCS 29 */
    { 2340, 2600 },   /* MCS 30 */
    { 2600, 2889 }    /* MCS 31 */
};

/* HT40 Rate table MAX NSS = 4 */
static unsigned int ht_40_tbl[32][2] =
{
    { 135,  150  },    /* MCS 0 */
    { 270,  300  },    /* MCS 1 */
    { 405,  450  },    /* MCS 2 */
    { 540,  600  },    /* MCS 3 */
    { 810,  900  },    /* MCS 4 */
    { 1080, 1200 },    /* MCS 5 */
    { 1215, 1350 },    /* MCS 6 */
    { 1350, 1500 },    /* MCS 7 */
    { 270,  300  },    /* MCS 8 */
    { 540,  600  },    /* MCS 9 */
    { 810,  900  },    /* MCS 10 */
    { 1080, 1200 },    /* MCS 11 */
    { 1620, 1800 },    /* MCS 12 */
    { 2160, 2400 },    /* MCS 13 */
    { 2430, 2700 },    /* MCS 14 */
    { 2700, 3000 },    /* MCS 15 */
    { 405,  450  },    /* MCS 16 */
    { 810,  900  },    /* MCS 17 */
    { 1215, 1350 },    /* MCS 18 */
    { 1620, 1800 },    /* MCS 19 */
    { 2430, 2700 },    /* MCS 20 */
    { 3240, 3600 },    /* MCS 21 */
    { 3645, 4050 },    /* MCS 22 */
    { 4050, 4500 },    /* MCS 23 */
    { 540,  600  },    /* MCS 24 */
    { 1080, 1200 },    /* MCS 25 */
    { 1620, 1800 },    /* MCS 26 */
    { 2160, 2400 },    /* MCS 27 */
    { 3240, 3600 },    /* MCS 28 */
    { 4320, 4800 },    /* MCS 29 */
    { 4860, 5400 },    /* MCS 30 */
    { 5400, 6000 }};   /* MCS 31 */

/* VHT20 Rate Table MAX NSS = 4 */
static unsigned int vht_20_tbl[10][8] =
{
    { 65,  72,  130,  144,  195,  217,   260,   289},    /* MCS 0 */
    { 130, 144, 260,  289,  390,  433,   520,   578},    /* MCS 1 */
    { 195, 217, 390,  433,  585,  650,   780,   867},    /* MCS 2 */
    { 260, 289, 520,  578,  780,  867,   1040,  1156},   /* MCS 3 */
    { 390, 433, 780,  867,  1170, 1300,  1560,  1733},   /* MCS 4 */
    { 520, 578, 1040, 1156, 1560, 1733,  2080,  2311},   /* MCS 5 */
    { 585, 650, 1170, 1300, 1755, 1950,  2340,  2600},   /* MCS 6 */
    { 650, 722, 1300, 1444, 1950, 2167,  2600,  2889},   /* MCS 7 */
    { 780, 867, 1560, 1733, 2340, 2600,  3120,  3467},   /* MCS 8 */
    {   0,   0,    0,    0, 2600, 2889,     0,     0}    /* MCS 9 */
};

/* VHT40 Rate Table MAX NSS = 4 */
static unsigned int vht_40_tbl[10][8] =
{
    { 135,  150,  270,   300,  405,  450,   540,   600},    /* MCS 0 */
    { 270,  300,  540,   600,  810,  900,  1080,  1200},    /* MCS 1 */
    { 405,  450,  810,   900, 1215, 1350,  1620,  1800},    /* MCS 2 */
    { 540,  600,  1080, 1200, 1620, 1800,  2160,  2400},    /* MCS 3 */
    { 810,  900,  1620, 1800, 2430, 2700,  3240,  3600},    /* MCS 4 */
    { 1080, 1200, 2160, 2400, 3240, 3600,  4320,  4800},    /* MCS 5 */
    { 1215, 1350, 2430, 2700, 3645, 4050,  4860,  5400},    /* MCS 6 */
    { 1350, 1500, 2700, 3000, 4050, 4500,  5400,  6000},    /* MCS 7 */
    { 1620, 1800, 3240, 3600, 4860, 5400,  6480,  7200},    /* MCS 8 */
    { 1800, 2000, 3600, 4000, 5400, 6000,  7200,  8000}     /* MCS 9 */
};

/* VHT80 Rate Table MAX NSS = 4 */
static unsigned int vht_80_tbl[10][8] =
{
    {  293,  325,  585,  650,   878,   975,   1170,   1300},   /* MCS 0 */
    {  585,  650, 1170, 1300,  1755,  1950,   2340,   2600},   /* MCS 1 */
    {  878,  975, 1755, 1950,  2633,  2925,   3510,   3900},   /* MCS 2 */
    { 1170, 1300, 2340, 2600,  3510,  3900,   4680,   5200},   /* MCS 3 */
    { 1755, 1950, 3510, 3900,  5265,  5850,   7020,   7800},   /* MCS 4 */
    { 2340, 2600, 4680, 5200,  7020,  7800,   9360,  10400},   /* MCS 5 */
    { 2633, 2925, 5265, 5850,     0,     0,  10530,  11700},   /* MCS 6 */
    { 2925, 3250, 5850, 6500,  8775,  9750,  11700,  13000},   /* MCS 7 */
    { 3510, 3900, 7020, 7800, 10530, 11700,  14040,  15600},   /* MCS 8 */
    { 3900, 4333, 7800, 8667, 11700, 13000,  15600,  17333}    /* MCS 9 */
};

/* VHT160 Rate Table MAX NSS = 4 */
static unsigned int vht_160_tbl[10][8] =
{
    {  585,  650,  1170,  1300,  1755,  1950,  2340,  2600},   /* MCS 0 */
    { 1170, 1300,  2340,  2600,  3510,  3900,  4680,  5200},   /* MCS 1 */
    { 1755, 1950,  3510,  3900,  5265,  5850,  7020,  7800},   /* MCS 2 */
    { 2340, 2600,  4680,  5200,  7020,  7800,  9360, 10400},   /* MCS 3 */
    { 3510, 3900,  7020,  7800, 10530, 11700, 14040, 15600},   /* MCS 4 */
    { 4680, 5200,  9360, 10400, 14040, 15600, 18720, 20800},   /* MCS 5 */
    { 5265, 5850, 10530, 11700, 15795, 17550, 21060, 23400},   /* MCS 6 */
    { 5850, 6500, 11700, 13000, 17550, 19500, 23400, 26000},   /* MCS 7 */
    { 7020, 7800, 14040, 15600, 21060, 23400, 28080, 31200},   /* MCS 8 */
    { 7800, 8667, 15600, 17333,     0,     0, 31200, 34667}    /* MCS 9 */
};


static gchar *
prism_rate_return_sig(guint32 rate_phy1, guint32 rate_phy2, struct ieee_802_11_phdr *phdr)
{
    gchar *result = NULL;
    unsigned int mcs, base, pream_type, disp_rate, bw, sgi, ldpc, stbc, groupid, txbf;
    gboolean su_ppdu = FALSE;
    unsigned int partial_aid, nsts_u1, nsts_u2, nsts_u3, nsts_u4;
    unsigned int sig_a_1, sig_a_2, nss = 1, nsts_su, signal_type;
    unsigned int cck_tbl[] = {22, 11, 4, 2};
    static const unsigned int bw_map[] = { 0, 1, 4, 11 };

    /*
     * Qualcomm Atheros: Display Nss, MCS/Rate, BW, sgi, LDPC, STBC info
     */
    pream_type =  rate_phy1 & 0xF;
    switch (pream_type) {

    case 0: /* OFDM */
        phdr->phy = PHDR_802_11_PHY_11A; /* or 11g? */
        mcs = (rate_phy1 >> 4) & 0xF;
        base = (mcs & 0x4) ? 9 : 6;
        mcs &= ~0x4;
        mcs = base << (11 - mcs);
        mcs = (mcs > 54) ? 54 : mcs;
        phdr->has_data_rate = 1;
        phdr->data_rate = mcs * 2;
        signal_type = rate_phy1 & (1 << 12);
        bw = 20 << ((rate_phy1 >> 13) & 0x3);
        result = wmem_strdup_printf(wmem_packet_scope(),
              "Rate: OFDM %u.%u Mb/s Signaling:%s BW %d",
               mcs, 0, signal_type ? "Dynamic" : "Static", bw
              );
        break;

    case 1: /* CCK */
        phdr->phy = PHDR_802_11_PHY_11B;
        mcs = (rate_phy1 >> 4) & 0xF;
        base = (mcs & 0x4) ? 1 : 0;
        phdr->phy_info.info_11b.has_short_preamble = 1;
        phdr->phy_info.info_11b.short_preamble = base;
        mcs &= ~0x4;
        mcs = (mcs - 8) & 0x3;
        disp_rate = cck_tbl[mcs];
        phdr->has_data_rate = 1;
        phdr->data_rate = disp_rate;
        result = wmem_strdup_printf(wmem_packet_scope(), "Rate: %u.%u Mb/s %s",
                      disp_rate / 2,
                      (disp_rate & 1) ? 5 : 0,
                      base ? "[SP]" : "[LP]");
        break;

    case 2: /* HT */
        phdr->phy = PHDR_802_11_PHY_11N;
        sig_a_1 = (rate_phy1 >> 4) & 0xFFFF;
        sig_a_2 = (rate_phy2) & 0xFFF;
        mcs = sig_a_1  & 0x7f;
        phdr->phy_info.info_11n.has_mcs_index = 1;
        phdr->phy_info.info_11n.mcs_index = mcs;
        bw = 20 << ((sig_a_1 >> 7) & 1);
        phdr->phy_info.info_11n.has_bandwidth = 1;
        phdr->phy_info.info_11n.bandwidth = ((sig_a_1 >> 7) & 1);
        sgi = (sig_a_2 >> 7) & 1;
        phdr->phy_info.info_11n.has_short_gi = 1;
        phdr->phy_info.info_11n.short_gi = sgi;
        ldpc = (sig_a_2 >> 6) & 1;
        phdr->phy_info.info_11n.has_fec = 1;
        phdr->phy_info.info_11n.fec = ldpc;
        stbc = ((sig_a_2 >> 4) & 3)?1:0;
        phdr->phy_info.info_11n.has_stbc_streams = 1;
        phdr->phy_info.info_11n.stbc_streams = stbc;
        phdr->phy_info.info_11n.has_ness = 1;
        phdr->phy_info.info_11n.ness = (sig_a_2 >> 8) & 3;
        nss = (mcs >> 3) + 1;
        /* Check limits */
        disp_rate = 0;
        if ((nss <= 4) && (mcs <= 31) && ((bw == 20) || (bw==40))){
            switch (bw) {

            case 20:
                if (sgi) {
                    disp_rate = ht_20_tbl[mcs][1];
                } else {
                    disp_rate = ht_20_tbl[mcs][0];
                }
                break;

            case 40:
                if (sgi) {
                    disp_rate = ht_40_tbl[mcs][1];
                } else {
                    disp_rate = ht_40_tbl[mcs][0];
                }
                break;
            }
        }
        result = wmem_strdup_printf(wmem_packet_scope(),
              "%u.%u Mb/s HT MCS %d NSS %d BW %d MHz %s %s %s",
               disp_rate/10, disp_rate%10, mcs, nss, bw,
               sgi ? "[SGI]" : "",
               ldpc ? "[LDPC]" : "",
               stbc ? "[STBC]" : "");
        break;

    case 3: /* VHT */
        phdr->phy = PHDR_802_11_PHY_11AC;
        sig_a_1 = (rate_phy1 >> 4) & 0xFFFFFF;
        sig_a_2 = (rate_phy2) & 0xFFFFFF;
        stbc = (sig_a_1 >> 3) & 1;
        phdr->phy_info.info_11ac.has_stbc = 1;
        phdr->phy_info.info_11ac.stbc = stbc;
        sgi = sig_a_2 & 1;
        phdr->phy_info.info_11ac.has_short_gi = 1;
        phdr->phy_info.info_11ac.short_gi = sgi;
        bw = 20 << (sig_a_1 & 3);
        phdr->phy_info.info_11ac.has_bandwidth = 1;
        phdr->phy_info.info_11ac.bandwidth = bw_map[(sig_a_1 & 3)];
        ldpc = (sig_a_2 >> 2) & 1;
        phdr->phy_info.info_11ac.has_fec = 1;
        phdr->phy_info.info_11ac.fec = ldpc;
        groupid = (sig_a_1 >> 4) & 0x3F;
        phdr->phy_info.info_11ac.has_group_id = 1;
        phdr->phy_info.info_11ac.group_id = groupid;

        if (groupid == 0 || groupid == 63)
            su_ppdu = TRUE;

        disp_rate = 0;

        if (su_ppdu) {
            nsts_su = (sig_a_1 >> 10) & 0x7;
            if (stbc)
                nss = nsts_su >> 2;
            else
                nss = nsts_su;
            ++nss;
            mcs = (sig_a_2 >> 4) & 0xF;
            phdr->phy_info.info_11ac.mcs[0] = mcs;
            phdr->phy_info.info_11ac.nss[0] = nss;
            txbf = (sig_a_2 >> 8) & 1;
            phdr->phy_info.info_11ac.has_beamformed = 1;
            phdr->phy_info.info_11ac.beamformed = txbf;
            partial_aid = (sig_a_1 >> 13) & 0x1FF;
            phdr->phy_info.info_11ac.has_partial_aid = 1;
            phdr->phy_info.info_11ac.partial_aid = partial_aid;

            /* Check limits */
            if ((nss <= 4) && (mcs <= 9) && ((bw == 20) || (bw==40) || (bw==80) || bw==160)) {
                switch (bw) {

                case 20:
                    if (sgi) {
                        disp_rate = vht_20_tbl[mcs][(nss * 2) - 1];
                    } else {
                        disp_rate = vht_20_tbl[mcs][(nss - 1) * 2];
                    }
                    break;

                case 40:
                    if (sgi) {
                        disp_rate = vht_40_tbl[mcs][(nss * 2) - 1];
                    } else {
                        disp_rate = vht_40_tbl[mcs][(nss - 1) * 2];
                    }
                    break;

                case 80:
                    if (sgi) {
                        disp_rate = vht_80_tbl[mcs][(nss * 2) - 1];
                    } else {
                        disp_rate = vht_80_tbl[mcs][(nss - 1) * 2];
                    }
                    break;

                case 160:
                    if (sgi) {
                        disp_rate = vht_160_tbl[mcs][(nss * 2) - 1];
                    } else {
                        disp_rate = vht_160_tbl[mcs][(nss - 1) * 2];
                    }
                    break;
                }
            }

            result = wmem_strdup_printf(wmem_packet_scope(),
                "%u.%u Mb/s VHT MCS %d NSS %d Partial AID %d BW %d MHz %s %s %s GroupID %d %s %s",
                disp_rate/10, disp_rate%10,
                mcs, nss, partial_aid, bw,
                sgi ? "[SGI]" : "",
                ldpc ? "[LDPC]" : "",
                stbc ? "[STBC]" : "",
                groupid,
                "[SU_PPDU]",
                txbf ? "[TxBF]" : "");
        } else {
            nsts_u1 = (sig_a_1 >> 10) & 0x7;
            nsts_u2 = (sig_a_1 >> 13) & 0x7;
            nsts_u3 = (sig_a_1 >> 16) & 0x7;
            nsts_u4 = (sig_a_1 >> 19) & 0x7;

            result = wmem_strdup_printf(wmem_packet_scope(),
                "VHT NSTS %d %d %d %d BW %d MHz %s %s %s GroupID %d %s",
                nsts_u1, nsts_u2, nsts_u3, nsts_u4, bw,
                sgi ? "[SGI]" : "",
                ldpc ? "[LDPC]" : "",
                stbc ? "[STBC]" : "",
                groupid,
                "[MU_PPDU]");
        }
        break;
    }

    return result;
}

static gboolean
capture_prism(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    guint32 cookie;

    if (!BYTES_ARE_IN_FRAME(offset, len, 4))
        return FALSE;

    /* Some captures with DLT_PRISM have the AVS WLAN header */
    cookie = pntoh32(pd);
    if ((cookie == WLANCAP_MAGIC_COOKIE_V1) ||
        (cookie == WLANCAP_MAGIC_COOKIE_V2)) {
        return call_capture_dissector(wlancap_cap_handle, pd, offset, len, cpinfo, pseudo_header);
    }

    /* Prism header */
    if (!BYTES_ARE_IN_FRAME(offset, len, PRISM_HEADER_LENGTH))
        return FALSE;

    offset += PRISM_HEADER_LENGTH;

    /* 802.11 header follows */
    return call_capture_dissector(ieee80211_cap_handle, pd, offset, len, cpinfo, pseudo_header);
}

static int
dissect_prism(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *prism_tree, *prism_did_tree = NULL;
    proto_item *ti = NULL, *ti_did = NULL;
    tvbuff_t *next_tvb;
    int offset;
    guint32 msgcode, msglen, did, rate_phy1 = 0, rate_phy2 = 0;
    guint byte_order;
    guint16 status;
    const guint8 *devname_p;
    guint32 mactime;
    guint32 channel;
    guint32 signal_dbm;
    guint32 rate;
    struct ieee_802_11_phdr phdr;

    offset = 0;
    did = 0;

    /* handle the AVS header */
    msgcode = tvb_get_ntohl(tvb, offset);
    if ((msgcode == WLANCAP_MAGIC_COOKIE_V1) ||
        (msgcode == WLANCAP_MAGIC_COOKIE_V2)) {
        call_dissector(wlancap_handle, tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    /*
     * If we don't see a valid message type, assume the Prism or AVS
     * header was omitted and just hand off to the 802.11 dissector;
     * at least one capture has AVS headers on some packets and no
     * radio headers on others (incoming vs. outgoing?).
     *
     * Check for both byte orders and use that to determine
     * the byte order of the fields in the Prism header.
     */
    if ((msgcode == PRISM_TYPE1_MSGCODE) || (msgcode == PRISM_TYPE2_MSGCODE)) {
        /* big-endian fetch matched */
        byte_order = ENC_BIG_ENDIAN;
    } else if (((msgcode = tvb_get_letohl(tvb, offset)) == PRISM_TYPE1_MSGCODE) ||
                                               (msgcode == PRISM_TYPE2_MSGCODE)) {
        /* little-endian fetch matched */
        byte_order = ENC_LITTLE_ENDIAN;
    } else {
        /* neither matched - try it as just 802.11 with no Prism header */
        call_dissector(ieee80211_handle, tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    /* We don't have any 802.11 metadata yet. */
    memset(&phdr, 0, sizeof(phdr));
    phdr.fcs_len = -1;
    phdr.decrypted = FALSE;
    phdr.datapad = FALSE;
    phdr.phy = PHDR_802_11_PHY_UNKNOWN;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Prism");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_prism, tvb, 0, 144, ENC_NA);
    prism_tree = proto_item_add_subtree(ti, ett_prism);

    /* Message Code */
    proto_tree_add_item_ret_uint(prism_tree, hf_ieee80211_prism_msgcode, tvb, offset, 4, byte_order, &msgcode);
    offset += 4;

    /* Message Length */
    proto_tree_add_item_ret_uint(prism_tree, hf_ieee80211_prism_msglen, tvb, offset, 4, byte_order, &msglen);
    offset += 4;

    /* Device Name */
    proto_tree_add_item_ret_string(prism_tree, hf_ieee80211_prism_devname, tvb, offset, 16, ENC_ASCII|ENC_NA, wmem_packet_scope(), &devname_p);
    offset += 16;

    col_add_fstr(pinfo->cinfo, COL_INFO, "Device: %s, Message 0x%x, Length %d", devname_p, msgcode, msglen);

    while (offset < PRISM_HEADER_LENGTH)
    {
        /* DID */
        if (tree) {
            ti_did = proto_tree_add_item(prism_tree, hf_ieee80211_prism_did, tvb, offset, 12, ENC_NA);
            prism_did_tree = proto_item_add_subtree(ti_did, ett_prism_did);

            proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_type, tvb, offset, 4, byte_order);
            did = tvb_get_guint32(tvb, offset, byte_order);
            proto_item_append_text(ti_did, " %s", val_to_str(did, prism_did_vals, "Unknown %x") );
        }
        offset += 4;


        /* Status */
        status = tvb_get_guint16(tvb, offset, byte_order);
        proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_status, tvb, offset, 2, byte_order);
        offset += 2;

        /* Length */
        proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_length, tvb, offset, 2, byte_order);
        offset += 2;

        /* Data, if present... */
        if (status == 0) {
            switch (did) {

            case PRISM_TYPE1_HOSTTIME:
            case PRISM_TYPE2_HOSTTIME:
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_hosttime, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " %d", tvb_get_guint32(tvb, offset, byte_order) );
                }
                break;

            case PRISM_TYPE1_MACTIME:
            case PRISM_TYPE2_MACTIME:
                mactime = tvb_get_guint32(tvb, offset, byte_order);
                phdr.has_tsf_timestamp = 1;
                phdr.tsf_timestamp = mactime;
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_mactime, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " %d", mactime );
                }
                break;

            case PRISM_TYPE1_CHANNEL:
            case PRISM_TYPE2_CHANNEL:
                channel = tvb_get_guint32(tvb, offset, byte_order);
                phdr.has_channel = TRUE;
                phdr.channel = channel;
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_channel, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " %u", channel);
                }
                col_add_fstr(pinfo->cinfo, COL_FREQ_CHAN, "%u", channel);
                break;

            case PRISM_TYPE1_RSSI:
            case PRISM_TYPE2_RSSI:
                signal_dbm = tvb_get_guint32(tvb, offset, byte_order);
                phdr.has_signal_dbm = 1;
                phdr.signal_dbm = signal_dbm;
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_rssi, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " %d", signal_dbm );
                }
                col_add_fstr(pinfo->cinfo, COL_RSSI, "%d", signal_dbm);
                break;

            case PRISM_TYPE1_SQ:
            case PRISM_TYPE2_SQ:
                 if (tree) {
                      proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_sq, tvb, offset, 4, byte_order);
                      proto_item_append_text(ti_did, " 0x%x", tvb_get_guint32(tvb, offset, byte_order) );
                }
                break;

            case PRISM_TYPE1_SIGNAL:
            case PRISM_TYPE2_SIGNAL:
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_signal, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_guint32(tvb, offset, byte_order) );
                }
                break;

            case PRISM_TYPE1_NOISE:
            case PRISM_TYPE2_NOISE:
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_noise, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_guint32(tvb, offset, byte_order) );
                }
                break;

            case PRISM_TYPE1_RATE:
            case PRISM_TYPE2_RATE:
                rate = tvb_get_guint32(tvb, offset, byte_order);
                phdr.has_data_rate = TRUE;
                phdr.data_rate = rate;
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_rate, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " %s Mb/s", prism_rate_return(rate));
                }
                col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%s", prism_rate_return(rate));
                break;

            case PRISM_TYPE1_RATE_SIG_A1:
            case PRISM_TYPE2_RATE_SIG_A1:
                /*
                 * XXX - always little-endian, or same byte order as the
                 * rest of the Prism header?
                 */
                rate_phy1 = tvb_get_letohl(tvb, offset);
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_sig_a1, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_letohl(tvb, offset));
                }
                break;

            case PRISM_TYPE1_RATE_SIG_A2:
            case PRISM_TYPE2_RATE_SIG_A2:
                /*
                 * XXX - always little-endian, or same byte order as the
                 * rest of the Prism header?
                 */
                rate_phy2 = tvb_get_letohl(tvb, offset);
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_sig_a2, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_letohl(tvb, offset));
                }
                break;

            case PRISM_TYPE1_RATE_SIG_B:
            case PRISM_TYPE2_RATE_SIG_B:
                if (tree && rate_phy1 && rate_phy2) {
                    proto_item *sig_sub_item;

                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_sig_b, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_letohl(tvb, offset));

                    sig_sub_item = proto_tree_add_item(prism_tree, hf_ieee80211_prism_did_sig_rate_field, tvb, offset, 4, byte_order);
                    proto_item_append_text(sig_sub_item, " %s", prism_rate_return_sig(rate_phy1, rate_phy2, &phdr));
                  }
                  break;

            case PRISM_TYPE1_ISTX:
            case PRISM_TYPE2_ISTX:
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_istx, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_guint32(tvb, offset, byte_order) );
                }
                break;

            case PRISM_TYPE1_FRMLEN:
            case PRISM_TYPE2_FRMLEN:
                if (tree) {
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_frmlen, tvb, offset, 4, byte_order);
                    proto_item_append_text(ti_did, " %d", tvb_get_guint32(tvb, offset, byte_order));
                }
                break;

            default:
                proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_unknown, tvb, offset, 4, byte_order);
                break;
            }
        }
        offset += 4;
    }

    /* dissect the 802.11 header next */
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo, tree, (void *)&phdr);
    return tvb_captured_length(tvb);
}

static hf_register_info hf_prism[] = {
    /* Prism-specific header fields
       XXX - make as many of these generic as possible. */
    { &hf_ieee80211_prism_msgcode,
     {"Message Code", "prism.msgcode", FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_msglen,
     {"Message Length", "prism.msglen", FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_devname,
     {"Device Name", "prism.devname", FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did,
     {"DID", "prism.did", FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_type,
     {"DID", "prism.did.type", FT_UINT32, BASE_HEX, VALS(prism_did_vals), 0x0,
      "Different ID for each parameter", HFILL }},

    { &hf_ieee80211_prism_did_status,
     {"Status", "prism.did.status", FT_UINT16, BASE_DEC, VALS(prism_status_vals), 0x0,
      "Supplied by the driver or not", HFILL }},

    { &hf_ieee80211_prism_did_length,
     {"Length", "prism.did.length", FT_UINT16, BASE_DEC, NULL, 0x0,
      "Length of data", HFILL }},

    { &hf_ieee80211_prism_did_hosttime,
     {"Host Time", "prism.did.hosttime", FT_UINT32, BASE_DEC, NULL, 0x0,
      "In jiffies - for our system this is in 10ms units", HFILL }},

    { &hf_ieee80211_prism_did_mactime,
     {"MAC timestamp (lower 32 bits)", "prism.did.mactime", FT_UINT32, BASE_DEC, NULL, 0x0,
      "Lower 32 bits of value in microseconds of the MAC's Time Synchronization Function timer when the first bit of the MPDU arrived at the MAC.", HFILL }},

    { &hf_ieee80211_prism_did_channel,
     {"Channel", "prism.did.channel", FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_rssi,
     {"RSSI", "prism.did.rssi", FT_INT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_sq,
     {"Signal Quality", "prism.did.sq", FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_signal,
     {"Signal", "prism.did.signal", FT_INT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_noise,
     {"Noise", "prism.did.noise", FT_INT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_rate,
     {"Data rate (Mb/s)", "prism.did.rate", FT_UINT32, BASE_CUSTOM, CF_FUNC(prism_rate_base_custom), 0x0,
      "Speed this frame was sent/received at", HFILL }},

    { &hf_ieee80211_prism_did_sig_a1,
     {"SIG_A1", "prism.did.siga1", FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_sig_a2,
     {"SIG_A2", "prism.did.siga2", FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_sig_b,
     {"SIG", "prism.did.sigb", FT_UINT32, BASE_HEX, NULL, 0x0,
     NULL, HFILL}},

    { &hf_ieee80211_prism_did_sig_rate_field,
     {"SIG Field", "prism.did.sigab", FT_NONE, BASE_NONE, 0, 0x0,
      NULL, HFILL}},

    { &hf_ieee80211_prism_did_istx,
     {"IsTX", "prism.did.istx", FT_UINT32, BASE_HEX, VALS(prism_istx_vals), 0x0,
      "Type of packet (RX or TX?)", HFILL }},

    { &hf_ieee80211_prism_did_frmlen,
     {"Frame Length", "prism.did.frmlen", FT_UINT32, BASE_DEC, NULL, 0x0,
      "Length of the following frame in bytes", HFILL }},

    { &hf_ieee80211_prism_did_unknown,
     {"Unknown DID Field", "prism.did.unknown", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
      NULL, HFILL }}
};

static gint *tree_array[] = {
    &ett_prism,
    &ett_prism_did,
    &ett_sig_ab
};

void proto_register_ieee80211_prism(void)
{
    proto_prism = proto_register_protocol("Prism capture header", "Prism",
                                          "prism");
    proto_register_field_array(proto_prism, hf_prism, array_length(hf_prism));
    proto_register_subtree_array(tree_array, array_length(tree_array));

    prism_handle = register_dissector("prism", dissect_prism, proto_prism);
}

void proto_reg_handoff_ieee80211_prism(void)
{
    capture_dissector_handle_t ieee80211_prism_cap_handle;

    dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_PRISM, prism_handle);
    ieee80211_handle = find_dissector_add_dependency("wlan", proto_prism);
    ieee80211_radio_handle = find_dissector_add_dependency("wlan_radio", proto_prism);
    wlancap_handle = find_dissector_add_dependency("wlancap", proto_prism);

    ieee80211_prism_cap_handle = create_capture_dissector_handle(capture_prism, proto_prism);
    capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_PRISM, ieee80211_prism_cap_handle);

    ieee80211_cap_handle = find_capture_dissector("ieee80211");
    wlancap_cap_handle = find_capture_dissector("wlancap");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
