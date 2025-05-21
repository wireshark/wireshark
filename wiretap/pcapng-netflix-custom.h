/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WTAP_PCAPNG_NETFLIX_CUSTOM_H
#define WTAP_PCAPNG_NETFLIX_CUSTOM_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Netflix custom blocks and options.
 *
 * https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
 */
#define PEN_NFLX 10949

typedef struct nflx_custom_opt_s {
    uint32_t nflx_type2;
    size_t nflx_custom_data_len;
    char *nflx_custom_data;
} nflx_custom_opt_t;

#define NFLX_OPT_TYPE_VERSION    1
#define NFLX_OPT_TYPE_TCPINFO    2
#define NFLX_OPT_TYPE_DUMPINFO   4
#define NFLX_OPT_TYPE_DUMPTIME   5
#define NFLX_OPT_TYPE_STACKNAME  6

/* Flags used in tlb_eventflags */
#define NFLX_TLB_FLAG_RXBUF     0x0001 /* Includes receive buffer info */
#define NFLX_TLB_FLAG_TXBUF     0x0002 /* Includes send buffer info */
#define NFLX_TLB_FLAG_HDR       0x0004 /* Includes a TCP header */
#define NFLX_TLB_FLAG_VERBOSE   0x0008 /* Includes function/line numbers */
#define NFLX_TLB_FLAG_STACKINFO 0x0010 /* Includes stack-specific info */

/* Flags used in tlb_flags */
#define NFLX_TLB_TF_REQ_SCALE   0x00000020 /* Sent WS option */
#define NFLX_TLB_TF_RCVD_SCALE  0x00000040 /* Received WS option */

/* Values of tlb_state */
#define NFLX_TLB_TCPS_ESTABLISHED 4
#define NFLX_TLB_IS_SYNCHRONIZED(state) (state >= NFLX_TLB_TCPS_ESTABLISHED)

/*
 * DO NOT USE sizeof (struct nflx_tcpinfo) AS THE SIZE OF THE CUSTOM
 * OPTION DATA FOLLOWING THE TYPE. This structure has 64-bit integral
 * type values in it, but the sum of the sizes of the elements plus
 * internal padding is *not* a multiple of 8, so, on a platform
 * on which 64-bit integral type values are aligned on an 8-byte
 * boundary - i.e., on all 64-bit platforms on which we run,
 * probably meaning on the majority of machines on which Wireshark
 * is run these days, especially given that we don't support 32-bit
 * Windows or macOS any more - it will have 4 bytes of unnamed padding
 * at the end.
 *
 * The custom option data in capture files does *not* necessarily include
 * the unnamed padding.
 */
#define OPT_NFLX_TCPINFO_SIZE 268U

struct nflx_tcpinfo {
    uint64_t tlb_tv_sec;
    uint64_t tlb_tv_usec;
    uint32_t tlb_ticks;
    uint32_t tlb_sn;
    uint8_t  tlb_stackid;
    uint8_t  tlb_eventid;
    uint16_t tlb_eventflags;
    int32_t  tlb_errno;
    uint32_t tlb_rxbuf_tls_sb_acc;
    uint32_t tlb_rxbuf_tls_sb_ccc;
    uint32_t tlb_rxbuf_tls_sb_spare;
    uint32_t tlb_txbuf_tls_sb_acc;
    uint32_t tlb_txbuf_tls_sb_ccc;
    uint32_t tlb_txbuf_tls_sb_spare;
    int32_t  tlb_state;
    uint32_t tlb_starttime;
    uint32_t tlb_iss;
    uint32_t tlb_flags;
    uint32_t tlb_snd_una;
    uint32_t tlb_snd_max;
    uint32_t tlb_snd_cwnd;
    uint32_t tlb_snd_nxt;
    uint32_t tlb_snd_recover;
    uint32_t tlb_snd_wnd;
    uint32_t tlb_snd_ssthresh;
    uint32_t tlb_srtt;
    uint32_t tlb_rttvar;
    uint32_t tlb_rcv_up;
    uint32_t tlb_rcv_adv;
    uint32_t tlb_flags2;
    uint32_t tlb_rcv_nxt;
    uint32_t tlb_rcv_wnd;
    uint32_t tlb_dupacks;
    int32_t  tlb_segqlen;
    int32_t  tlb_snd_numholes;
    uint32_t tlb_flex1;
    uint32_t tlb_flex2;
    uint32_t tlb_fbyte_in;
    uint32_t tlb_fbyte_out;
    uint8_t  tlb_snd_scale:4,
            tlb_rcv_scale:4;
    uint8_t  _pad[3];

    /* The following fields might become part of a union */
    uint64_t tlb_stackinfo_bbr_cur_del_rate;
    uint64_t tlb_stackinfo_bbr_delRate;
    uint64_t tlb_stackinfo_bbr_rttProp;
    uint64_t tlb_stackinfo_bbr_bw_inuse;
    uint32_t tlb_stackinfo_bbr_inflight;
    uint32_t tlb_stackinfo_bbr_applimited;
    uint32_t tlb_stackinfo_bbr_delivered;
    uint32_t tlb_stackinfo_bbr_timeStamp;
    uint32_t tlb_stackinfo_bbr_epoch;
    uint32_t tlb_stackinfo_bbr_lt_epoch;
    uint32_t tlb_stackinfo_bbr_pkts_out;
    uint32_t tlb_stackinfo_bbr_flex1;
    uint32_t tlb_stackinfo_bbr_flex2;
    uint32_t tlb_stackinfo_bbr_flex3;
    uint32_t tlb_stackinfo_bbr_flex4;
    uint32_t tlb_stackinfo_bbr_flex5;
    uint32_t tlb_stackinfo_bbr_flex6;
    uint32_t tlb_stackinfo_bbr_lost;
    uint16_t tlb_stackinfo_bbr_pacing_gain;
    uint16_t tlb_stackinfo_bbr_cwnd_gain;
    uint16_t tlb_stackinfo_bbr_flex7;
    uint8_t  tlb_stackinfo_bbr_bbr_state;
    uint8_t  tlb_stackinfo_bbr_bbr_substate;
    uint8_t  tlb_stackinfo_bbr_inhpts;
    uint8_t  tlb_stackinfo_bbr_ininput;
    uint8_t  tlb_stackinfo_bbr_use_lt_bw;
    uint8_t  tlb_stackinfo_bbr_flex8;
    uint32_t tlb_stackinfo_bbr_pkt_epoch;

    uint32_t tlb_len;
};

/*
 * This is 208 bytes long, and that's a multiple of 8, so the padding
 * problem that struct nflx_tcpinfo has doesn't appear here.
 */
struct nflx_dumpinfo {
    uint32_t tlh_version;
    uint32_t tlh_type;
    uint64_t tlh_length;
    uint16_t tlh_ie_fport;
    uint16_t tlh_ie_lport;
    uint32_t tlh_ie_faddr_addr32[4];
    uint32_t tlh_ie_laddr_addr32[4];
    uint32_t  tlh_ie_zoneid;
    uint64_t tlh_offset_tv_sec;
    uint64_t tlh_offset_tv_usec;
    char    tlh_id[64];
    char    tlh_reason[32];
    char    tlh_tag[32];
    uint8_t  tlh_af;
    uint8_t  _pad[7];
};

/** Add an NFLX custom option to a block
 *
 * @param[in] block Block to which to add the option
 * @param[in] nflx_type NFLX option type
 * @param[in] nflx_custom_data pointer to the data
 * @param[in] nflx_custom_data_len length of custom_data
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_add_nflx_custom_option(wtap_block_t block, uint32_t nflx_type, const char *nflx_custom_data, size_t nflx_custom_data_len);

/** Get an NFLX custom option value from a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] nflx_type type of the option
 * @param[out] nflx_custom_data Returned value of NFLX custom option value
 * @param[in] nflx_custom_data_len size of buffer provided in nflx_custom_data
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_nflx_custom_option(wtap_block_t block, uint32_t nflx_type, char *nflx_custom_data, size_t nflx_custom_data_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* WTAP_PCAPNG_NETFLIX_CUSTOM_H */
