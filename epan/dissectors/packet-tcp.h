/* packet-tcp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_TCP_H__
#define __PACKET_TCP_H__

#include "ws_symbol_export.h"

#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* TCP flags */
#define TH_FIN  0x0001
#define TH_SYN  0x0002
#define TH_RST  0x0004
#define TH_PUSH 0x0008
#define TH_ACK  0x0010
#define TH_URG  0x0020
#define TH_ECE  0x0040
#define TH_CWR  0x0080
#define TH_AE   0x0100
#define TH_RES  0x0E00 /* 3 reserved bits */
#define TH_MASK 0x0FFF

#define IS_TH_FIN(x) (x & TH_FIN)
#define IS_TH_URG(x) (x & TH_URG)

/* Idea for gt: either x > y, or y is much bigger (assume wrap) */
#define GT_SEQ(x, y) ((int32_t)((y) - (x)) < 0)
#define LT_SEQ(x, y) ((int32_t)((x) - (y)) < 0)
#define GE_SEQ(x, y) ((int32_t)((y) - (x)) <= 0)
#define LE_SEQ(x, y) ((int32_t)((x) - (y)) <= 0)
#define EQ_SEQ(x, y) (x) == (y)

/* mh as in mptcp header */
struct mptcpheader {

	bool mh_mpc;         /* true if seen an mp_capable option */
	bool mh_join;        /* true if seen an mp_join option */
	bool mh_dss;         /* true if seen a dss */
	bool mh_add;         /* true if seen an MP_ADD */
	bool mh_remove;      /* true if seen an MP_REMOVE */
	bool mh_prio;        /* true if seen an MP_PRIO */
	bool mh_fail;        /* true if seen an MP_FAIL */
	bool mh_fastclose;   /* true if seen a fastclose */
	bool mh_tcprst;      /* true if seen a MP_TCPRST */

	uint8_t mh_capable_flags; /* to get hmac version for instance */
	uint8_t mh_dss_flags; /* data sequence signal flag */
	uint32_t mh_dss_ssn; /* DSS Subflow Sequence Number */
	uint64_t mh_dss_rawdsn; /* DSS Data Sequence Number */
	uint64_t mh_dss_rawack; /* DSS raw data ack */
	uint16_t mh_dss_length;  /* mapping/DSS length */

	uint64_t mh_key; /* Sender key in MP_CAPABLE */
	uint32_t mh_token; /* seen in MP_JOIN. Should be a hash of the initial key */

	uint32_t mh_stream; /* this stream index field is included to help differentiate when address/port pairs are reused */

	/* Data Sequence Number of the current segment. It needs to be computed from previous mappings
	 * and as such is not necessarily set
	 */
	uint64_t mh_rawdsn64;
	/* DSN formatted according to  the wireshark MPTCP options */
	uint64_t mh_dsn;
};

/* the tcp header structure, passed to tap listeners */
typedef struct tcpheader {
	uint32_t th_rawseq;  /* raw value */
	uint32_t th_seq;     /* raw or relative value depending on tcp_relative_seq */

	uint32_t th_rawack;  /* raw value */
	uint32_t th_ack;     /* raw or relative value depending on tcp_relative_seq */
	bool th_have_seglen;	/* true if th_seglen is valid */
	uint32_t th_seglen;  /* in bytes */
	uint32_t th_win;   /* make it 32 bits so we can handle some scaling */
	uint16_t th_sport;
	uint16_t th_dport;
	uint8_t th_hlen;
	bool th_use_ace;
	uint16_t th_flags;
	uint32_t th_stream; /* this stream index field is included to help differentiate when address/port pairs are reused */
	address ip_src;
	address ip_dst;

	/* This is the absolute maximum we could find in TCP options (RFC2018, section 3) */
	#define MAX_TCP_SACK_RANGES 4
	uint8_t num_sack_ranges;
	uint32_t sack_left_edge[MAX_TCP_SACK_RANGES];
	uint32_t sack_right_edge[MAX_TCP_SACK_RANGES];

	/* header for TCP option Multipath Operation */
	struct mptcpheader *th_mptcp;
} tcp_info_t;

/*
 * Private data passed from the TCP dissector to subdissectors.
 * NOTE: This structure is used by Export PDU functionality so
 * make sure that handling is also updated if this structure
 * changes!
 */
struct tcpinfo {
	uint32_t seq;             /* Sequence number of first byte in the data */
	uint32_t nxtseq;          /* Sequence number of first byte after data */
	uint32_t lastackseq;      /* Sequence number of last ack */
	bool    is_reassembled;  /* This is reassembled data. */
	uint16_t flags;           /* TCP flags */
	uint16_t urgent_pointer;  /* Urgent pointer value for the current packet. */
};

/*
 * Loop for dissecting PDUs within a TCP stream; assumes that a PDU
 * consists of a fixed-length chunk of data that contains enough information
 * to determine the length of the PDU, followed by rest of the PDU.
 *
 * The first three arguments are the arguments passed to the dissector
 * that calls this routine.
 *
 * "proto_desegment" is the dissector's flag controlling whether it should
 * desegment PDUs that cross TCP segment boundaries.
 *
 * "fixed_len" is the length of the fixed-length part of the PDU.
 *
 * "get_pdu_len()" is a routine called to get the length of the PDU from
 * the fixed-length part of the PDU; it's passed "pinfo", "tvb", "offset" and
 * "dissector_data".
 *
 * "dissect_pdu()" is the routine to dissect a PDU.
 */
WS_DLL_PUBLIC void
tcp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		 bool proto_desegment, unsigned fixed_len,
		 unsigned (*get_pdu_len)(packet_info *, tvbuff_t *, int, void*),
		 dissector_t dissect_pdu, void* dissector_data);

extern const reassembly_table_functions
tcp_reassembly_table_functions;

extern struct tcp_multisegment_pdu *
pdu_store_sequencenumber_of_next_pdu(packet_info *pinfo, uint32_t seq, uint32_t nxtpdu, wmem_tree_t *multisegment_pdus);

typedef struct _tcp_unacked_t {
	struct _tcp_unacked_t *next;
	uint32_t frame;
	uint32_t	seq;
	uint32_t	nextseq;
	nstime_t ts;
} tcp_unacked_t;

struct tcp_acked {
	uint32_t frame_acked;
	nstime_t ts;

	uint32_t rto_frame;
	nstime_t rto_ts;	/* Time since previous packet for
				   retransmissions. */
	uint16_t flags; /* see TCP_A_* in packet-tcp.c */
	uint32_t dupack_num;	/* dup ack number */
	uint32_t dupack_frame;	/* dup ack to frame # */
	uint32_t bytes_in_flight; /* number of bytes in flight */
	uint32_t push_bytes_sent; /* bytes since the last PSH flag */

	uint32_t new_data_seq; /* For segments with old data,
				 where new data starts */
	bool partial_ack; /* true when acknowledging data
				 and not a full segment */
};

/* One instance of this structure is created for each pdu that spans across
 * multiple tcp segments.
 */
struct tcp_multisegment_pdu {
	uint32_t seq;
	uint32_t nxtpdu;
	uint32_t first_frame;            /* The frame where this MSP was created (used as key in reassembly tables). */
	uint32_t last_frame;
	nstime_t last_frame_time;
	uint32_t first_frame_with_seq;   /* The frame that contains the first frame that matches 'seq'
					   (same as 'first_frame', larger than 'first_frame' for OoO segments) */
	uint32_t flags;
#define MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT	0x00000001
/* Whether this MSP is finished and no more segments can be added. */
#define MSP_FLAGS_GOT_ALL_SEGMENTS		0x00000002
/* Whether the first segment of this MSP was not yet seen. */
#define MSP_FLAGS_MISSING_FIRST_SEGMENT		0x00000004
};


/* Represents the MPTCP DSS option mapping part
 It allows to map relative subflow sequence number (ssn) to global MPTCP sequence numbers
 under their 64 bits form
*/
typedef struct _mptcp_dss_mapping_t {

/* In DSS, SSN are enumerated with relative seq_nb, i.e. starting from 0 */

	uint32_t ssn_low;
	uint32_t ssn_high;

/* Ideally the dsn should always be registered with the extended version
 * but it may not be possible if we don't know the 32 MSB of the base_dsn
 */
	bool extended_dsn; /* true if MPTCP_DSS_FLAG_DATA_8BYTES */

	uint64_t rawdsn;    /* matches the low member of range
                    should be converted to the 64 bits version before being registered
                */
/* to check if mapping was sent before or after packet */
uint32_t frame;
} mptcp_dss_mapping_t;


/* Structure used in mptcp meta member 'dsn_map'
 */
typedef struct _mptcp_dsn2packet_mapping_t {
	uint32_t frame;                  /* packet to look into PINFO_FD_NUM */
	struct tcp_analysis* subflow;   /* in order to get statistics */
} mptcp_dsn2packet_mapping_t;


/* Should basically look like a_tcp_flow_t but for mptcp with 64bit sequence number.
The meta is specific to a direction of the communication and aggregates information of
all the subflows
*/
typedef struct _mptcp_meta_flow_t {

	uint8_t static_flags;	/* remember which fields are set */

	/* flags exchanged between hosts during 3WHS. Gives checksum/extensiblity/hmac information */
	uint8_t flags;
	uint64_t base_dsn;	/* first data seq number (used by relative sequence numbers) seen. */
	uint64_t nextseq;	/* highest seen nextseq */
	uint64_t dfin;		/* data fin */

	uint8_t version;		/* negotiated mptcp version */

	uint64_t key;		/* if it was set */

	/* expected token sha1 digest of keys, truncated to 32 most significant bits
	 derived from key. Stored to speed up subflow/MPTCP connection mapping */
	uint32_t token;

	uint32_t nextseqframe;	/* frame number for segment with highest sequence number */

	/* highest seen continuous seq number (without hole in the stream)  */
	uint64_t maxseqtobeacked;

	uint64_t fin;		/* frame number of the final dataFIN */

	/* first addresses registered */
	address ip_src;
	address ip_dst;
	uint32_t sport;
	uint32_t dport;
} mptcp_meta_flow_t;

/* MPTCP data specific to this subflow direction */
struct mptcp_subflow {
	uint8_t static_flags; /* flags stating which of the flow */
	uint32_t nonce;       /* used only for MP_JOIN */
	uint8_t address_id;   /* sent during an MP_JOIN */


	/* map DSN to packets
	 * Used when looking for reinjections across subflows
	 */
	wmem_itree_t *dsn2packet_map;

	/* Map SSN to a DSS mappings
	 * a DSS can map DSN to SSNs possibily over several packets,
	 * hence some packets may have been mapped by previous DSS,
	 * whence the necessity to be able to look for SSN -> DSN */
	wmem_itree_t *ssn2dsn_mappings;
	/* meta flow to which it is attached. Helps setting forward and backward meta flow */
	mptcp_meta_flow_t *meta;
};


typedef enum {
	MPTCP_HMAC_NOT_SET = 0,
	/* this is either SHA1 for MPTCP v0 or sha256 for MPTCP v1 */
	MPTCP_HMAC_SHA = 1,
	MPTCP_HMAC_LAST
} mptcp_hmac_algorithm_t;


#define MPTCP_CAPABLE_CRYPTO_MASK           0x3F

#define MPTCP_CHECKSUM_MASK                 0x80

/* Information in a flow that is only used when tcp_analyze_seq preference
 * is enabled, so save the memory when it isn't
 */
typedef struct tcp_analyze_seq_flow_info_t {
	tcp_unacked_t *segments;/* List of segments for which we haven't seen an ACK */
	uint16_t segment_count;	/* How many unacked segments we're currently storing */
	uint32_t lastack;	/* Last seen ack for the reverse flow */
	nstime_t lastacktime;	/* Time of the last ack packet */
	uint32_t lastnondupack;	/* frame number of last seen non dupack */
	uint32_t dupacknum;	/* dupack number */
	uint32_t nextseq;	/* highest seen nextseq */
	uint32_t maxseqtobeacked;/* highest seen continuous seq number (without hole in the stream) from the fwd party,
				 * this is the maximum seq number that can be acked by the rev party in normal case.
				 * If the rev party sends an ACK beyond this seq number it indicates TCP_A_ACK_LOST_PACKET condition */
	uint32_t nextseqframe;	/* frame number for segment with highest
				 * sequence number
				 */
	nstime_t nextseqtime;	/* Time of the nextseq packet so we can
				 * distinguish between retransmission,
				 * fast retransmissions and outoforder
				 */

	uint8_t lastacklen;     /* length of the last fwd ACK packet - 0 means pure ACK */

	/*
	 * Handling of SACK blocks
	 * Copied from tcpheader
	 */
	uint8_t num_sack_ranges;
	uint32_t sack_left_edge[MAX_TCP_SACK_RANGES];
	uint32_t sack_right_edge[MAX_TCP_SACK_RANGES];

} tcp_analyze_seq_flow_info_t;

	/* Process info, currently discovered via IPFIX */
typedef struct tcp_process_info_t {
	uint32_t process_uid;	/* UID of local process */
	uint32_t process_pid;	/* PID of local process */
	char   *username;		/* Username of the local process */
	char   *command;		/* Local process name + path + args */

} tcp_process_info_t;

typedef struct _tcp_flow_t {
	uint8_t static_flags; /* true if base seq set */
	uint32_t base_seq;	/* base seq number (used by relative sequence numbers)*/
#define TCP_MAX_UNACKED_SEGMENTS 10000 /* The most unacked segments we'll store */
	uint32_t fin;		/* frame number of the final FIN */
	uint32_t window;		/* last seen window */
	int16_t	win_scale;	/* -1 is we don't know, -2 is window scaling is not used */
	int16_t scps_capable;   /* flow advertised scps capabilities */
	uint16_t maxsizeacked;   /* 0 if not yet known */
	bool valid_bif;     /* if lost pkts, disable BiF until ACK is recvd */
	uint32_t push_bytes_sent; /* bytes since the last PSH flag */
	bool push_set_last; /* tracking last time PSH flag was set */
	uint8_t mp_operations; /* tracking of the MPTCP operations */
	bool is_first_ack;  /* indicates if this is the first ACK */
	bool closing_initiator; /* tracking who is responsible of the connection end */

	tcp_analyze_seq_flow_info_t* tcp_analyze_seq_info;

/* This tcp flow/session contains only one single PDU and should
 * be reassembled until the final FIN segment.
 */
#define TCP_FLOW_REASSEMBLE_UNTIL_FIN	0x0001
	uint16_t flags;

	/* see TCP_A_* in packet-tcp.c */
	uint32_t lastsegmentflags;

	/* The next (largest) sequence number after all segments seen so far.
	 * Valid only on the first pass and used to handle out-of-order segments
	 * during reassembly. */
	uint32_t maxnextseq;

	/* The number of data flows seen in that direction */
	uint16_t flow_count;

	/* This tree is indexed by sequence number and keeps track of all
	 * all pdus spanning multiple segments for this flow.
	 */
	wmem_tree_t *multisegment_pdus;

	/* A sorted list of pending out-of-order segments. */
	wmem_list_t *ooo_segments;

	/* Process info, currently discovered via IPFIX */
	tcp_process_info_t* process_info;

	/* MPTCP subflow intel */
	struct mptcp_subflow *mptcp_subflow;
} tcp_flow_t;

/* Stores common information between both hosts of the MPTCP connection*/
struct mptcp_analysis {

	uint16_t mp_flags; /* MPTCP meta analysis related, see MPTCP_META_* in packet-tcp.c */

	/*
	 * For other subflows, they link the meta via mptcp_subflow_t::meta_flow
	 * according to the validity of the token.
	 */
	mptcp_meta_flow_t meta_flow[2];

	uint32_t stream; /* Keep track of unique mptcp stream (per MP_CAPABLE handshake) */
	uint8_t hmac_algo;  /* hmac decided after negotiation */
	wmem_list_t* subflows;	/* List of subflows (tcp_analysis) */

	/* identifier of the tcp stream that saw the initial 3WHS with MP_CAPABLE option */
	struct tcp_analysis *master;

	/* Keep track of the last TCP operations seen in order to avoid false DUP ACKs */
	uint8_t mp_operations;
};

struct tcp_analysis {
	/* These two structs are managed based on comparing the source
	 * and destination addresses and, if they're equal, comparing
	 * the source and destination ports.
	 *
	 * If the source is greater than the destination, then stuff
	 * sent from src is in ual1.
	 *
	 * If the source is less than the destination, then stuff
	 * sent from src is in ual2.
	 *
	 * XXX - if the addresses and ports are equal, we don't guarantee
	 * the behavior.
	 */
	tcp_flow_t	flow1;
	tcp_flow_t	flow2;

	/* These pointers are set by get_tcp_conversation_data()
	 * fwd point in the same direction as the current packet
	 * and rev in the reverse direction
	 */
	tcp_flow_t	*fwd;
	tcp_flow_t	*rev;

	/* This pointer is NULL   or points to a tcp_acked struct if this
	 * packet has "interesting" properties such as being a KeepAlive or
	 * similar
	 */
	struct tcp_acked *ta;
	/* This structure contains a tree containing all the various ta's
	 * keyed by frame number.
	 */
	wmem_tree_t	*acked_table;

	/* Remember the timestamp of the first frame seen in this tcp
	 * conversation to be able to calculate a relative time compared
	 * to the start of this conversation
	 */
	nstime_t	ts_first;

        /* Remember the timestamp of the most recent SYN in this conversation in
         * order to calculate the first_rtt below. Not necessarily ts_first, if
         * the SYN is retransmitted. */
	nstime_t	ts_mru_syn;

        /* If we have the handshake, remember the RTT between the initial SYN
         * and ACK for use detecting out-of-order segments. */
	nstime_t	ts_first_rtt;

	/* Remember the timestamp of the frame that was last seen in this
	 * tcp conversation to be able to calculate a delta time compared
	 * to previous frame in this conversation
	 */
	nstime_t	ts_prev;

	/* Keep track of tcp stream numbers instead of using the conversation
	 * index (as how it was done before). This prevents gaps in the
	 * stream index numbering
	 */
	uint32_t        stream;

	/* Keep track of packet number within the TCP stream */
	uint32_t        pnum;

	/* Remembers the server port on the SYN (or SYN|ACK) packet to
	 * help determine which dissector to call
	 */
	uint16_t server_port;

	/* Set when the client sends a SYN with data and the cookie in the Fast Open
	 * option.
	 */
	uint8_t tfo_syn_data : 1;

	/* Remembers which side is currently sending data. */
	int8_t flow_direction : 2;

	/* allocated only when mptcp enabled
	 * several tcp_analysis may refer to the same mptcp_analysis
	 * can exist without any meta
	 */
	struct mptcp_analysis* mptcp_analysis;

	/* Track the TCP conversation completeness, as the capture might
	 * contain all parts of a TCP flow (establishment, data, clearing) or
	 * just some parts if we jumped on the bandwagon of an already established
	 * connection or left before it was terminated explicitly
	 */
	uint8_t         conversation_completeness;

	/* Stores the value as a String to be displayed in the appropriate field */
	char            *conversation_completeness_str;

	/* Track AccECN support */
	bool had_acc_ecn_setup_syn;
	bool had_acc_ecn_setup_syn_ack;
	bool had_acc_ecn_option;
};

/* Structure that keeps per packet data. First used to be able
 * to calculate the time_delta from the last seen frame in this
 * TCP conversation. Can be extended for future use.
 */
struct tcp_per_packet_data_t {
	nstime_t	ts_del;
	uint32_t        pnum;
	uint8_t		tcp_snd_manual_analysis;
};

/* Structure that keeps per packet data. Some operations are cpu-intensive and are
 * best cached into this structure
 */
typedef struct mptcp_per_packet_data_t_ {

	/* Mapping that covers this packet content */
	mptcp_dss_mapping_t *mapping;

} mptcp_per_packet_data_t;


WS_DLL_PUBLIC void dissect_tcp_payload(tvbuff_t *tvb, packet_info *pinfo, int offset,
				uint32_t seq, uint32_t nxtseq, uint32_t sport,
				uint32_t dport, proto_tree *tree,
				proto_tree *tcp_tree,
				struct tcp_analysis *tcpd, struct tcpinfo *tcpinfo);

WS_DLL_PUBLIC struct tcp_analysis *get_tcp_conversation_data(conversation_t *conv,
                                packet_info *pinfo);

/** Same as get_tcp_conversation_data(), without updating any data at all. Thus,
 *  it really identifies the conversation data and doesn't do anything with it.
 *
 */
WS_DLL_PUBLIC struct tcp_analysis *get_tcp_conversation_data_idempotent(conversation_t *conv);

WS_DLL_PUBLIC bool decode_tcp_ports(tvbuff_t *, int, packet_info *, proto_tree *, int, int, struct tcp_analysis *, struct tcpinfo *);

/** Associate process information with a given flow
 *
 * @param frame_num The frame number
 * @param local_addr The local IPv4 or IPv6 address of the process
 * @param remote_addr The remote IPv4 or IPv6 address of the process
 * @param local_port The local TCP port of the process
 * @param remote_port The remote TCP port of the process
 * @param uid The numeric user ID of the process
 * @param pid The numeric PID of the process
 * @param username Ephemeral string containing the full or partial process name
 * @param command Ephemeral string containing the full or partial process name
 */
extern void add_tcp_process_info(uint32_t frame_num, address *local_addr, address *remote_addr, uint16_t local_port, uint16_t remote_port, uint32_t uid, uint32_t pid, char *username, char *command);

/** Get the current number of TCP streams
 *
 * @return The number of TCP streams
 */
WS_DLL_PUBLIC uint32_t get_tcp_stream_count(void);

/** Get the current number of MPTCP streams
 *
 * @return The number of MPTCP streams
 */
WS_DLL_PUBLIC uint32_t get_mptcp_stream_count(void);

/* Follow Stream functionality shared with HTTP (and SSL?) */
extern char *tcp_follow_conv_filter(epan_dissect_t *edt, packet_info *pinfo, unsigned *stream, unsigned *sub_stream);
extern char *tcp_follow_index_filter(unsigned stream, unsigned sub_stream);
extern char *tcp_follow_address_filter(address *src_addr, address *dst_addr, int src_port, int dst_port);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
