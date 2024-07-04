/** @file
 *
 * Definitions for exported_pdu TLVs
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORTED_PDU_TLVS_H
#define EXPORTED_PDU_TLVS_H

/**
 * This is the format of the link-layer header of packets of type
 * LINKTYPE_WIRESHARK_UPPER_PDU in pcap and pcapng files.
 *
 * It is a sequence of TLVs; at least one TLV MUST indicate what protocol is
 * in the PDU following the TLVs.
 *
 * Each TLV contains, in order:
 *
 *    a 2-byte big-endian type field;
 *    a 2-byte big-endian length field;
 *    a value, the length of which is indicated by the value of
 *      the length field (that value does not include the length
 *      of the type or length fields themselves).
 *
 * Buffer layout:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Option Code              |         Option Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                       Option Value                            /
 * /             variable length, aligned to 32 bits               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /                 . . . other options . . .                     /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Option Code == opt_endofopt  |  Option Length == 0          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The list of TLVs may begin with a TLV of type EXP_PDU_TAG_OPTIONS_LENGTH;
 * its value is a 4-byte integer value, giving the length of all TLVs
 * following that TLV (i.e., the length does not include the length of
 * the EXP_PDU_TAG_OPTIONS_LENGTH TLV). This tag is deprecated; it is
 * not guaranteed to be present, and code reading packets should not
 * require it to be present.
 *
 * The last TLV is of type EXP_PDU_TAG_END_OF_OPT; it has a length
 * of 0, and the value is zero-length.
 *
 * For string values, a string may have zero, one, or more null bytes
 * at the end; code that reads the string value must not assume that
 * there are, or are not, null bytes at the end.  Null bytes are included
 * in the length field, but are not part of the string value.
 *
 * For integral values, the values are in big-endian format.
 */

/*  Tag values
 *
 *  Do NOT add new values to this list without asking
 *  wireshark-dev[AT]wireshark.org for a value. Otherwise, you run the risk of
 *  using a value that's already being used for some other purpose, and of
 *  having tools that read exported_pdu captures not being able to handle
 *  captures with your new tag value, with no hope that they will ever be
 *  changed to do so (as that would destroy their ability to read captures
 *  using that value for that other purpose).
 */
#define EXP_PDU_TAG_END_OF_OPT            0 /**< End-of-options Tag. */
/* 1 - 9 reserved */
#define EXP_PDU_TAG_OPTIONS_LENGTH       10 /**< Total length of the options excluding this TLV
                                             * Deprecated - do not use
                                             */
#define EXP_PDU_TAG_LINKTYPE             11 /**< Deprecated - do not use */
#define EXP_PDU_TAG_DISSECTOR_NAME       12 /**< The value part should be an ASCII non NULL terminated string
                                             * of the registered dissector used by Wireshark e.g "sip"
                                             * Will be used to call the next dissector.
                                             * NOTE: this is NOT a protocol name;
                                             * a given protocol may have multiple
                                             * dissectors, if, for example, the
                                             * protocol headers depend on the
                                             * protocol being used to transport
                                             * the protocol in question.
                                             */
#define EXP_PDU_TAG_HEUR_DISSECTOR_NAME  13 /**< The value part should be an ASCII non NULL terminated string
                                          * containing the heuristic dissector unique short name given
                                          * during registration, e.g "sip_udp"
                                          * Will be used to call the next dissector.
                                          */
#define EXP_PDU_TAG_DISSECTOR_TABLE_NAME 14 /**< The value part should be an ASCII non NULL terminated string
                                          * containing the dissector table name given
                                          * during registration, e.g "gsm_map.v3.arg.opcode"
                                          * Will be used to call the next dissector.
                                          */

/* For backwards source compatibility */
#define EXP_PDU_TAG_PROTO_NAME           EXP_PDU_TAG_DISSECTOR_NAME
#define EXP_PDU_TAG_HEUR_PROTO_NAME      EXP_PDU_TAG_HEUR_DISSECTOR_NAME

/* Add protocol type related tags here.
 * NOTE Only one protocol type tag may be present in a packet, the first one
 * found will be used*/
/* 13 - 19 reserved */
#define EXP_PDU_TAG_IPV4_SRC        20  /**< IPv4 source address - 4 bytes */
#define EXP_PDU_TAG_IPV4_DST        21  /**< IPv4 destination address - 4 bytes */
#define EXP_PDU_TAG_IPV6_SRC        22  /**< IPv6 source address - 16 bytes */
#define EXP_PDU_TAG_IPV6_DST        23  /**< IPv6 destination address - 16 bytes */

/* Port type values for EXP_PDU_TAG_PORT_TYPE; these do not necessarily
 * correspond to port type values inside libwireshark. */
#define EXP_PDU_PT_NONE         0
#define EXP_PDU_PT_SCTP         1
#define EXP_PDU_PT_TCP          2
#define EXP_PDU_PT_UDP          3
#define EXP_PDU_PT_DCCP         4
#define EXP_PDU_PT_IPX          5
#define EXP_PDU_PT_NCP          6
#define EXP_PDU_PT_EXCHG        7
#define EXP_PDU_PT_DDP          8
#define EXP_PDU_PT_SBCCS        9
#define EXP_PDU_PT_IDP          10
#define EXP_PDU_PT_TIPC         11
#define EXP_PDU_PT_USB          12
#define EXP_PDU_PT_I2C          13
#define EXP_PDU_PT_IBQP         14
#define EXP_PDU_PT_BLUETOOTH    15
#define EXP_PDU_PT_TDMOP        16
#define EXP_PDU_PT_IWARP_MPA    17
#define EXP_PDU_PT_MCTP         18

#define EXP_PDU_TAG_PORT_TYPE       24  /**< part type - 4 bytes, EXP_PDU_PT value */
#define EXP_PDU_TAG_SRC_PORT        25  /**< source port - 4 bytes (even for protocols with 2-byte ports) */
#define EXP_PDU_TAG_DST_PORT        26  /**< destination port - 4 bytes (even for protocols with 2-byte ports) */

#define EXP_PDU_TAG_SS7_OPC         28
#define EXP_PDU_TAG_SS7_DPC         29

#define EXP_PDU_TAG_ORIG_FNO        30

#define EXP_PDU_TAG_DVBCI_EVT       31

#define EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL 32 /**< value part is the numeric value to be used calling the dissector table
                                                      *  given with tag EXP_PDU_TAG_DISSECTOR_TABLE_NAME, must follow immediately after the table tag.
                                                      */

#define EXP_PDU_TAG_COL_PROT_TEXT   33 /**< UTF-8 text string to put in COL_PROTOCOL, one use case is in conjunction with dissector tables where
                                        *   COL_PROTOCOL might not be filled in.
                                        */


/**< value part is structure passed into TCP subdissectors.  The field
    begins with a 2-byte version number; if the version number value is
    1, the value part is in the form:

    version          2 bytes - xport PDU version of structure (for backwards/forwards compatibility)
    seq              4 bytes - Sequence number of first byte in the data
    nxtseq           4 bytes - Sequence number of first byte after data
    lastackseq       4 bytes - Sequence number of last ack
    is_reassembled   1 byte - Non-zero if this is reassembled data
    flags            2 bytes - TCP flags
    urgent_pointer   2 bytes - Urgent pointer value for the current packet

  All multi-byte values are in big-endian format.  There is no alignment
  padding between values, so seq. nxtseq, and lastackseq are not aligned
  on 4-byte boundaries, andflags and urgent_pointer are not aligned on
  2-byte boundaries.
*/
#define EXP_PDU_TAG_TCP_INFO_DATA  34

#define EXP_PDU_TAG_P2P_DIRECTION  35  /**< The packet direction (P2P_DIR_SENT, P2P_DIR_RECV). */

#define EXP_PDU_TAG_COL_INFO_TEXT  36 /**< UTF-8 text string to put in COL_INFO, useful when putting meta data into the packet list.
                                        */

#define EXP_PDU_TAG_USER_DATA_PDU  37 /**< Raw user data PDU which can be dissected as any protocol. */

/* 3GPP identity types for EXP_PDU_TAG_3GPP_ID */
#define EXP_PDU_3GPP_ID_CGI     0 /**< 56-bit 2G/3G Cell Global Identifier (MNC big-endian encoding) */
#define EXP_PDU_3GPP_ID_ECGI    1 /**< 52-bit 4G E-UTRAN Cell Global Identifier (MNC big-endian encoding) */
#define EXP_PDU_3GPP_ID_NCGI    2 /**< 60-bit NR Cell Global Identifier (MNC big-endian encoding) */

/**< Stores a 3GPP identifier.
    The value begins with a 1-byte identity type (EXP_PDU_3GPP_ID_*),
    followed by the identity itself.
*/
#define EXP_PDU_TAG_3GPP_ID   38

#define EXP_PDU_TAG_IPV4_LEN            4
#define EXP_PDU_TAG_IPV6_LEN            16

#define EXP_PDU_TAG_PORT_TYPE_LEN       4
#define EXP_PDU_TAG_PORT_LEN            4

#define EXP_PDU_TAG_SS7_OPC_LEN         8 /* 4 bytes PC, 2 bytes standard type, 1 byte NI, 1 byte padding */
#define EXP_PDU_TAG_SS7_DPC_LEN         8 /* 4 bytes PC, 2 bytes standard type, 1 byte NI, 1 byte padding */

#define EXP_PDU_TAG_ORIG_FNO_LEN        4

#define EXP_PDU_TAG_DVBCI_EVT_LEN       1

#define EXP_PDU_TAG_DISSECTOR_TABLE_NUM_VAL_LEN     4

#endif /* EXPORTED_PDU_TLVS_H */
