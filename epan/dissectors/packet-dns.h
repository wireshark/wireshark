/* packet-dns.h
 * Definitions for packet disassembly structures and routines used both by
 * DNS and NBNS.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __PACKET_DNS_H__
#define __PACKET_DNS_H__


/* type values  */
#define DNS_T_A              1              /* host address */
#define DNS_T_NS             2              /* authoritative name server */
#define DNS_T_MD             3              /* mail destination (obsolete) */
#define DNS_T_MF             4              /* mail forwarder (obsolete) */
#define DNS_T_CNAME          5              /* canonical name */
#define DNS_T_SOA            6              /* start of authority zone */
#define DNS_T_MB             7              /* mailbox domain name (experimental) */
#define DNS_T_MG             8              /* mail group member (experimental) */
#define DNS_T_MR             9              /* mail rename domain name (experimental) */
#define DNS_T_NULL          10              /* null RR (experimental) */
#define DNS_T_WKS           11              /* well known service */
#define DNS_T_PTR           12              /* domain name pointer */
#define DNS_T_HINFO         13              /* host information */
#define DNS_T_MINFO         14              /* mailbox or mail list information */
#define DNS_T_MX            15              /* mail routing information */
#define DNS_T_TXT           16              /* text strings */
#define DNS_T_RP            17              /* responsible person (RFC 1183) */
#define DNS_T_AFSDB         18              /* AFS data base location (RFC 1183) */
#define DNS_T_X25           19              /* X.25 address (RFC 1183) */
#define DNS_T_ISDN          20              /* ISDN address (RFC 1183) */
#define DNS_T_RT            21              /* route-through (RFC 1183) */
#define DNS_T_NSAP          22              /* OSI NSAP (RFC 1706) */
#define DNS_T_NSAP_PTR      23              /* PTR equivalent for OSI NSAP (RFC 1348 - obsolete) */
#define DNS_T_SIG           24              /* digital signature (RFC 2535) */
#define DNS_T_KEY           25              /* public key (RFC 2535) */
#define DNS_T_PX            26              /* pointer to X.400/RFC822 mapping info (RFC 1664) */
#define DNS_T_GPOS          27              /* geographical position (RFC 1712) */
#define DNS_T_AAAA          28              /* IPv6 address (RFC 1886) */
#define DNS_T_LOC           29              /* geographical location (RFC 1876) */
#define DNS_T_NXT           30              /* "next" name (RFC 2535) */
#define DNS_T_EID           31              /* Endpoint Identifier */
#define DNS_T_NIMLOC        32              /* Nimrod Locator */
#define DNS_T_SRV           33              /* service location (RFC 2052) */
#define DNS_T_ATMA          34              /* ATM Address */
#define DNS_T_NAPTR         35              /* naming authority pointer (RFC 3403) */
#define DNS_T_KX            36              /* Key Exchange (RFC 2230) */
#define DNS_T_CERT          37              /* Certificate (RFC 4398) */
#define DNS_T_A6            38              /* IPv6 address with indirection (RFC 2874 - obsolete) */
#define DNS_T_DNAME         39              /* Non-terminal DNS name redirection (RFC 2672) */
#define DNS_T_SINK          40              /* SINK */
#define DNS_T_OPT           41              /* OPT pseudo-RR (RFC 2671) */
#define DNS_T_APL           42              /* Lists of Address Prefixes (APL RR) (RFC 3123) */
#define DNS_T_DS            43              /* Delegation Signer (RFC 4034) */
#define DNS_T_SSHFP         44              /* Using DNS to Securely Publish SSH Key Fingerprints (RFC 4255) */
#define DNS_T_IPSECKEY      45              /* RFC 4025 */
#define DNS_T_RRSIG         46              /* RFC 4034 */
#define DNS_T_NSEC          47              /* RFC 4034 */
#define DNS_T_DNSKEY        48              /* RFC 4034 */
#define DNS_T_DHCID         49              /* DHCID RR (RFC 4701) */
#define DNS_T_NSEC3         50              /* Next secure hash (RFC 5155) */
#define DNS_T_NSEC3PARAM    51              /* NSEC3 parameters (RFC 5155) */
#define DNS_T_TLSA          52              /* TLSA (RFC 6698) */
#define DNS_T_HIP           55              /* Host Identity Protocol (HIP) RR (RFC 5205) */
#define DNS_T_NINFO         56              /* NINFO */
#define DNS_T_RKEY          57              /* RKEY */
#define DNS_T_TALINK        58              /* Trust Anchor LINK */
#define DNS_T_CDS           59              /* Child DS (RFC7344)*/
#define DNS_T_CDNSKEY       60              /* DNSKEY(s) the Child wants reflected in DS ( [RFC7344])*/
#define DNS_T_OPENPGPKEY    61              /* OPENPGPKEY draft-ietf-dane-openpgpkey-00 */
#define DNS_T_CSYNC         62              /* Child To Parent Synchronization (RFC7477) */
#define DNS_T_ZONEMD        63              /* Message Digest for DNS Zones (RFC8976) */
#define DNS_T_SVCB          64              /* draft-ietf-dnsop-svcb-https-01 */
#define DNS_T_HTTPS         65              /* draft-ietf-dnsop-svcb-https-01 */
#define DNS_T_DSYNC         66              /* draft-ietf-dnsop-generalized-notify */
#define DNS_T_SPF           99              /* SPF RR (RFC 4408) section 3 */
#define DNS_T_UINFO        100              /* [IANA-Reserved] */
#define DNS_T_UID          101              /* [IANA-Reserved] */
#define DNS_T_GID          102              /* [IANA-Reserved] */
#define DNS_T_UNSPEC       103              /* [IANA-Reserved] */
#define DNS_T_NID          104              /* ILNP [RFC6742] */
#define DNS_T_L32          105              /* ILNP [RFC6742] */
#define DNS_T_L64          106              /* ILNP [RFC6742] */
#define DNS_T_LP           107              /* ILNP [RFC6742] */
#define DNS_T_EUI48        108              /* EUI 48 Address (RFC7043) */
#define DNS_T_EUI64        109              /* EUI 64 Address (RFC7043) */
#define DNS_T_TKEY         249              /* Transaction Key (RFC 2930) */
#define DNS_T_TSIG         250              /* Transaction Signature (RFC 2845) */
#define DNS_T_IXFR         251              /* incremental transfer (RFC 1995) */
#define DNS_T_AXFR         252              /* transfer of an entire zone (RFC 5936) */
#define DNS_T_MAILB        253              /* mailbox-related RRs (MB, MG or MR) (RFC 1035) */
#define DNS_T_MAILA        254              /* mail agent RRs (OBSOLETE - see MX) (RFC 1035) */
#define DNS_T_ANY          255              /* A request for all records (RFC 1035) */
#define DNS_T_URI          256              /* URI */
#define DNS_T_CAA          257              /* Certification Authority Authorization (RFC 6844) */
#define DNS_T_AVC          258              /* Application Visibility and Control (Wolfgang_Riedel) */
#define DNS_T_DOA          259              /* Digital Object Architecture (draft-durand-doa-over-dns) */
#define DNS_T_AMTRELAY     260              /* Automatic Multicast Tunneling Relay (RFC8777) */
#define DNS_T_RESINFO      261              /* Resolver Information */
#define DNS_T_WALLET       262              /* Public wallet address */
#define DNS_T_TA         32768              /* DNSSEC Trust Authorities */
#define DNS_T_DLV        32769              /* DNSSEC Lookaside Validation (DLV) DNS Resource Record (RFC 4431) */
#define DNS_T_WINS       65281              /* Microsoft's WINS RR */
#define DNS_T_WINS_R     65282              /* Microsoft's WINS-R RR */
#define DNS_T_XPF        65422              /* XPF draft-bellis-dnsop-xpf */

/* Class values */
#define DNS_C_IN             1              /* the Internet */
#define DNS_C_CS             2              /* CSNET (obsolete) */
#define DNS_C_CH             3              /* CHAOS */
#define DNS_C_HS             4              /* Hesiod */
#define DNS_C_NONE         254              /* none */
#define DNS_C_ANY          255              /* any */

#define DNS_C_QU            (1<<15)         /* High bit is set in queries for unicast queries */
#define DNS_C_FLUSH         (1<<15)         /* High bit is set for MDNS cache flush */

/* Opcodes */
#define DNS_OPCODE_QUERY    0         /* standard query */
#define DNS_OPCODE_IQUERY   1         /* inverse query */
#define DNS_OPCODE_STATUS   2         /* server status request */
#define DNS_OPCODE_NOTIFY   4         /* zone change notification */
#define DNS_OPCODE_UPDATE   5         /* dynamic update */
#define DNS_OPCODE_DSO      6         /* DNS stateful operations */

/* Reply codes */
#define DNS_RCODE_NOERROR    0
#define DNS_RCODE_FORMERR    1
#define DNS_RCODE_SERVFAIL   2
#define DNS_RCODE_NXDOMAIN   3
#define DNS_RCODE_NOTIMPL    4
#define DNS_RCODE_REFUSED    5
#define DNS_RCODE_YXDOMAIN   6
#define DNS_RCODE_YXRRSET    7
#define DNS_RCODE_NXRRSET    8
#define DNS_RCODE_NOTAUTH    9
#define DNS_RCODE_NOTZONE   10
#define DNS_RCODE_DSOTYPENI 11

#define DNS_RCODE_BAD       16
#define DNS_RCODE_BADKEY    17
#define DNS_RCODE_BADTIME   18
#define DNS_RCODE_BADMODE   19
#define DNS_RCODE_BADNAME   20
#define DNS_RCODE_BADALG    21
#define DNS_RCODE_BADTRUNC  22
#define DNS_RCODE_BADCOOKIE 23

WS_DLL_PUBLIC
const value_string dns_classes[];

/*
 * DNS stats/information provided for tapping
 */
typedef struct DnsTap {
    unsigned packet_qr;     // query (0) or response (1)
    unsigned packet_qtype;  // query type (DNS_T_*)
    int packet_qclass;      // query class (DNS_C_*)
    unsigned packet_rcode;  // reply code (DNS_RCODE_*)
    unsigned packet_opcode; // query opcode (DNS_OPCODE_*)
    unsigned payload_size;  // full packet payload size
    unsigned qname_len;     // length of query name
    unsigned qname_labels;  // query name label count
    char* qname;            // query name
    unsigned nquestions;    // number of questions
    unsigned nanswers;      // number of answers
    unsigned nauthorities;  // number of authority records
    unsigned nadditionals;  // number of additional records
    bool unsolicited;       // true if unsolicitated response
    bool retransmission;    // true if retransmitted query
    nstime_t rrt;           // time between query and response
    wmem_list_t *rr_types;  // list of resource record types
    char source[256];       // source of request/response (stringified IPv4 or IPv6 address; "n/a" if unexpected address type)
    char qhost[256];        // host or left-most part of query name
    char qdomain[256];      // domain or remaining part of query name
    unsigned flags;         // raw header flags
} dns_tap_t;

/*
 * Expands DNS name from TVB into a byte string.
 *
 * Returns int: byte size of DNS data.
 * Returns char *name: a dot (.) separated raw string of DNS domain name labels.
 * This string is null terminated. Labels are copied directly from raw packet
 * data without any validation for a string encoding. This is the callers responsibility.
 * Return int name_len: byte length of "name".
 */
WS_DLL_PUBLIC
int get_dns_name(wmem_allocator_t* scope, tvbuff_t *tvb, int offset, int max_len, int dns_data_offset,
    const char **name, int* name_len);


#define MIN_DNAME_LEN    2              /* minimum domain name length */
#define MAX_DNAME_LEN   255             /* maximum domain name length */

#endif /* packet-dns.h */
