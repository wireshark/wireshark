/* packet-f5ethtrailer.c
 *
 * F5 Ethernet Trailer Copyright 2008-2018 F5 Networks
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
Supported Platforms:
    BIGIP 9.4.2 and later for the trailer, BIGIP 11.2.0 and later for fileinfo

Usage:

  * Acquire capture files using the following command line:
    * tcpdump -w capture.pcap -s0 -i internal:nnn
  * Load the capture file into wireshark.

  * Observe the grammar added to the beginning of each packet in the "Info"
    column of the packet list pane.
  * Observe the added "F5 Ethernet trailer" section in the packet detail
    pane.
  * These fields are filterable like any other field.
  * Review the preferences for the dissector.

  * If you are missing the Low details of the trailer for some packets, try
    modifying the settings for the Ethernet dissector.  Go to "Edit/Preferences...",
    expand "Protocols" on the left and select "Ethernet".  Disable "Assume
    short frames which include a trailer contain padding".

Notes:

  Follow F5 Conversation:

    As an alternative to the Populate Fields for Other Dissectors below, you
    can now follow a connection through the BIG-IP using the main menu
    Analyze/Conversation Filter menu.  There are three options: follow "F5 IP",
    "F5 TCP" or "F5 UDP".  Select a frame and choose the appropriate menu item.
    For best results, disable Populate Fields for Other Dissectors.  This
    method of following a conversation should avoid the stray packets problem
    mentioned below.

    These menu selections will populate an appropriate filter expression with
    ip.addr, tcp.port or udp.port, f5ethtrailer.peeraddr, f5ethtrailer.peerport
    and f5ethtrailer.peeripproto.

    You will need to have gathered the capture with high noise (":nnn") to
    contain the peer flow information in order for this to work.

  Populate Fields for Other Dissectors:

    The populate fields for other dissectors will add hidden fields to the
    f5ethtrailer for "ip.addr", "ipv6.addr", "tcp.port" and "udp.port" based on
    information in high noise of a packet.  This will allow the "Conversation
    Filter" option in Wireshark to find both the client-side and server-side
    flows for a connection.

    In order to use this, you will need to enable the "Populate fields for
    other dissectors" preference.  Note that the fields are registered when the
    preference is enabled.  After changing the preference, you may need to
    restart Wireshark for proper handling.

    Please note that this may cause some stray packets to show up in filter
    results since, for example, "tcp.port eq A and tcp.port eq B" can now be
    matching on at least four fields (tcp.port from the TCP dissector and
    tcp.port from the f5ethtrailer dissector) and a filter can match on an
    address/port from the IP/TCP/UDP dissector or an address/port from the
    f5ethtrailer dissector.

    For example, given two connections:
      client:12345 <-> VIP:443 {BIGIP} clientS:12346 <-> poolmember:80
      client:12346 <-> VIP:443 {BIGIP} clientS:12347 <-> poolmember:80
    Selecting "Conversation Filter->TCP" on the client side of the second
    connection will result in a filter of:
      ip.addr eq client and ip.addr eq VIP and
      tcp.port eq 12346 and tcp.port eq 443
    All four flows would be displayed by the filter:
      * From client:12345 <-> VIP:443 (unexpected)
        - ip.addr from ip.src matches.
        - ip.addr from ip.dst matches.
        - tcp.port from f5ethtrailer.peerlocalport matches.
        - tcp.port from tcp.dstport matches.
      * From clientS:12346 <-> poolmember:80 (unexpected)
        - ip.addr from f5ethtrailer.peerremoteaddr matches.
        - ip.addr from f5ethtrailer.peerlocaladdr matches.
        - tcp.port from tcp.srcport matches.
        - tcp.port from f5ethtrailer.peerlocalport matches.
      * From client:12346 <-> VIP:443 (expected)
        - ip.addr from ip.src matches.
        - ip.addr from ip.dst matches.
        - tcp.port from tcp.srcport matches.
        - tcp.port from tcp.dstport matches.
      * From clientS:12347 <-> poolmember:80 (desired)
        - ip.addr from f5ethtrailer.peerremoteaddr matches.
        - ip.addr from f5ethtrailer.peerlocaladdr matches.
        - tcp.port from f5ethtrailer.peerremoteport matches.
        - tcp.port from f5ethtrailer.peerlocalport matches.

    You can filter based on IP/port information by disabling the "Populate
    fields for other dissectors" and creating your own filter like:
      ( ip.addr eq client and ip.addr eq VIP and
        tcp.port eq 12346 and tcp.port eq 443 ) or
      ( f5ethtrailer.peeraddr eq client and f5ethtrailer.peeraddr eq VIP and
        f5ethtrailer.peerport eq 12346 and f5ethtrailer.peerport eq 443 )

    Since the preference is disabled by default, it should not cause any
    interference unless the user actively enables the preference.  You can
    remove the option entirely at compile time by defining the compiler macro
    "NO_F5_POP_OTHERFIELDS".

  Analysis:

    The f5ethtrailer dissector can add an "F5 Analysis" subtree to the "F5
    Ethernet trailer" protocol tree.  The items added here are also added to
    Wireshark expert info.  The analysis done is intended to help spot traffic
    anomalies.

    Possible Analysis:
      * Flow reuse or SYN retransmit
        Filter field name: f5ethtrailer.analysis.flowreuse
        This is intended to highlight initial packets that arrive that match
        a pre-existing flow.  In other words, a TCP SYN packet that arrives
        and matches an existing flow.  This can indicate:
        - A prior flow was not properly terminated and a new flow is starting.
        - A stray SYN has arrived for an existing connection.
        - A SYN has been retransmitted (the first SYN would have created the
          flow that subsequent SYNs would match).

      * Flow lost, incorrect VLAN, loose initiation, tunnel or SYN cookie use
        Filter field name: f5ethtrailer.analysis.flowlost
        This is intended to highlight non-initial packets that arrive that
        do not match an existing flow.  In other words, a TCP non-SYN packet
        arriving that does not match an existing flow.  This can indicate:
        - The flow is no longer in the BIGIP's connection table.
        - VLAN keyed connections is in use (the default) and a packet arrived
          on an incorrect VLAN.
        - A stray packet has arrived.
        - The packet may be handled by a virtual server with loose initiation.
          In this case, a packet in the middle of a TCP conversation could
          arrive and then be handled by a virtual server that has loose
          initiation enabled to create a flow.
        - The packet may be the inner payload of a tunnel.  For inbound tunnel
          traffic, the encapsulating packet is shown as well as the
          encapsulated packet (and the encapsulated packet may not have flow
          information).
        - SYN cookies are being used (the initial SYN would not have created
          a flow).

    A few notes.  The analysis is implemented by using Wireshark taps and
    tapping the IP/IPv6/TCP dissectors.  The taps are not called until after
    packet dissection is completely finished.  So, the f5ethtrailer dissector
    may not have the necessary data to draw conclusions.  The traffic light
    in the lower left corner of the Wireshark GUI might not properly reflect
    the existence of these analysis fields.

  Hiding Slot Information in Info Column:

    You can now specify which platforms will display slot information in the
    summary in the info columns.  In the preferences for the F5 Ethernet
    trailer dissector, you can provide a regular expression to match the
    platform in F5 tcpdump header packet.  If there is no platform information
    in the header (or there is no header at all), slot information will always
    be displayed.  A reasonable regular expression would be "^(A.*|Z101)$" to
    match chassis and vCMP platforms (there is no distinction for vCMP on a
    chassis versus an appliance).  The default is to always display slot
    information (no regular expression is provided by default).

  Statistics reports:

    All statistics are reported as packet counts and byte counts.  Byte count
    statistics do not include the bytes of the trailer.

    Statistics menu now has:
      F5/Virtual Server Distribution
        A line for each named virtual server name
        A line for traffic with a flow ID and no virtual server name
        A line for traffic without a flow ID.

      F5/tmm Distribution
        A line for each tmm.
          A line each for ingress and egress (should add to tmm total)
          A line each for (should add to tmm total)
            Traffic with a virtual server name
            Traffic with a flow ID and no virtual server name
            Traffic without a flow ID.
 */


/* A note about the F5_POP_OTHERFIELDS macro:
 *
 * This is used to conditionally compile the population of fields like ip.addr,
 * tcp.port, etc.  There are two points where the conditional compilation macro
 * *must* be used:  The field definitions and the preference definition.  Due
 * to the fact that the default for the pop_other_fields is false, everything
 * else should just take care of itself.  However, for maximum speed, most of
 * the code does not get compiled.
 *
 * You can disable this by defining the NO_F5_POP_OTHERFIELDS macro.
 *
 * I have changed this to on by default because in its current form, if you do
 * not enable it at run time (in the preferences) the fields are not
 * registered, so it's almost like it was never compiled in.  However, adding
 * the ability to remove it if desired for some reason.
 *
 * The preference is still disabled by default, so this should theoretically
 * not be a change for people that have been running without it.
 */

/* Only enable populate othe fields if it has not been requested that it be
 * built without (-DNO_F5_POP_OTHERFIELDS on the compiler command line). */
#ifndef NO_F5_POP_OTHERFIELDS
#define F5_POP_OTHERFIELDS
#endif

#include "config.h"

#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/epan_dissect.h>
#include <epan/ipproto.h>
#include <epan/tap.h>
#include <epan/expert.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/dissector_filters.h>
#include <epan/dissectors/packet-ip.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/etypes.h>
#include <epan/to_str.h>
#include <epan/stats_tree.h>
#define F5FILEINFOTAP_SRC
#include "packet-f5ethtrailer.h"
#undef  F5FILEINFOTAP_SRC

/* Wireshark ID of the F5ETHTRAILER protocol */
static int proto_f5ethtrailer = -1;
static int tap_f5ethtrailer = -1;
static int proto_f5fileinfo = -1;
static int tap_f5fileinfo = -1;
/** Helper dissector for DPT format noise */
static int proto_f5ethtrailer_dpt_noise = -1;

void proto_reg_handoff_f5ethtrailer(void);
void proto_register_f5ethtrailer(void);

void proto_reg_handoff_f5fileinfo(void);
void proto_register_f5fileinfo(void);

/* Common Fields */
static gint hf_provider = -1;
static gint hf_type = -1;
static gint hf_length = -1;
static gint hf_version = -1;
static gint hf_data = -1;
static gint hf_dpt_unknown = -1;
/* Low */
static gint hf_low_id = -1;
static gint hf_ingress = -1;
static gint hf_slot0 = -1;
static gint hf_slot1 = -1;
static gint hf_tmm = -1;
static gint hf_vipnamelen = -1;
static gint hf_vip = -1;
/* Med */
static gint hf_med_id = -1;
static gint hf_flow_id = -1;
static gint hf_peer_id = -1;
static gint hf_any_flow = -1;
static gint hf_cf_flags = -1;
static gint hf_cf_flags2 = -1;
static gint hf_flow_type = -1;
static gint hf_ha_unit = -1;
static gint hf_ingress_slot = -1;
static gint hf_ingress_port = -1;
static gint hf_priority = -1;
static gint hf_rstcause = -1;
static gint hf_rstcause_len = -1;
static gint hf_rstcause_ver = -1;
static gint hf_rstcause_peer = -1;
static gint hf_rstcause_val = -1;
static gint hf_rstcause_line = -1;
static gint hf_rstcause_txt = -1;
/* High */
static gint hf_high_id = -1;
static gint hf_peer_ipproto = -1;
static gint hf_peer_vlan = -1;
static gint hf_peer_remote_addr = -1;
static gint hf_peer_remote_ip6addr = -1;
static gint hf_peer_remote_rtdom = -1;
static gint hf_peer_local_addr = -1;
static gint hf_peer_local_ip6addr = -1;
static gint hf_peer_local_rtdom = -1;
static gint hf_peer_ipaddr = -1;
static gint hf_peer_ip6addr = -1;
static gint hf_peer_rtdom = -1;
static gint hf_peer_remote_port = -1;
static gint hf_peer_local_port = -1;
static gint hf_peer_port = -1;
static gint hf_peer_nopeer = -1;
/* Analysis */
static gint hf_analysis = -1;

#ifdef F5_POP_OTHERFIELDS
static gint hf_ip_ipaddr  = -1;
static gint hf_ip6_ip6addr = -1;
static gint hf_tcp_tcpport = -1;
static gint hf_udp_udpport = -1;
#endif

static gint hf_dpt_magic = -1;
static gint hf_dpt_ver = -1;
static gint hf_dpt_len = -1;

static expert_field ei_f5eth_flowlost = EI_INIT;
static expert_field ei_f5eth_flowreuse = EI_INIT;
static expert_field ei_f5eth_badlen = EI_INIT;

/* These are the ids of the subtrees that we may be creating */
static gint ett_f5ethtrailer          = -1;
static gint ett_f5ethtrailer_unknown  = -1;
static gint ett_f5ethtrailer_low      = -1;
static gint ett_f5ethtrailer_med      = -1;
static gint ett_f5ethtrailer_high     = -1;
static gint ett_f5ethtrailer_rstcause = -1;

/* For fileinformation */
static gint hf_fi_command          = -1;
static gint hf_fi_version          = -1;
static gint hf_fi_hostname         = -1;
static gint hf_fi_platform         = -1;
static gint hf_fi_platformname     = -1;
static gint hf_fi_product          = -1;

/* Wireshark preference to show RST cause in info column */
static gboolean rstcause_in_info = TRUE;
#ifdef F5_POP_OTHERFIELDS
/* Wireshark preference to enable/disable the population of other dissectors'
 * fields.  Only used if built with the F5_POP_OTHERFIELDS macro */
static gboolean pop_other_fields = FALSE;
#endif
/** Wireshark preference to perform analysis */
static gboolean pref_perform_analysis = TRUE;

/** Identifiers for taps (when enabled), only the address is important, the
 * values are unused. */
static gint tap_ip_enabled;
static gint tap_ipv6_enabled;
static gint tap_tcp_enabled;


/** Used "in" and "out" map for the true and false for ingress. (Not actually
 * used in field definition, but rather used to display via a format call
 * and in the info column information.) */
static const true_false_string f5tfs_ing = { "IN", "OUT" };

/** Table containing subdissectors for different providers */
static dissector_table_t provider_subdissector_table;


/*-----------------------------------------------------------------------------------------------*/
/** \brief Convert a Wireshark port type to a IP protocol number.
 *
 *  \attention Not all port types are supported, only the ones that this dissector actively uses.
 *
 *   @param ptype The Wireshark port_type
 *   @return      The IP protocol number corresponding to the port type.
 */
inline static guint8 ptype_to_ipproto(const port_type ptype)
{
	guint8 ipproto = 0;
	switch(ptype) {
		case PT_TCP:
			ipproto = IP_PROTO_TCP;
			break;
		case PT_UDP:
			ipproto = IP_PROTO_UDP;
			break;
		default:
			ipproto = 0;
			break;
	}
	return(ipproto);
} /* ptype_to_ipproto() */


/*===============================================================================================*/
/* Analyze menu functions */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Determines if we can apply an IP Conversation filter.
 *
 *  \attention This is an interface function to be called from the rest of wireshark.
 *
 *   @param pinfo   A pointer to the packet info to look at for the L3 data.
 *   @return        True if it is valid IP/IPv6, false otherwise
 */
static gboolean f5_ip_conv_valid(packet_info *pinfo)
{
	gboolean is_ip  = FALSE;

	proto_get_frame_protocols(pinfo->layers, &is_ip, NULL, NULL, NULL, NULL, NULL, NULL);
	return(is_ip);
} /* f5_ip_conv_valid() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Determines if we can apply a TCP Conversation filter.
 *
 *  \attention This is an interface function to be called from the rest of wireshark.
 *
 *   @param pinfo   A pointer to the packet info to look at for the L3/L4 data.
 *   @return        True if it is valid IP/IPv6 + TCP, false otherwise
 */
static gboolean f5_tcp_conv_valid(packet_info *pinfo)
{
	gboolean is_ip  = FALSE;
	gboolean is_tcp = FALSE;

	proto_get_frame_protocols(pinfo->layers, &is_ip, &is_tcp, NULL, NULL, NULL, NULL, NULL);
	return(is_ip && is_tcp);
} /* f5_tcp_conv_valid() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Determines if we can apply a UDP Conversation filter.
 *
 *  \attention This is an interface function to be called from the rest of wireshark.
 *
 *   @param pinfo   A pointer to the packet info to look at for the L3/L4 data.
 *   @return        True if it is valid IP/IPv6 + UDP, false otherwise
 */
static gboolean f5_udp_conv_valid(packet_info *pinfo)
{
	gboolean is_ip  = FALSE;
	gboolean is_udp = FALSE;

	proto_get_frame_protocols(pinfo->layers, &is_ip, NULL, &is_udp, NULL, NULL, NULL, NULL);
	return(is_ip && is_udp);
} /* f5_tcp_conv_valid() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Calculates the F5 IP conversation filter based on the current packet.
 *
 *  \attention This is an interface function to be called from the rest of wireshark.
 *
 *   @param pinfo   A pointer to the packet info to look at for the L3/L4 data.
 *   @return        A filter string for the F5 IP conversation or NULL if no filter can be
 *                  computed.  The caller should free this string with g_free().
 *
 *  \attention This function uses g_strdup_printf() rather than the wmem equivalent because the
 *             caller (menu_dissector_filter_cb()) uses g_free to free the filter string.
 *             (as of WS 1.12).
 */
static gchar *f5_ip_conv_filter(packet_info *pinfo)
{
	gchar *buf = NULL;
	gchar s_addr[WS_INET6_ADDRSTRLEN];
	gchar d_addr[WS_INET6_ADDRSTRLEN];

	*d_addr = *s_addr = '\0';
	if(pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) {
		address_to_str_buf(&pinfo->src, s_addr, WS_INET6_ADDRSTRLEN);
		address_to_str_buf(&pinfo->dst, d_addr, WS_INET6_ADDRSTRLEN);
		if(*s_addr != '\0' && *d_addr != '\0') {
			buf = g_strdup_printf(
				"(ip.addr eq %s and ip.addr eq %s) or"
				" (f5ethtrailer.peeraddr eq %s and f5ethtrailer.peeraddr eq %s)",
				s_addr, d_addr, s_addr, d_addr);
		}
	} else if(pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6) {
		address_to_str_buf(&pinfo->src, s_addr, WS_INET6_ADDRSTRLEN);
		address_to_str_buf(&pinfo->dst, d_addr, WS_INET6_ADDRSTRLEN);
		if(*s_addr != '\0' && *d_addr != '\0') {
			buf = g_strdup_printf(
				"(ipv6.addr eq %s and ipv6.addr eq %s) or"
				" (f5ethtrailer.peeraddr6 eq %s and f5ethtrailer.peeraddr6 eq %s)",
				s_addr, d_addr, s_addr, d_addr);
		}
	}
	return(buf);
} /* f5_ip_conv_filter() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Calculates the F5 TCP conversation filter based on the current packet.
 *
 *  \attention This is an interface function to be called from the rest of wireshark.
 *
 *   @param pinfo   A pointer to the packet info to look at for the L3/L4 data.
 *   @return        A filter string for the F5 TCP conversation or NULL if no filter can be
 *                  computed.  The caller should free this string with g_free().
 *
 *  Prior to version 11.0.0, the f5ethtrailer.peeripproto field was not populated properly.  In
 *  an effort to accurately match the appropriate protocol, the filter adds:
 *       f5ethtrailer.ipproto eq 6 (for the >=11.0.0 case)
 *    or f5ethtrailer.ipproto eq 0 and tcp (for the <11.0.0 case)
 *  This is in an attempt to try to not pick up UDP packets that happen to have the same ports when
 *  you are filtering on a TCP conversation.  Note that in the <11.0.0 case, an IP protocol change
 *  across the peer flows (I don't know that I've seen that happen, so it's at least rare) will not
 *  be filtered properly.  In the >=11.0.0 case, if you have TCP on one side and UDP on the other
 *  and it should "do the right thing".
 *
 *  \attention This function uses g_strdup_printf() rather than the wmem equivalent because the
 *             caller (menu_dissector_filter_cb()) uses g_free to free the filter string.
 *             (as of WS 1.12).
 */
static gchar *f5_tcp_conv_filter(packet_info *pinfo)
{
	gchar *buf = NULL;
	gchar s_addr[WS_INET6_ADDRSTRLEN];
	gchar d_addr[WS_INET6_ADDRSTRLEN];

	*d_addr = *s_addr = '\0';
	if(pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) {
		address_to_str_buf(&pinfo->src, s_addr, WS_INET6_ADDRSTRLEN);
		address_to_str_buf(&pinfo->dst, d_addr, WS_INET6_ADDRSTRLEN);
		if(*s_addr != '\0' && *d_addr != '\0') {
			buf = g_strdup_printf(
				"(ip.addr eq %s and ip.addr eq %s and tcp.port eq %d and tcp.port eq %d) or"
				" (f5ethtrailer.peeraddr eq %s and f5ethtrailer.peeraddr eq %s and"
				" f5ethtrailer.peerport eq %d and f5ethtrailer.peerport eq %d and"
				" (f5ethtrailer.peeripproto eq 6 or (f5ethtrailer.peeripproto eq 0 and tcp)))",
				s_addr, d_addr, pinfo->srcport, pinfo->destport,
				s_addr, d_addr, pinfo->srcport, pinfo->destport);
		}
	} else if(pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6) {
		address_to_str_buf(&pinfo->src, s_addr, WS_INET6_ADDRSTRLEN);
		address_to_str_buf(&pinfo->dst, d_addr, WS_INET6_ADDRSTRLEN);
		if(*s_addr != '\0' && *d_addr != '\0') {
			buf = g_strdup_printf(
				"(ipv6.addr eq %s and ipv6.addr eq %s and tcp.port eq %d and tcp.port eq %d) or"
				" (f5ethtrailer.peeraddr6 eq %s and f5ethtrailer.peeraddr6 eq %s and"
				" f5ethtrailer.peerport eq %d and f5ethtrailer.peerport eq %d and"
				" (f5ethtrailer.peeripproto eq 6 or (f5ethtrailer.peeripproto eq 0 and tcp)))",
				s_addr, d_addr, pinfo->srcport, pinfo->destport,
				s_addr, d_addr, pinfo->srcport, pinfo->destport);
		}
	}
	return(buf);
} /* f5_tcp_conv_filter() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Calculates the F5 UDP conversation filter based on the current packet.
 *
 *  \attention This is an interface function to be called from the rest of wireshark.
 *
 *   @param pinfo   A pointer to the packet info to look at for the L3/L4 data.
 *   @return        A filter string for the F5 UDP conversation or NULL if no filter can be
 *                  computed.  The caller should free this string with g_free().
 *
 *  Prior to version 11.0.0, the f5ethtrailer.peeripproto field was not populated properly.  In
 *  an effort to accurately match the appropriate protocol, the filter adds:
 *       f5ethtrailer.ipproto eq 17 (for the >=11.0.0 case)
 *    or f5ethtrailer.ipproto eq 0 and udp (for the <11.0.0 case)
 *  This is in an attempt to try to not pick up TCP packets that happen to have the same ports when
 *  you are filtering on a UDP conversation.  Note that in the <11.0.0 case, an IP protocol change
 *  across the peer flows (I don't know that I've seen that happen, so it's at least rare) will not
 *  be filtered properly.  In the >=11.0.0 case, if you have TCP on one side and UDP on the other
 *  and it should "do the right thing".
 *
 *  \attention This function uses g_strdup_printf() rather than the wmem equivalent because the
 *             caller (menu_dissector_filter_cb()) uses g_free to free the filter string.
 *             (as of WS 1.12).
 */
static gchar *f5_udp_conv_filter(packet_info *pinfo)
{
	gchar *buf = NULL;
	gchar s_addr[WS_INET6_ADDRSTRLEN];
	gchar d_addr[WS_INET6_ADDRSTRLEN];

	*d_addr = *s_addr = '\0';
	if(pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) {
		address_to_str_buf(&pinfo->src, s_addr, WS_INET6_ADDRSTRLEN);
		address_to_str_buf(&pinfo->dst, d_addr, WS_INET6_ADDRSTRLEN);
		if(*s_addr != '\0' && *d_addr != '\0') {
			buf = g_strdup_printf(
				"(ip.addr eq %s and ip.addr eq %s and udp.port eq %d and udp.port eq %d) or"
				" (f5ethtrailer.peeraddr eq %s and f5ethtrailer.peeraddr eq %s and"
				" f5ethtrailer.peerport eq %d and f5ethtrailer.peerport eq %d and"
				" (f5ethtrailer.peeripproto eq 17 or (f5ethtrailer.peeripproto eq 0 and udp)))",
				s_addr, d_addr, pinfo->srcport, pinfo->destport,
				s_addr, d_addr, pinfo->srcport, pinfo->destport);
		}
	} else if(pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6) {
		address_to_str_buf(&pinfo->src, s_addr, WS_INET6_ADDRSTRLEN);
		address_to_str_buf(&pinfo->dst, d_addr, WS_INET6_ADDRSTRLEN);
		if(*s_addr != '\0' && *d_addr != '\0') {
			buf = g_strdup_printf(
				"(ipv6.addr eq %s and ipv6.addr eq %s and udp.port eq %d and udp.port eq %d) or"
				" (f5ethtrailer.peeraddr6 eq %s and f5ethtrailer.peeraddr6 eq %s and"
				" f5ethtrailer.peerport eq %d and f5ethtrailer.peerport eq %d and"
				" (f5ethtrailer.peeripproto eq 17 or (f5ethtrailer.peeripproto eq 0 and udp)))",
				s_addr, d_addr, pinfo->srcport, pinfo->destport,
				s_addr, d_addr, pinfo->srcport, pinfo->destport);
		}
	}
	return(buf);
} /* f5_udp_conv_filter() */

/* End of Analyze menu functions */
/*===============================================================================================*/



/*===============================================================================================*/
/* Stats tree functions */

static int st_node_tmmpktdist  = -1; /**< Tree for packet counts */
static int st_node_tmmbytedist = -1; /**< Tree for byte counts (excludes trailer) */
static const gchar *st_str_tmmdist         = "F5/tmm Distribution";
static const gchar *st_str_tmmdist_pkts    = "tmm Packet Distribution";
static const gchar *st_str_tmmdist_bytes   = "tmm Byte Distribution (excludes trailer)";
static const gchar *st_str_tmm_dir_in      = "direction in";
static const gchar *st_str_tmm_dir_out     = "direction out";
static const gchar *st_str_tmm_flow_virt   = "flow with virtual";
static const gchar *st_str_tmm_flow_novirt = "flow without virtual";
static const gchar *st_str_tmm_flow_none   = "flow none";

static int st_node_virtpktdist  = -1; /**< Tree for packet counts */
static int st_node_virtbytedist = -1; /**< Tree for packet counts (excludes trailer) */
static const gchar *st_str_virtdist        = "F5/Virtual Server Distribution";
static const gchar *st_str_virtdist_pkts   = "Virtual Server Packet Distribution";
static const gchar *st_str_virtdist_bytes  = "Virtual Server Byte Distribution (excludes trailer)";
static const gchar *st_str_virtdist_noflow = "No flow";
static const gchar *st_str_virtdist_novirt = "Flow without virtual server name";

/*-----------------------------------------------------------------------------------------------*/
/** \brief Initializer for tmm distribution statistics
 *
 *  \attention This is an interface function to be called from the rest of wireshark.
 *
 *   @param st      A pointer to the stats tree to use
 *
 */
static void f5eth_tmmdist_stats_tree_init(
	stats_tree *st
) {
	st_node_tmmpktdist = stats_tree_create_node(st, st_str_tmmdist_pkts, 0, STAT_DT_INT, TRUE);
	stat_node_set_flags(st, st_str_tmmdist_pkts, 0, TRUE, ST_FLG_SORT_TOP);
	st_node_tmmbytedist = stats_tree_create_node(st, st_str_tmmdist_bytes, 0, STAT_DT_INT, TRUE);
} /* f5eth_tmmdist_stats_tree_init() */

#define PER_TMM_STAT_NAME_BUF_LEN (sizeof("slot SSS,tmm TTT"))

/*-----------------------------------------------------------------------------------------------*/
/** \brief Per-packet tmm distrubution statistics
 *
 *  \attention This is an interface function to be called from the rest of wireshark.
 *
 *   @param st      A pointer to the stats tree to use
 *   @param pinfo   A pointer to the packet info.
 *   @param edt     Unused
 *   @param data    A pointer to the data provided by the tap
 *   @return        TAP_PACKET_REDRAW if the data was actually used to alter
 *                  the statistics, TAP_PACKET_DONT_REDRAW otherwise.
 *
 */
static tap_packet_status f5eth_tmmdist_stats_tree_packet(
	stats_tree *st,
	packet_info *pinfo,
	epan_dissect_t *edt _U_,
	const void *data
) {
	const f5eth_tap_data_t *tdata = (const f5eth_tap_data_t *)data;
	guint32 pkt_len;
	int st_node_tot_pkts;
	int st_node_tot_bytes;
	int st_node_tmm_pkts;
	int st_node_tmm_bytes;
	char tmm_stat_name_buffer[PER_TMM_STAT_NAME_BUF_LEN];

	if(tdata == NULL)
		return TAP_PACKET_DONT_REDRAW;

	/* Unnecessary since this tap packet function and the F5 Ethernet trailer dissector are both in
	 * the same source file.  If you are using this function as an example in a separate tap source
	 * file, you should uncomment this.
	if(check_f5eth_tap_magic(tdata) == 0) return TAP_PACKET_DONT_REDRAW;
	 */

	g_snprintf(tmm_stat_name_buffer, PER_TMM_STAT_NAME_BUF_LEN, "slot %3d,tmm %3d",
		tdata->slot, tdata->tmm);

	pkt_len = pinfo->fd->pkt_len - tdata->trailer_len;

	st_node_tot_pkts = tick_stat_node(st, st_str_tmmdist_pkts, 0, TRUE);
	st_node_tot_bytes = increase_stat_node(st, st_str_tmmdist_bytes, 0, TRUE, pkt_len);

	st_node_tmm_pkts  = tick_stat_node(st, tmm_stat_name_buffer, st_node_tot_pkts, TRUE);
	st_node_tmm_bytes = increase_stat_node(st, tmm_stat_name_buffer, st_node_tot_bytes, TRUE,
		pkt_len);
	if(tdata->ingress == 1) {
		tick_stat_node(st, st_str_tmm_dir_in, st_node_tmm_pkts, FALSE);
		increase_stat_node(st, st_str_tmm_dir_in, st_node_tmm_bytes, FALSE, pkt_len);
		/* Create nodes in case we see no egress packets */
		increase_stat_node(st, st_str_tmm_dir_out, st_node_tmm_pkts, FALSE, 0);
		increase_stat_node(st, st_str_tmm_dir_out, st_node_tmm_bytes, FALSE, 0);
	} else {
		tick_stat_node(st, st_str_tmm_dir_out, st_node_tmm_pkts, FALSE);
		increase_stat_node(st, st_str_tmm_dir_out, st_node_tmm_bytes, FALSE, pkt_len);
		/* Create nodes in case we see no ingress packets */
		increase_stat_node(st, st_str_tmm_dir_in, st_node_tmm_pkts, FALSE, 0);
		increase_stat_node(st, st_str_tmm_dir_in, st_node_tmm_bytes, FALSE, 0);
	}

	if(tdata->virtual_name == NULL) {
		if(tdata->flow == 0) {
			/* No flow ID and no virtual name */
			tick_stat_node(st, st_str_tmm_flow_none, st_node_tmm_pkts, FALSE);
			increase_stat_node(st, st_str_tmm_flow_none, st_node_tmm_bytes, FALSE, pkt_len);

			/* Create nodes in case we see no packets without a virtual */
			increase_stat_node(st, st_str_tmm_flow_novirt, st_node_tmm_pkts, FALSE, 0);
			increase_stat_node(st, st_str_tmm_flow_novirt, st_node_tmm_bytes, FALSE, 0);
		} else {
			/* Flow ID and no virtual name */
			tick_stat_node(st, st_str_tmm_flow_novirt, st_node_tmm_pkts, FALSE);
			increase_stat_node(st, st_str_tmm_flow_novirt, st_node_tmm_bytes, FALSE, pkt_len);

			/* Create nodes in case we see no packets with a virtual */
			increase_stat_node(st, st_str_tmm_flow_none, st_node_tmm_pkts, FALSE, 0);
			increase_stat_node(st, st_str_tmm_flow_none, st_node_tmm_bytes, FALSE, 0);
		}
		/* Create nodes in case we see no packets with a virtual */
		increase_stat_node(st, st_str_tmm_flow_virt, st_node_tmm_pkts, FALSE, 0);
		increase_stat_node(st, st_str_tmm_flow_virt, st_node_tmm_bytes, FALSE, 0);
	} else {
		/* Has a virtual name */
		tick_stat_node(st, st_str_tmm_flow_virt, st_node_tmm_pkts, FALSE);
		increase_stat_node(st, st_str_tmm_flow_virt, st_node_tmm_bytes, FALSE, pkt_len);

		/* Create nodes in case we see no packets without a virtual */
		increase_stat_node(st, st_str_tmm_flow_novirt, st_node_tmm_pkts, FALSE, 0);
		increase_stat_node(st, st_str_tmm_flow_novirt, st_node_tmm_bytes, FALSE, 0);
		/* Create nodes in case we see no packets without a flow */
		increase_stat_node(st, st_str_tmm_flow_none, st_node_tmm_pkts, FALSE, 0);
		increase_stat_node(st, st_str_tmm_flow_none, st_node_tmm_bytes, FALSE, 0);
	}

	return TAP_PACKET_REDRAW;
} /* f5eth_tmmdist_stats_tree_packet() */

/*-----------------------------------------------------------------------------------------------*/
static void f5eth_virtdist_stats_tree_init(
	stats_tree *st
) {
	st_node_virtpktdist = stats_tree_create_node(st, st_str_virtdist_pkts, 0, STAT_DT_INT, TRUE);
	stat_node_set_flags(st, st_str_virtdist_pkts, 0, TRUE, ST_FLG_SORT_TOP);
	st_node_virtbytedist = stats_tree_create_node(st, st_str_virtdist_bytes, 0, STAT_DT_INT, TRUE);

	stats_tree_create_node(st, st_str_virtdist_noflow, st_node_virtpktdist, STAT_DT_INT, TRUE);
	stat_node_set_flags(st, st_str_virtdist_noflow, st_node_virtpktdist, TRUE, ST_FLG_SORT_TOP);
	stats_tree_create_node(st, st_str_virtdist_novirt, st_node_virtpktdist, STAT_DT_INT, TRUE);
	stat_node_set_flags(st, st_str_virtdist_novirt, st_node_virtpktdist, TRUE, ST_FLG_SORT_TOP);

	stats_tree_create_node(st, st_str_virtdist_noflow, st_node_virtbytedist, STAT_DT_INT, TRUE);
	stat_node_set_flags(st, st_str_virtdist_noflow, st_node_virtbytedist, TRUE, ST_FLG_SORT_TOP);
	stats_tree_create_node(st, st_str_virtdist_novirt, st_node_virtbytedist, STAT_DT_INT, TRUE);
	stat_node_set_flags(st, st_str_virtdist_novirt, st_node_virtbytedist, TRUE, ST_FLG_SORT_TOP);
} /* f5eth_virtdist_stats_tree_init() */

/*-----------------------------------------------------------------------------------------------*/
static tap_packet_status f5eth_virtdist_stats_tree_packet(
	stats_tree *st,
	packet_info *pinfo,
	epan_dissect_t *edt _U_,
	const void *data
) {
	const f5eth_tap_data_t *tdata = (const f5eth_tap_data_t *)data;
	guint32 pkt_len;

	if (tdata == NULL)
		return TAP_PACKET_DONT_REDRAW;
	/* Unnecessary since this tap packet function and the F5 Ethernet trailer dissector are both in
	 * the same source file.  If you are using this function as an example in a separate tap source
	 * file, you should uncomment this.
	if(check_f5eth_tap_magic(tdata) == 0) return TAP_PACKET_DONT_REDRAW;
	 */

	pkt_len = pinfo->fd->pkt_len - tdata->trailer_len;

	tick_stat_node(st, st_str_virtdist_pkts, 0, TRUE);
	increase_stat_node(st, st_str_virtdist_bytes, 0, TRUE, pkt_len);

	/* We could have low noise (with a virtual name) without medium noise (with the flow ID).
	 * That will get treated as a no flow case. */
	if(tdata->virtual_name == NULL) {
		if(tdata->flow == 0) {
			/* No flow ID */
			tick_stat_node(st, st_str_virtdist_noflow, st_node_virtpktdist, TRUE);
			increase_stat_node(st, st_str_virtdist_noflow, st_node_virtbytedist, TRUE, pkt_len);
		} else {
			/* Flow ID without virtual name */
			tick_stat_node(st, st_str_virtdist_novirt, st_node_virtpktdist, TRUE);
			increase_stat_node(st, st_str_virtdist_novirt, st_node_virtbytedist, TRUE, pkt_len);
		}
	} else {
		/* Has virtual name */
		tick_stat_node(st, tdata->virtual_name, st_node_virtpktdist, TRUE);
		increase_stat_node(st, tdata->virtual_name, st_node_virtbytedist, TRUE, pkt_len);
	}

	return TAP_PACKET_REDRAW;
} /* f5eth_virtdist_stats_tree_packet() */


/* End of statistics gathering */
/*===============================================================================================*/



/*===============================================================================================*/
/* Info column display handling.
 *
 * Format Specifiers:
 *   in/out are separate formats so that no printf formatting is required for these two common
 *     alternatives.
 *   There are two sets of six format strings.  One set corresponding to "full" or long output
 *     ("long" is not used due to conflict with C keyword) and the other set corresponding to
 *     "brief" output.
 *     Full:
 *       in/out only; one for in, one for out:
 *         info_format_full_in_only,    info_format_full_out_only
 *       in/out, slot and tmm; one for in and one for out:
 *         info_format_full_in_slot,    info_format_full_out_slot
 *       in/out and tmm (no slot information); one for in and one for out:
 *         info_format_full_in_noslot,  info_format_full_out_noslot
 *     Brief:
 *       in/out only; one for in, one for out:
 *         info_format_brief_in_only,   info_format_brief_out_only
 *       in/out, slot and tmm; one for in and one for out:
 *         info_format_brief_in_slot,   info_format_brief_out_slot
 *       in/out and tmm (no slot information); one for in and one for out:
 *         info_format_brief_in_noslot, info_format_brief_out_noslot
 *   The set of format specifiers in use are chosen based on whether brief is chosen and the
 *     following variables are set accordingly:
 *        info_format_in_only,          info_format_out_only   (should have no format specifiers)
 *        info_format_in_slot,          info_format_out_slot   (should have two format specifiers)
 *        info_format_in_noslot,        info_format_out_noslot (should have one format specifier)
 *
 * Functions:
 *   Separate functions depending on the amount of information desired.  The decision is made once
 *     when the preference is set and a function pointer is used to call the appropriate one:
 *       f5eth_set_info_col_inout():   In/out only.
 *       f5eth_set_info_col_slot():    in/out, slot and tmm.
 *       f5eth_set_info_col_noslot():  in/out and tmm (no slot information).
 *   f5eth_set_info_col is the function pointer to the function currently in use.
 */

/** Info column display format formats */
static const char info_format_full_in_only[]     = "IN : ";
static const char info_format_full_out_only[]    = "OUT: ";
static const char info_format_full_in_slot[]     = "IN  s%u/tmm%-2u: ";
static const char info_format_full_out_slot[]    = "OUT s%u/tmm%-2u: ";
static const char info_format_full_in_noslot[]   = "IN  tmm%-2u: ";
static const char info_format_full_out_noslot[]  = "OUT tmm%-2u: ";

/* Variables used in f5eth_set_info_col functions initialized to defaults */
static char *info_format_in_only    = NULL;  /**< In format in use with in/out only */
static char *info_format_out_only   = NULL;  /**< Out format in use with in/out only */
static char *info_format_in_noslot  = NULL;  /**< In format in use without slot */
static char *info_format_out_noslot = NULL;  /**< Out format in use without slot */
static char *info_format_in_slot    = NULL;  /**< In format in use with slot */
static char *info_format_out_slot   = NULL;  /**< Out format in use with slot */

/** Info column display format preference types:
  * These correspond to bit flags
  *   Display on  = 0x0001
  *   In out only = 0x0002
  *   Brief       = 0x0004
  */
typedef enum {
	none = 0,
	full = 1,
	in_out_only = 3,
	brief = 5,
	brief_in_out_only = 7
} f5eth_info_type_t;

/** Info column display format type strings */
static const enum_val_t f5eth_display_strings[] = {
	{ "None",           "None",               0 },
	{ "Full",           "Full",               1 },
	{ "InOutOnly",      "In/out only",        3 },
	{ "Brief",          "Brief",              5 },
	{ "BriefInOutOnly", "Brief in/out only",  7 },

	{ NULL,             NULL,                 0 }
};
/** Info column display preference (default to full) */
static f5eth_info_type_t pref_info_type = full;

/** Preference for the brief in/out characters */
static const char *pref_brief_inout_chars = NULL;

/** Function pointer prototype for info column set functions */
typedef void (*f5eth_set_col_info_func)(packet_info *, guint, guint, guint);


/** Preference for setting platform regex for which platforms to display slot information for. */
static const char *pref_slots_regex = NULL;
/** Whether or not to display slot information, set based on platform and regex preference. */
static gboolean display_slot = TRUE;

/*-----------------------------------------------------------------------------------------------*/
/** \brief Adds full format (in/out, slot, tmm) to info column
 *
 *   @param pinfo   A pointer to the packet info structure.
 *   @param ingress zero for egress, non-zero for ingress.
 *   @param slot    The slot number handling the packet
 *   @param tmm     The tmm handling the packet
 */
static void f5eth_set_info_col_slot(
	packet_info *pinfo,
	guint ingress,
	guint slot,
	guint tmm
) {
	gboolean col_writable;
	/*
	 * HTTP and other protocols set writable to false to protect
	 * their data.  We don't care.
	 */
	col_writable = col_get_writable(pinfo->cinfo, COL_INFO);
	col_set_writable(pinfo->cinfo, COL_INFO, TRUE);

	if(ingress != 0) {
		DISSECTOR_ASSERT(info_format_in_slot);
		col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, info_format_in_slot, slot, tmm);
	} else {
		DISSECTOR_ASSERT(info_format_out_slot);
		col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, info_format_out_slot, slot, tmm);
	}

	/* Reset writable to whatever it was before we got here. */
	col_set_writable(pinfo->cinfo, COL_INFO, col_writable);
} /* f5eth_set_info_col_slot() */


/*-----------------------------------------------------------------------------------------------*/
/** \brief Adds format without slot (in/out, tmm) to info column
 *
 *   @param pinfo   A pointer to the packet info structure.
 *   @param ingress zero for egress, non-zero for ingress.
 *   @param slot    The slot number handling the packet (unused)
 *   @param tmm     The tmm handling the packet
 */
static void f5eth_set_info_col_noslot(
	packet_info *pinfo,
	guint ingress,
	guint slot _U_,
	guint tmm
) {
	gboolean col_writable;
	/*
	 * HTTP and other protocols set writable to false to protect
	 * their data.  We don't care.
	 */
	col_writable = col_get_writable(pinfo->cinfo, COL_INFO);
	col_set_writable(pinfo->cinfo, COL_INFO, TRUE);

	if(ingress != 0) {
		col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, info_format_in_noslot, tmm);
	} else {
		col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, info_format_out_noslot, tmm);
	}

	/* Reset writable to whatever it was before we got here. */
	col_set_writable(pinfo->cinfo, COL_INFO, col_writable);
} /* f5eth_set_info_col_noslot() */


/*-----------------------------------------------------------------------------------------------*/
/** \brief Adds format with only direction (in/out) to info column
 *
 *   @param pinfo   A pointer to the packet info structure.
 *   @param ingress zero for egress, non-zero for ingress.
 *   @param slot    The slot number handling the packet (unused)
 *   @param tmm     The tmm handling the packet (unused)
 */
static void f5eth_set_info_col_inout(
	packet_info *pinfo,
	guint ingress,
	guint slot _U_,
	guint tmm _U_
) {
	gboolean col_writable;
	/*
	 * HTTP and other protocols set writable to false to protect
	 * their data.  We don't care.
	 */
	col_writable = col_get_writable(pinfo->cinfo, COL_INFO);
	col_set_writable(pinfo->cinfo, COL_INFO, TRUE);

	if(ingress != 0) {
		col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "%s", info_format_in_only);
	} else {
		col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "%s", info_format_out_only);
	}

	/* Reset writable to whatever it was before we got here. */
	col_set_writable(pinfo->cinfo, COL_INFO, col_writable);
} /* f5eth_set_info_col_inout() */

/** The column display function.  Will really be set in proto_reg_handoff_f5fileinfo() */
static f5eth_set_col_info_func f5eth_set_info_col = f5eth_set_info_col_slot;


/*-----------------------------------------------------------------------------------------------*/
/** \brief Called out of f5info processing to determine platform display information
 *
 *   @param platform String representing the platform name (can be NULL, will not be referenced
 *                   after the function returns.)
 */
static void f5eth_process_f5info(const guint8 *platform)
{
	/** Always display slot information when there is no platform information in the header or
	 *  if there was no regex specified in the preference.  But use the in/out only
	 *  function if that is specified in the preference.*/
	if(platform == NULL || platform[0] == '\0' ||
	   pref_slots_regex == NULL || pref_slots_regex[0] == '\0' )
	{
		display_slot = TRUE;
		if(pref_info_type == in_out_only || pref_info_type == brief_in_out_only) {
			f5eth_set_info_col = f5eth_set_info_col_inout;
		} else {
			f5eth_set_info_col = f5eth_set_info_col_slot;
		}
		return;
	}

	/** If the string matches the regex */
	if(g_regex_match_simple(pref_slots_regex, platform, (GRegexCompileFlags)0,
		(GRegexMatchFlags)0) == TRUE)
	{
		/** Then display the slot information (only if in/out only is not selected). */
		display_slot = TRUE;
		if(pref_info_type == in_out_only || pref_info_type == brief_in_out_only) {
			f5eth_set_info_col = f5eth_set_info_col_inout;
		} else {
			f5eth_set_info_col = f5eth_set_info_col_slot;
		}
	} else {
		/** Else do not display the slot information (only if in/out only is not selected). */
		display_slot = FALSE;
		if(pref_info_type == in_out_only || pref_info_type == brief_in_out_only) {
			f5eth_set_info_col = f5eth_set_info_col_inout;
		} else {
			f5eth_set_info_col = f5eth_set_info_col_noslot;
		}
	}
} /* f5eth_process_f5info() */

/* End of info column display handling.                                                          */
/*===============================================================================================*/

/** Magic information for the fileinfo packet that might appear at the beginning of a capture. */
static const guint8 fileinfomagic1[] = {
	0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0,  0x05, 0xff,
	'F', '5', '-', 'P', 's', 'e', 'u', 'd', 'o', '-', 'p', 'k', 't',   0
};

#define F5_OFF_TYPE    0
#define F5_OFF_LENGTH  1
#define F5_OFF_VERSION 2
#define F5_OFF_VALUE   3

/** This is used only for legacy trailers.  The highest version number is 3 for medium trailers. */
#define F5TRAILER_VER_MAX 3

#define F5TRAILER_TYPE(tvb, offset) (tvb_get_guint8(tvb, offset))
#define F5TRAILER_LEN(tvb, offset)  \
		(tvb_get_guint8(tvb, (offset) + F5_OFF_LENGTH) + F5_OFF_VERSION)
#define F5TRAILER_VER(tvb, offset)  \
		(tvb_get_guint8(tvb, (offset) + F5_OFF_VERSION))

#define F5TYPE_LOW  1
#define F5TYPE_MED  2
#define F5TYPE_HIGH 3

/* These are to perform a sanity check to try to avoid rendering true garbage
 * in packets.  So, in addition to matching one of the types, the len of the
 * suspected trailer needs to fall into this range.  However, we also want to
 * balance this against the ability to render most of a trailer if the format
 * changes without necessarily having to change the dissector immediately.
 *
 * Max length seems to be 42 on high detail.
 * Max length with RST cause in medium(v1) is 30 + 8 + 1 + 96 (might be 30+96)?
 * Max length with RST cause in medium(v2) is 31 + 8 + 1 + 96 (might be 31+96)?
 * Max length with RST cause in medium(v3) is 35 + 8 + 1 + 96 (might be 35+96)?
 * Min length is 8 on v9.4 medium detail.
 * Min length is 7 on v11.2 low trailer with no VIP name.
 *
 * These are only used for legacy trailers.
 */
#define F5_MIN_SANE 7
#define F5_MAX_SANE 140


#define F5_HIV0_LEN                   42

/* Legacy trailers */
#define F5_MEDV94_LEN                  8
#define F5_MEDV10_LEN                 21
#define F5_MEDV11_LEN                 29
#define F5_MEDV1_LENMIN               30
#define F5TRL_MEDV1_RSTCLEN(tvb, offset) tvb_get_guint8(tvb, (offset)+(F5_MEDV1_LENMIN-1))
#define F5TRL_MEDV1_RSTCVER(tvb, offset) ((tvb_get_guint8(tvb, (offset)+F5_MEDV1_LENMIN) & 0xfe) >> 1)
#define F5TRL_MEDV1_RSTCPEER(tvb, offset) (tvb_get_guint8(tvb, (offset)+F5_MEDV1_LENMIN) & 0x01)
#define F5_MEDV2_LENMIN               31
#define F5TRL_MEDV2_RSTCLEN(tvb, offset) tvb_get_guint8(tvb, (offset)+(F5_MEDV2_LENMIN-1))
#define F5TRL_MEDV2_RSTCVER(tvb, offset) ((tvb_get_guint8(tvb, (offset)+F5_MEDV2_LENMIN) & 0xfe) >> 1)
#define F5TRL_MEDV2_RSTCPEER(tvb, offset) (tvb_get_guint8(tvb, (offset)+F5_MEDV2_LENMIN) & 0x01)
#define F5_MEDV3_LENMIN               35
#define F5TRL_MEDV3_RSTCLEN(tvb, offset) tvb_get_guint8(tvb, (offset)+(F5_MEDV3_LENMIN-1))
#define F5TRL_MEDV3_RSTCVER(tvb, offset) ((tvb_get_guint8(tvb, (offset)+F5_MEDV3_LENMIN) & 0xfe) >> 1)
#define F5TRL_MEDV3_RSTCPEER(tvb, offset) (tvb_get_guint8(tvb, (offset)+F5_MEDV3_LENMIN) & 0x01)

#define F5_LOWV94_LEN                 35
#define F5_LOWV10_LEN                 22
#define F5_OFF_LOW_ING                 3
#define F5_OFF_LOW_SLOT                4
#define F5_OFF_LOW_TMM                 5
#define VIP_NAME_LEN                  16
#define F5_LOWV1_LENMIN                7
#define F5TRL_LOWV1_VIPLEN(tvb, offset) tvb_get_guint8(tvb, (offset)+(F5_LOWV1_LENMIN-1))

/* DPT trailers */
#define F5_MEDV4_LENMIN               32 /**< Minimum length without TLV header */
#define F5TRL_MEDV4_RSTCLEN(tvb, offset) tvb_get_guint8(tvb, (offset)+(F5_MEDV4_LENMIN-1))
#define F5TRL_MEDV4_RSTCVER(tvb, offset) \
		((tvb_get_guint8(tvb, (offset)+F5_MEDV4_LENMIN) & 0xfe) >> 1)
#define F5TRL_MEDV4_RSTCPEER(tvb, offset) (tvb_get_guint8(tvb, (offset)+F5_MEDV4_LENMIN) & 0x01)

#define F5_DPT_V1_HDR_MAGIC_OFF     0
#define F5_DPT_V1_HDR_MAGIC_LEN     4
#define F5_DPT_V1_HDR_MAGIC         0xf5deb0f5
#define F5_DPT_V1_HDR_LENGTH_OFF    (F5_DPT_V1_HDR_MAGIC_OFF + F5_DPT_V1_HDR_MAGIC_LEN)
#define F5_DPT_V1_HDR_LENGTH_LEN    2
#define F5_DPT_V1_HDR_VERSION_OFF   (F5_DPT_V1_HDR_LENGTH_OFF + F5_DPT_V1_HDR_LENGTH_LEN)
#define F5_DPT_V1_HDR_VERSION_LEN   2
#define F5_DPT_V1_HDR_VERSION_MIN   1 /**< Minimum DPT version handled by this dissector. */
#define F5_DPT_V1_HDR_VERSION_MAX   1 /**< Maximum DPT version handled by this dissector. */
#define F5_DPT_V1_HDR_LEN           (F5_DPT_V1_HDR_VERSION_OFF + F5_DPT_V1_HDR_VERSION_LEN)

#define F5_DPT_PROVIDER_NOISE       1

#define F5_DPT_V1_TLV_PROVIDER_OFF     0
#define F5_DPT_V1_TLV_PROVIDER_LEN     2
#define F5_DPT_V1_TLV_TYPE_OFF         (F5_DPT_V1_TLV_PROVIDER_OFF + F5_DPT_V1_TLV_PROVIDER_LEN)
#define F5_DPT_V1_TLV_TYPE_LEN         2
#define F5_DPT_V1_TLV_LENGTH_OFF       (F5_DPT_V1_TLV_TYPE_OFF + F5_DPT_V1_TLV_TYPE_LEN)
#define F5_DPT_V1_TLV_LENGTH_LEN       2
#define F5_DPT_V1_TLV_VERSION_OFF      (F5_DPT_V1_TLV_LENGTH_OFF + F5_DPT_V1_TLV_LENGTH_LEN)
#define F5_DPT_V1_TLV_VERSION_LEN      2
#define F5_DPT_V1_TLV_HDR_LEN          (F5_DPT_V1_TLV_VERSION_OFF+F5_DPT_V1_TLV_VERSION_LEN)


/*===============================================================================================*/
/* This section is for performing analysis of the trailer information. */

/** Analysis Overview:
 *
 *  The analysis in this dissector is meant to correlate data in the F5 Ethernet trailer with other
 *  data in the frame (e.g. IP, TCP) and highlight things that don't look right.  They might be
 *  perfectly valid, but in most cases, they are are not.
 *
 *  How it works:
 *
 *  When analysis is enabled, the dissector ties protocol data to each packet.  The dissector
 *  populates some useful data it needs to perform analysis into the protocol data.  It also
 *  registers taps on IP, IPv6 and TCP to populate data from those headers into the stored protocol
 *  data.
 *
 *  All of that information is then used to look for certain, common anomalies.
 *
 *  It uses taps rather than surfing the WS protocol tree because:
 *    1. I suspect that surfing the protocol tree is rather expensive.
 *    2. We need to try to find the outer-most headers and use those.  The taps should fire in
 *       order so that should get what is needed.  When searching the tree, it's difficult to
 *       know if, for example, the TCP header we are on is tied to the outer IP header or to
 *       the IP header that's inside and ICMP inside an IP.
 *
 *  Challenges:
 *
 *  1.  Taps run after all dissectors run on a packet.  As a result, when the trailer dissector is
 *      running, it does not have the data from the other protocols to perform the analysis.
 *  2.  The Ethernet dissector does not call trailer dissectors if it is not building a tree.
 *
 *  Flow:
 *
 *  In the trailer dissector, if ip_visited is set and analysis done is not set, then analysis
 *  is performed.
 *
 *  In the tcp tap, if analysis_done is not set and pkt_ingress is not unknown (meaning that the
 *  trailer dissector had an opportunity to run on this packet), then analysis is performed.  Also
 *  in this case, we attempt to attach the expert info to a top-level tree element for the
 *  F5 Ethernet trailer.
 *
 *  The purpose of the analysis in the dissector is for first-pass misses of the dissector.  For
 *  example, on initial file load, if the Ethernet dissector does not call the trailer dissector
 *  then analysis cannot be performed by the tcp tap because the data from the trailer is not
 *  available.  In order to get the analysis on the second pass, we run here.
 *
 *  The purpose of the analysis and rendering in the tcp tap is to handle one-pass situations
 *  (e.g. tshark).  In one-pass situations, after the tcp tap is called, the trailer dissector
 *  will not run again to have an opportunity to perform and render analysis.
 */

#define IP_MF 0x2000 /** IP more fragments flag */
#define IP_OFFSET_WIDTH 13 /** Size of fragment offset field */
#define IP_OFFSET_MASK ((1 << IP_OFFSET_WIDTH) - 1)


/** Structure used to store data gathered by the taps and dissector that is attached to the pinfo
 * structure for the packet.  This structure ends up getting allocated for every packet.  So, we
 * want to keep it small.
 *
 * For fields that are 1 bit wide, they have 0 == false and 1 == true.
 * For fields that are 2 bits wide, they have 0 == false, 1 == true and 3 == unknown.
 */
struct f5eth_analysis_data_t {
	guint8 ip_visited:1;          /**< Did the IPv4 or IPv6 tap look at this packet already? */
	guint8 tcp_visited:1;         /**< Did the TCP tap look at this packet already? */
	guint8 ip_istcp:2;            /**< Is this a TCP (set by ip/ip6 tap on first header) */
	guint8 ip_isfrag:2;           /**< Is this packet an IP fragment? */
	guint8 tcp_synset:2;          /**< Is the SYN flag set in the TCP header? */
	guint8 tcp_ackset:2;          /**< Is the ACK flag set in the TCP header? */

	guint8 pkt_ingress:2;         /**< Packet is ingress packet */
	guint8 pkt_has_flow:2;        /**< Packet has associated flow */
	guint8 pkt_has_peer:2;        /**< Packet has associated peer flow */

	guint8 analysis_done:1;       /**< Analysis has been performed */
	guint8 analysis_flowreuse:1;  /**< Analysis indicates flow reuse */
	guint8 analysis_flowlost:1;   /**< Analysis indicates flow lost */
	guint8 analysis_hasresults:1; /**< Are there actually any results? */
};


/*-----------------------------------------------------------------------------------------------*/
/** \brief Allocates a new analysis data structure and initializes the values.
 */
static struct f5eth_analysis_data_t *new_f5eth_analysis_data_t(void)
{
	struct f5eth_analysis_data_t *r = wmem_new0(wmem_file_scope(), struct f5eth_analysis_data_t);

	/* r->ip_visited = 0; */
	/* r->tcp_visited = 0; */
	r->ip_istcp = 3;
	r->tcp_synset = 3;
	r->tcp_ackset = 3;
	r->ip_isfrag = 3;

	r->pkt_ingress = 3;
	r->pkt_has_flow = 3;
	r->pkt_has_peer = 3;

	/* r->analysis_done = 0; */
	/* r->analysis_flowreuse = 0; */
	/* r->analysis_flowlost = 0; */
	/* r->analysis_hasresults = 0; */

	return(r);
} /* new_f5eth_analysis_data_t() */


/* Functions for find a subtree of a particular type of the current tree. */

/** Structure used as the anonymous data in the proto_tree_children_foreach() function */
struct subtree_search {
	proto_tree *tree; /**< The matching tree that we found */
	gint      hf;     /**< The type of tree that we are looking for. */
};

/*-----------------------------------------------------------------------------------------------*/
/** \brief Function to see if a node is of a particular type and return it if it is a tree.
 *
 *  @param pn   A pointer to the proto_node being looked at.
 *  @param data A pointer to the subtree_search structure with search criteria and results.
 */
static void compare_subtree(proto_node *pn, gpointer data)
{
	struct subtree_search *search_struct;
	search_struct = (struct subtree_search *)data;

	if(pn && pn->finfo && pn->finfo->hfinfo && pn->finfo->hfinfo->id == search_struct->hf) {
		search_struct->tree = proto_item_get_subtree(pn);
	}
} /* compare_subtree() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Function to search child trees (one level) for a tree of a specific type.
 *
 *  @param tree A pointer to the proto_tree being looked at.
 *  @param hf   The register hfinfo id that we are looking for.
 *  @return     The tree that was found or NULL if it was not found.
 */
static proto_tree *find_subtree(
	proto_tree *tree,
	gint hf)
{
	struct subtree_search search_struct;

	if(tree == NULL || hf == -1) return(NULL);
	search_struct.tree = NULL;
	search_struct.hf = hf;
	proto_tree_children_foreach(tree, compare_subtree, &search_struct);
	return(search_struct.tree);
} /* find_subtree() */


/*-----------------------------------------------------------------------------------------------*/
/** \brief Computes the analysis results based on the data in the analysis data struct.
 *
 *   @param ad A pointer to the f5eth_analysis_data_t struct
 */
static void perform_analysis(struct f5eth_analysis_data_t *ad)
{
	/** Tests that apply to ingress TCP non-frags */
	if(ad->pkt_ingress == 1 && ad->ip_istcp == 1 && ad->tcp_visited == 1 && ad->ip_isfrag == 0) {

		/** If this is an inbound SYN and there is a flow ID, we might have a problem. */
		if( ad->tcp_synset == 1 &&
			ad->tcp_ackset == 0 &&
			ad->pkt_has_flow == 1 )
		{
			ad->analysis_flowreuse = 1;
			ad->analysis_hasresults = 1;
		}

		/** If this is an inbound packet with the ACK flag set and there is no flow, we might have
		 *  a problem. */
		if( ad->tcp_ackset == 1 &&
			ad->pkt_has_flow == 0 )
		{
			ad->analysis_flowlost = 1;
			ad->analysis_hasresults = 1;
		}

	}

	ad->analysis_done = 1;
} /* perform_analysis() */



/*-----------------------------------------------------------------------------------------------*/
/** \brief Puts the results of the F5 Ethernet trailer analysis into the protocol tree.
 *
 *   @param tvb   A pointer to a TV buffer for the packet.
 *   @param pinfo A pointer to the packet info struction for the packet
 *   @param tree  A pointer to the protocol tree structure
 *   @param ad    A pointer to the intra-noise information data
 */
static void render_analysis(
	tvbuff_t       *tvb,
	packet_info    *pinfo,
	proto_tree     *tree,
	const struct f5eth_analysis_data_t *ad)
{
	proto_item *pi;
	if (ad == NULL || ad->analysis_hasresults == 0)
		return;

	pi = proto_tree_add_item(tree, hf_analysis, tvb, 0, 0, ENC_NA);
	PROTO_ITEM_SET_GENERATED(pi);
	if(ad->analysis_flowreuse) {
		expert_add_info(pinfo, pi, &ei_f5eth_flowreuse);
	}
	if(ad->analysis_flowlost) {
		expert_add_info(pinfo, pi, &ei_f5eth_flowlost);
	}
} /* render_analysis() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Tap call back to retrieve information about the IP headers.
 */
static tap_packet_status ip_tap_pkt(
	void *tapdata _U_,
	packet_info *pinfo,
	epan_dissect_t *edt _U_,
	const void *data
) {
	struct f5eth_analysis_data_t *ad;
	const ws_ip4 *iph;

	ad = (struct f5eth_analysis_data_t*)p_get_proto_data(wmem_file_scope(), pinfo,
		proto_f5ethtrailer, 0);
	if(ad == NULL) return(TAP_PACKET_DONT_REDRAW);	/* No F5 information */
	if(ad->ip_visited == 1) return(TAP_PACKET_DONT_REDRAW);
	ad->ip_visited = 1;

	if(data == NULL) return(TAP_PACKET_DONT_REDRAW);
	iph = (const ws_ip4 *)data;

	/* Only care about TCP at this time */
	/* We wait until here to make this check so that if TCP in encapsulated in something else, we
	 * don't work on the encapsulated header.  So, we only want to work on TCP if it associated
	 * with the first IP header (not if it's embedded in an ICMP datagram or some sort of tunnel).
	 */
	if(iph->ip_proto != IP_PROTO_TCP) {
		ad->ip_istcp = 0;
		return(TAP_PACKET_DONT_REDRAW);
	}

	ad->ip_istcp = 1;
	ad->ip_isfrag = ((iph->ip_off & IP_OFFSET_MASK) || (iph->ip_off & IP_MF)) ? 1 : 0;

	return(TAP_PACKET_REDRAW);
} /* ip_tap_pkt() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Tap call back to retrieve information about the IPv6 headers.
 */
static tap_packet_status ipv6_tap_pkt(
	void *tapdata _U_,
	packet_info *pinfo,
	epan_dissect_t *edt _U_,
	const void *data
) {
	struct f5eth_analysis_data_t *ad;
	const struct ws_ip6_hdr *ipv6h;

	ad = (struct f5eth_analysis_data_t*)p_get_proto_data(wmem_file_scope(), pinfo,
		proto_f5ethtrailer, 0);
	if(ad == NULL) return(TAP_PACKET_DONT_REDRAW);	/* No F5 information */
	if(ad->ip_visited == 1) return(TAP_PACKET_DONT_REDRAW);
	ad->ip_visited = 1;

	if(data == NULL) return(TAP_PACKET_DONT_REDRAW);
	ipv6h = (const struct ws_ip6_hdr *)data;

	/* Only care about TCP at this time */
	/* We wait until here to make this check so that if TCP in encapsulated in something else, we
	 * don't work on the encapsulated header.  So, we only want to work on TCP if it associated
	 * with the first IP header (not if it's embedded in an ICMP datagram or some sort of tunnel.
	 */
	/* Note that this only works if TCP is the first next header.  If there are other IPv6 headers,
	 * we will not see the fact that it is TCP (limitation of IPv6 tap).  This becomes a problem if
	 * there are hop_by_hop or routing headers or other (non-fragment) IPv6 headers.  If it's a
	 * fragment, we don't care anyways (too much effort). */
	if(ipv6h->ip6h_nxt != IP_PROTO_TCP) {
		ad->ip_istcp = 0;
		return(TAP_PACKET_DONT_REDRAW);
	}

	ad->ip_istcp = 1;

	return(TAP_PACKET_REDRAW);
} /* ipv6_tap_pkt() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Tap call back to retrieve information about the TCP headers.
 */
static tap_packet_status tcp_tap_pkt(
	void *tapdata _U_,
	packet_info *pinfo,
	epan_dissect_t *edt _U_,
	const void *data
) {
	struct f5eth_analysis_data_t *ad;
	const tcp_info_t *tcph;

	ad = (struct f5eth_analysis_data_t*)p_get_proto_data(wmem_file_scope(), pinfo,
		proto_f5ethtrailer, 0);
	if(ad == NULL) return(TAP_PACKET_DONT_REDRAW);	/* No F5 information */
	if(ad->tcp_visited == 1) return(TAP_PACKET_DONT_REDRAW);
	ad->tcp_visited = 1;

	if(data == NULL) return(TAP_PACKET_DONT_REDRAW);
	tcph = (const tcp_info_t *)data;

	ad->tcp_synset = (tcph->th_flags & TH_SYN) ? 1 : 0;
	ad->tcp_ackset = (tcph->th_flags & TH_ACK) ? 1 : 0;

	/** Only do this if the trailer dissector ran. */
	if(ad->pkt_ingress != 3 && ad->analysis_done == 0) {
		perform_analysis(ad);
		/** If there were results from the analysis, go find the tree and try to insert them. */
		if(ad->analysis_hasresults == 1) {
			proto_tree *tree;

			/** This was the first opportunity to run, so add anything necessary to the tree. */
			/* If we don't find a tree, we could theoretically anchor it to the top-tree.  However,
			 * this situation should not happen since, if we know the ingress property, then the
			 * trailer dissector ran and probably created a subtree, so it should most always be
			 * there.  If it is not there, it could be because there is nothing of interest to a
			 * filter in the f5ethtrailer protocol, so it didn't create a tree (so probably don't
			 * want to blindly tie this to the top-tree).  Other causes would warrant further
			 * investigation as to why it couldn't be found. */
			if((tree = find_subtree(edt->tree, proto_f5ethtrailer)) != NULL)
				render_analysis(edt->tvb, pinfo, tree, ad);
		}
	}

	return(TAP_PACKET_REDRAW);
} /* tcp_tap_pkt() */

/* End of analysis functions */
/*===============================================================================================*/


/* Used to determine if an address is an IPv4 address represented as an IPv6
 * address. */
static const guint8 ipv4as6prefix[] =
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
static const guint8 f5rtdomprefix[] =
	{ 0x26, 0x20, 0, 0, 0x0c, 0x10, 0xf5, 0x01, 0, 0 };

#define F5_IPV6ADDR_LEN 16

/*---------------------------------------------------------------------------*/
/* Display an IPv6 encoded IPv4 addr in an IPv4 field if appropriate. */
static proto_item *displayIPv6as4(
	proto_tree         *tree,
	int                 addrfield,
	int                 rtdomfield,
	tvbuff_t           *tvb,
	int                 offset,
	gboolean            hidden
) {
	proto_item *pi = NULL;

	if(tvb_memeql(tvb, offset, ipv4as6prefix, sizeof(ipv4as6prefix)) == 0) {
		if(addrfield >= 0) {
			pi = proto_tree_add_item(tree, addrfield, tvb, offset+(int)sizeof(ipv4as6prefix), 4, ENC_BIG_ENDIAN);
			if(hidden) PROTO_ITEM_SET_HIDDEN(pi);
		}
	} else if(tvb_memeql(tvb, offset, f5rtdomprefix, sizeof(f5rtdomprefix)) == 0) {
		/* Route domain information may show up here if the traffic is between tmm and the BIG-IP
		 * host (e.g. monitor traffic).  If so, break it up and render it for ease of viewing (and
		 * searching).  Ignore the incorrect addresses used by 10.0.x (solution 10511) as these
		 * will hopefully not be common. */
		/* These are technically backwards as we are probably returning the wrong pi.  However,
		 * when configuring, people usually see route domain after the address, so that is why this
		 * particular ordering is used (and none of the callers currently use the return value). */
		if(addrfield >= 0) {
			pi = proto_tree_add_item(tree, addrfield, tvb, offset+(int)sizeof(f5rtdomprefix)+2, 4, ENC_BIG_ENDIAN);
			if(hidden) PROTO_ITEM_SET_HIDDEN(pi);
		}
		if(rtdomfield >= 0) {
			pi = proto_tree_add_item(tree, rtdomfield, tvb, offset+(int)sizeof(f5rtdomprefix), 2, ENC_BIG_ENDIAN);
			if(hidden) PROTO_ITEM_SET_HIDDEN(pi);
		}
	}

	return(pi);
} /* displayIPv6as4() */


/*---------------------------------------------------------------------------*/
/* High level trailers */
static guint
dissect_high_trailer(
	tvbuff_t       *tvb,
	packet_info    *pinfo,
	proto_tree     *tree,
	guint           offset,
	guint8          trailer_length,
	guint8          trailer_ver,
	f5eth_tap_data_t *tdata)
{
	proto_item *pi;
	guint       o;
	guint8      ipproto;

	switch(trailer_ver) {
	case 0:
		if(trailer_length != F5_HIV0_LEN) return(0);
		break;
	default:
		return(0);
	}

	/* We do not need to do anything if we don't have a tree */
	if(tree == NULL) return(trailer_length);

	o = offset;

	proto_tree_add_item(tree, hf_type, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	proto_tree_add_item(tree, hf_length, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	proto_tree_add_item(tree, hf_version, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;

	if(tdata->peer_flow == 0) {
		proto_tree_add_item(tree, hf_peer_nopeer, tvb, o, trailer_length-3, ENC_NA);
		return(trailer_length);
	}

	/* Add in the high order structures. */
	ipproto = tvb_get_guint8(tvb,o);
	proto_tree_add_item(tree, hf_peer_ipproto,   tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	proto_tree_add_item(tree, hf_peer_vlan,      tvb, o, 2, ENC_BIG_ENDIAN);
	o += 2;

	/* peer remote address */
#ifdef F5_POP_OTHERFIELDS
	if(pop_other_fields) {
		displayIPv6as4(tree, hf_ip_ipaddr, -1, tvb, o, TRUE);
		pi = proto_tree_add_item(tree, hf_ip6_ip6addr, tvb, o, 16, ENC_NA);
		PROTO_ITEM_SET_HIDDEN(pi);
	}
#endif
	displayIPv6as4(tree, hf_peer_remote_addr, hf_peer_remote_rtdom, tvb, o, FALSE);
	displayIPv6as4(tree, hf_peer_ipaddr, hf_peer_rtdom, tvb, o, TRUE);
	proto_tree_add_item(tree, hf_peer_remote_ip6addr, tvb, o, 16, ENC_NA);
	pi = proto_tree_add_item(tree, hf_peer_ip6addr, tvb, o, 16, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(pi);
	o += 16;

	/* peer local address */
#ifdef F5_POP_OTHERFIELDS
	if(pop_other_fields) {
		displayIPv6as4(tree, hf_ip_ipaddr, -1, tvb, o, TRUE);
		pi = proto_tree_add_item(tree, hf_ip6_ip6addr, tvb, o, 16, ENC_NA);
		PROTO_ITEM_SET_HIDDEN(pi);
	}
#endif
	displayIPv6as4(tree, hf_peer_local_addr, hf_peer_local_rtdom, tvb, o, FALSE);
	displayIPv6as4(tree, hf_peer_ipaddr, hf_peer_rtdom, tvb, o, TRUE);
	proto_tree_add_item(tree, hf_peer_local_ip6addr, tvb, o, 16, ENC_NA);
	pi = proto_tree_add_item(tree, hf_peer_ip6addr, tvb, o, 16, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(pi);
	o += 16;

#ifdef F5_POP_OTHERFIELDS
	/* If there is no proto in the trailer, go get it from the actual packet
	 * information. */
	if(pop_other_fields && ipproto == 0) {
		ipproto = ptype_to_ipproto(pinfo->ptype);
	}
#endif

	/* peer remote port */
#ifdef F5_POP_OTHERFIELDS
	if(pop_other_fields) {
		switch (ipproto)
		{
		case IP_PROTO_TCP:
			pi = proto_tree_add_item(tree, hf_tcp_tcpport, tvb, o, 2, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			break;
		case IP_PROTO_UDP:
			pi = proto_tree_add_item(tree, hf_udp_udpport, tvb, o, 2, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			break;
		}
	}
#endif
	proto_tree_add_item(tree, hf_peer_remote_port, tvb, o, 2, ENC_BIG_ENDIAN);
	pi = proto_tree_add_item(tree, hf_peer_port, tvb, o, 2, ENC_BIG_ENDIAN);
	PROTO_ITEM_SET_HIDDEN(pi);
	o += 2;

	/* peer remote port */
#ifdef F5_POP_OTHERFIELDS
	if(pop_other_fields) {
		switch (ipproto)
		{
		case IP_PROTO_TCP:
			pi = proto_tree_add_item(tree, hf_tcp_tcpport, tvb, o, 2, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			break;
		case IP_PROTO_UDP:
			pi = proto_tree_add_item(tree, hf_udp_udpport, tvb, o, 2, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			break;
		}
	}
#endif
	proto_tree_add_item(tree, hf_peer_local_port, tvb, o, 2, ENC_BIG_ENDIAN);
	pi = proto_tree_add_item(tree, hf_peer_port, tvb, o, 2, ENC_BIG_ENDIAN);
	PROTO_ITEM_SET_HIDDEN(pi);

	return(trailer_length);
} /* dissect_high_trailer() */


/*---------------------------------------------------------------------------*/
/* Medium level trailers */
static guint
dissect_med_trailer(
	tvbuff_t       *tvb,
	packet_info    *pinfo _U_,
	proto_tree     *tree,
	guint           offset,
	guint8          trailer_length,
	guint8          trailer_ver,
	f5eth_tap_data_t *tdata)
{
	proto_item *pi;
	guint       o;
	guint       rstcauselen = 0;
	guint       rstcausever = 0xff;

	switch(trailer_ver) {
	case 0:
		if(trailer_length != F5_MEDV11_LEN &&
		   trailer_length != F5_MEDV10_LEN &&
		   trailer_length != F5_MEDV94_LEN)
		{
			return(0);
		}
		break;
	case 1:
		if(trailer_length < F5_MEDV1_LENMIN) { /* too small */ return(0); }
		rstcauselen = F5TRL_MEDV1_RSTCLEN(tvb,offset);
		/* check size is valid */
		if(rstcauselen + F5_MEDV1_LENMIN != trailer_length) { return(0); }

		if(rstcauselen) rstcausever = F5TRL_MEDV1_RSTCVER(tvb,offset);
		/* If we want the RST cause in the summary, we need to do it here,
		 * before the tree check below */
		if(rstcauselen && rstcause_in_info) {
			if(rstcausever == 0x00) {
				col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "[F5RST%s: %s]",
					F5TRL_MEDV1_RSTCPEER(tvb, offset) ? "(peer)" : "",
					tvb_get_string_enc(wmem_packet_scope(), tvb, offset+F5_MEDV1_LENMIN+9,
						rstcauselen-9, ENC_ASCII));
			}
		}

		break;
	case 2:
		if(trailer_length < F5_MEDV2_LENMIN) { /* too small */ return(0); }
		rstcauselen = F5TRL_MEDV2_RSTCLEN(tvb,offset);
		/* check size is valid */
		if(rstcauselen + F5_MEDV2_LENMIN != trailer_length) { return(0); }

		if(rstcauselen) rstcausever = F5TRL_MEDV2_RSTCVER(tvb,offset);
		/* If we want the RST cause in the summary, we need to do it here,
		 * before the tree check below */
		if(rstcauselen && rstcause_in_info) {
			if(rstcausever == 0x00) {
				col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "[F5RST%s: %s]",
					F5TRL_MEDV2_RSTCPEER(tvb, offset) ? "(peer)" : "",
					tvb_get_string_enc(wmem_packet_scope(), tvb, offset+F5_MEDV2_LENMIN+9,
						rstcauselen-9, ENC_ASCII));
			}
		}

		break;
	case 3:
		if(trailer_length < F5_MEDV3_LENMIN) { /* too small */ return(0); }
		rstcauselen = F5TRL_MEDV3_RSTCLEN(tvb,offset);
		/* check size is valid */
		if(rstcauselen + F5_MEDV3_LENMIN != trailer_length) { return(0); }

		if(rstcauselen) rstcausever = F5TRL_MEDV3_RSTCVER(tvb,offset);
		/* If we want the RST cause in the summary, we need to do it here,
		 * before the tree check below */
		if(rstcauselen && rstcause_in_info) {
			if(rstcausever == 0x00) {
				col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "[F5RST%s: %s]",
					F5TRL_MEDV3_RSTCPEER(tvb, offset) ? "(peer)" : "",
					tvb_get_string_enc(wmem_packet_scope(), tvb, offset+F5_MEDV3_LENMIN+9,
						rstcauselen-9, ENC_ASCII));
			}
		}

		break;
	default:
		return(0);
	}

	/* We do not need to do anything more if we don't have a tree and we are not performing
	 * analysis */
	if(pref_perform_analysis == FALSE && tree == NULL) return(trailer_length);

	o = offset;

	proto_tree_add_item(tree, hf_type, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	proto_tree_add_item(tree, hf_length, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	proto_tree_add_item(tree, hf_version, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;

	/* After 9.4, flow IDs and flags and type are here in medium */
	if(trailer_length != F5_MEDV94_LEN || trailer_ver > 0) {
		if(trailer_length == F5_MEDV10_LEN && trailer_ver == 0) {
			/* In v10, flowIDs are 32bit */
			tdata->flow = tvb_get_ntohl(tvb,o);
			proto_tree_add_item(tree, hf_flow_id, tvb, o, 4, ENC_BIG_ENDIAN);
			pi = proto_tree_add_item(tree, hf_any_flow, tvb, o, 4, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			o += 4;
			tdata->peer_flow = tvb_get_ntohl(tvb,o);
			proto_tree_add_item(tree, hf_peer_id, tvb, o, 4, ENC_BIG_ENDIAN);
			pi = proto_tree_add_item(tree, hf_any_flow, tvb, o, 4, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			o += 4;
		} else {
			/* After v10, flowIDs are 64bit */
			tdata->flow = tvb_get_ntoh64(tvb,o);
			proto_tree_add_item(tree, hf_flow_id, tvb, o, 8, ENC_BIG_ENDIAN);
			pi = proto_tree_add_item(tree, hf_any_flow, tvb, o, 8, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			o += 8;
			tdata->peer_flow = tvb_get_ntoh64(tvb,o);
			proto_tree_add_item(tree, hf_peer_id, tvb, o, 8, ENC_BIG_ENDIAN);
			pi = proto_tree_add_item(tree, hf_any_flow, tvb, o, 8, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			o += 8;
		}
		tdata->flows_set = 1;
		if(trailer_ver >= 3) {
			proto_tree_add_item(tree, hf_cf_flags2, tvb, o, 4, ENC_BIG_ENDIAN);
			o += 4;
		}
		proto_tree_add_item(tree, hf_cf_flags, tvb, o, 4, ENC_BIG_ENDIAN);
		o += 4;
		proto_tree_add_item(tree, hf_flow_type, tvb, o, 1, ENC_BIG_ENDIAN);
		o += 1;
	}

	/* We do not need to do anything if we don't have a tree */
	/* Needed to get here so that analysis and tap will work. */
	if(tree == NULL) return(trailer_length);

	proto_tree_add_item(tree, hf_ha_unit, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	if(trailer_ver == 0 && (trailer_length == F5_MEDV94_LEN || trailer_length == F5_MEDV10_LEN)) {
		proto_tree_add_item(tree, hf_ingress_slot, tvb, o, 2, ENC_LITTLE_ENDIAN);
		o += 2;
		proto_tree_add_item(tree, hf_ingress_port, tvb, o, 2, ENC_LITTLE_ENDIAN);
		o += 2;
	} else {
		/* V11 fixed the byte order of these */
		proto_tree_add_item(tree, hf_ingress_slot, tvb, o, 2, ENC_BIG_ENDIAN);
		o += 2;
		proto_tree_add_item(tree, hf_ingress_port, tvb, o, 2, ENC_BIG_ENDIAN);
		o += 2;
	}
	if(trailer_ver >= 2) {
		proto_tree_add_item(tree, hf_priority, tvb, o, 1, ENC_BIG_ENDIAN);
		o += 1;
	}
	if(trailer_ver >= 1) {
		if(rstcauselen) {
			proto_tree *rc_tree;
			proto_item *rc_item;
			guint64 rstcauseval;
			guint64 rstcauseline;
			guint   startcause;
			guint8  rstcausepeer;

			rc_item = proto_tree_add_item(tree, hf_rstcause, tvb, o, rstcauselen+1, ENC_NA);
			rc_tree = proto_item_add_subtree(rc_item, ett_f5ethtrailer_rstcause);
			proto_tree_add_item(rc_tree, hf_rstcause_len, tvb, o, 1, ENC_BIG_ENDIAN);
			o += 1;

			startcause = o;
			switch(rstcausever) {
			case 0x00:
				rstcausepeer = tvb_get_guint8(tvb,o) & 0x1;

				proto_tree_add_item(rc_tree, hf_rstcause_ver, tvb, o, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(rc_tree, hf_rstcause_peer, tvb, o, 1, ENC_BIG_ENDIAN);
				o += 1;

				rstcauseval  = tvb_get_ntoh64(tvb,o);
				rstcauseline = (rstcauseval & 0x000000000000ffffLL);
				rstcauseval  = (rstcauseval & 0xffffffffffff0000LL) >> 16;
				proto_tree_add_uint64_format_value(rc_tree, hf_rstcause_val, tvb, o, 6,
					rstcauseval, "0x%012" G_GINT64_MODIFIER "x", rstcauseval);
				proto_tree_add_item(rc_tree, hf_rstcause_line, tvb, o+6, 2, ENC_BIG_ENDIAN);
				o += 8;

				proto_item_append_text(rc_item, ": [%" G_GINT64_MODIFIER "x:%" G_GINT64_MODIFIER
					"u]%s %s", rstcauseval, rstcauseline, rstcausepeer ? " {peer}" : "",
					tvb_get_string_enc(wmem_packet_scope(), tvb, o, rstcauselen-(o-startcause),
					ENC_ASCII));
				proto_tree_add_item(rc_tree, hf_rstcause_txt, tvb, o, rstcauselen-(o-startcause),
					ENC_ASCII|ENC_NA);
				break;
			default:
				break;
			}
		}
	}

	return(trailer_length);
} /* dissect_med_trailer() */


/*---------------------------------------------------------------------------*/
/* Low level trailers */
static guint
dissect_low_trailer(
	tvbuff_t       *tvb,
	packet_info    *pinfo,
	proto_tree     *tree,
	guint           offset,
	guint8          trailer_length,
	guint8          trailer_ver,
	f5eth_tap_data_t *tdata)
{
	proto_item *pi;
	guint       ingress;
	guint       o;
	guint       vipnamelen = VIP_NAME_LEN;
	guint       slot_display = 0;
	gint        slot_display_field = -1;
	guint       tmm;

	switch(trailer_ver) {
	case 0:
		if(trailer_length != F5_LOWV10_LEN && trailer_length != F5_LOWV94_LEN) {
			return(0);
		}
		if(trailer_length == F5_LOWV94_LEN) {
			slot_display = tvb_get_guint8(tvb, offset + F5_OFF_LOW_SLOT);
			slot_display_field = hf_slot0;
			/* Analysis doesn't care about the virtual name, only populate if there is a tap active */
			if(have_tap_listener(tap_f5ethtrailer)
			   && tvb_get_guint8(tvb, offset + (F5_LOWV94_LEN-16)) != 0)
			{
				tdata->virtual_name = tvb_get_string_enc(wmem_packet_scope(), tvb,
					offset + (F5_LOWV94_LEN-16), 16, ENC_ASCII);
			}
		} else {
			slot_display = tvb_get_guint8(tvb, offset + F5_OFF_LOW_SLOT) + 1;
			slot_display_field = hf_slot1;
			/* Analysis doesn't care about the virtual name, only populate if there is a tap active */
			if(have_tap_listener(tap_f5ethtrailer)
			   && tvb_get_guint8(tvb, offset + (F5_LOWV10_LEN-16)) != 0)
			{
				tdata->virtual_name = tvb_get_string_enc(wmem_packet_scope(), tvb,
					offset + (F5_LOWV10_LEN-16), 16, ENC_ASCII);
			}
		}
		break;
	case 1:
		if(trailer_length < F5_LOWV1_LENMIN) { /* too small */ return(0); }
		vipnamelen = F5TRL_LOWV1_VIPLEN(tvb,offset);
		/* check size is valid */
		if(vipnamelen + F5_LOWV1_LENMIN != trailer_length) { return(0); }
		slot_display = tvb_get_guint8(tvb, offset + F5_OFF_LOW_SLOT) + 1;
		slot_display_field = hf_slot1;
		/* Analysis doesn't care about the virtual name, only populate if there is a tap active */
		if(vipnamelen > 0 && have_tap_listener(tap_f5ethtrailer)) {
			tdata->virtual_name = tvb_get_string_enc(wmem_packet_scope(), tvb,
				offset + F5_LOWV1_LENMIN, vipnamelen, ENC_ASCII);
		}
		break;
	default:
		return(0);
	}

	ingress = tvb_get_guint8(tvb, offset + F5_OFF_LOW_ING);
	tdata->ingress = ingress == 0 ? 0 : 1;
	tmm = tvb_get_guint8(tvb,offset + F5_OFF_LOW_TMM);
	if(tmm < F5ETH_TAP_TMM_MAX && slot_display < F5ETH_TAP_SLOT_MAX) {
		tdata->tmm  = tmm;
		tdata->slot = slot_display;
	}
	/* Is the column visible? */
	if (pref_info_type != none) {
		f5eth_set_info_col(pinfo, ingress, slot_display, tmm);
	}

	/* We do not need to do anything more if we don't have a tree and we are not performing
	 * analysis and this is not v9.4.  If v9.4, need to continue to get flow
	 * information.*/
	if(pref_perform_analysis == FALSE && tree == NULL
		&& !(trailer_length == F5_LOWV94_LEN && trailer_ver == 0
		     && have_tap_listener(tap_f5ethtrailer)))
	{
		return(trailer_length);
	}

	o = offset;

	proto_tree_add_item(tree, hf_type, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	proto_tree_add_item(tree, hf_length, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	proto_tree_add_item(tree, hf_version, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;

	/* Use special formatting here so that users do not have to filter on "IN"
	 * and "OUT", but rather can continue to use typical boolean values.  "IN"
	 * and "OUT" are provided as convenience. */
	proto_tree_add_boolean_format_value(tree, hf_ingress, tvb,
			o, 1, ingress, "%s (%s)",
			ingress ? tfs_true_false.true_string : tfs_true_false.false_string,
			ingress ? f5tfs_ing.true_string : f5tfs_ing.false_string);
	o++;

	proto_tree_add_uint(tree, slot_display_field, tvb, o, 1, slot_display);
	o += 1;

	proto_tree_add_item(tree, hf_tmm, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	if(trailer_length == F5_LOWV94_LEN && trailer_ver == 0) {
		/* In v9.4, flowIDs, flags and type are here in low */
		tdata->flow = tvb_get_ntohl(tvb,o);
		proto_tree_add_item(tree, hf_flow_id, tvb, o, 4, ENC_BIG_ENDIAN);
		pi = proto_tree_add_item(tree, hf_any_flow, tvb, o, 4, ENC_BIG_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(pi);
		o += 4;
		tdata->peer_flow = tvb_get_ntohl(tvb,o);
		proto_tree_add_item(tree, hf_peer_id, tvb, o, 4, ENC_BIG_ENDIAN);
		pi = proto_tree_add_item(tree, hf_any_flow, tvb, o, 4, ENC_BIG_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(pi);
		o += 4;
		tdata->flows_set = 1;
		proto_tree_add_item(tree, hf_cf_flags, tvb, o, 4, ENC_BIG_ENDIAN);
		o += 4;
		proto_tree_add_item(tree, hf_flow_type, tvb, o, 1, ENC_BIG_ENDIAN);
		o += 1;
	}

	/* We do not need to do anything more if we don't have a tree */
	/* Needed to get here so that analysis will work. */
	if(tree == NULL) return(trailer_length);

	if(trailer_ver == 1) {
		pi = proto_tree_add_item(tree, hf_vipnamelen, tvb, o, 1, ENC_BIG_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(pi);
		o += 1;
	}
	proto_tree_add_item(tree, hf_vip, tvb, o, vipnamelen, ENC_ASCII|ENC_NA);

	return(trailer_length);
} /* dissect_low_trailer() */


static void
render_f5dptv1_tlvhdr(
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	void *data _U_,
	gint offset
) {
	proto_tree_add_item(tree, hf_provider, tvb, offset+F5_DPT_V1_TLV_PROVIDER_OFF,
			F5_DPT_V1_TLV_PROVIDER_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_type,     tvb, offset+F5_DPT_V1_TLV_TYPE_OFF,
			F5_DPT_V1_TLV_TYPE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_length,   tvb, offset+F5_DPT_V1_TLV_LENGTH_OFF,
			F5_DPT_V1_TLV_LENGTH_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_version,  tvb, offset+F5_DPT_V1_TLV_VERSION_OFF,
			F5_DPT_V1_TLV_VERSION_LEN, ENC_BIG_ENDIAN);
} /* render_f5dptv1_tlvhdr() */


/*---------------------------------------------------------------------------*/
/** \brief Render the data for DPT high noise trailer TLV
 *
 *   @param tvb    The tvbuff containing the TLV block (header and data)
 *   @param pinfo  The pinfo structure for the frame
 *   @param tree   The tree to render the TVB under
 *   @param data   Pointer to tdata for the trailer
 *   @return       The size of the TVB
 */
static int
dissect_dpt_trailer_noise_high(
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	void *data
) {
	proto_item *pi;
	gint        o;
	gint        len;
	gint        ver;
	guint8      ipproto;
	f5eth_tap_data_t *tdata = (f5eth_tap_data_t *)data;

	DISSECTOR_ASSERT(tdata != NULL);
	len = tvb_get_ntohs(tvb, F5_DPT_V1_TLV_LENGTH_OFF);
	ver = tvb_get_ntohs(tvb, F5_DPT_V1_TLV_VERSION_OFF);

	/* Unknown version, cannot do anything */
	if(ver != 1) {
		return(0);
	}

	if(tree == NULL) {
		/* We do not need to do anything if we do not have a tree */
		return(len);
	}

	pi = proto_tree_add_item(tree, hf_high_id, tvb, 0, len, ENC_NA);
	tree = proto_item_add_subtree(pi, ett_f5ethtrailer_high);

	render_f5dptv1_tlvhdr(tvb, pinfo, tree, data, 0);

	o = F5_DPT_V1_TLV_HDR_LEN;

	/* If there was no peer id in the medium trailer, then there is no peer flow information to
	 * render; skip it all.
	 */
	if(tdata->peer_flow == 0) {
		proto_tree_add_item(tree, hf_peer_nopeer, tvb, o, len-o, ENC_NA);
		return(len);
	}

	/* Add in the high order structures. */
	ipproto = tvb_get_guint8(tvb,o);
	proto_tree_add_item(tree, hf_peer_ipproto,   tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	proto_tree_add_item(tree, hf_peer_vlan,      tvb, o, 2, ENC_BIG_ENDIAN);
	o += 2;

	/* peer remote address */
#ifdef F5_POP_OTHERFIELDS
	if(pop_other_fields) {
		displayIPv6as4(tree, hf_ip_ipaddr, -1, tvb, o, TRUE);
		pi = proto_tree_add_item(tree, hf_ip6_ip6addr, tvb, o, 16, ENC_NA);
		PROTO_ITEM_SET_HIDDEN(pi);
	}
#endif
	displayIPv6as4(tree, hf_peer_remote_addr, hf_peer_remote_rtdom, tvb, o, FALSE);
	displayIPv6as4(tree, hf_peer_ipaddr, hf_peer_rtdom, tvb, o, TRUE);
	proto_tree_add_item(tree, hf_peer_remote_ip6addr, tvb, o, 16, ENC_NA);
	pi = proto_tree_add_item(tree, hf_peer_ip6addr, tvb, o, 16, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(pi);
	o += 16;

	/* peer local address */
#ifdef F5_POP_OTHERFIELDS
	if(pop_other_fields) {
		displayIPv6as4(tree, hf_ip_ipaddr, -1, tvb, o, TRUE);
		pi = proto_tree_add_item(tree, hf_ip6_ip6addr, tvb, o, 16, ENC_NA);
		PROTO_ITEM_SET_HIDDEN(pi);
	}
#endif
	displayIPv6as4(tree, hf_peer_local_addr, hf_peer_local_rtdom, tvb, o, FALSE);
	displayIPv6as4(tree, hf_peer_ipaddr, hf_peer_rtdom, tvb, o, TRUE);
	proto_tree_add_item(tree, hf_peer_local_ip6addr, tvb, o, 16, ENC_NA);
	pi = proto_tree_add_item(tree, hf_peer_ip6addr, tvb, o, 16, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(pi);
	o += 16;

	/* peer remote port */
#ifdef F5_POP_OTHERFIELDS
	if(pop_other_fields) {
		switch (ipproto)
		{
		case IP_PROTO_TCP:
			pi = proto_tree_add_item(tree, hf_tcp_tcpport, tvb, o, 2, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			break;
		case IP_PROTO_UDP:
			pi = proto_tree_add_item(tree, hf_udp_udpport, tvb, o, 2, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			break;
		}
	}
#endif
	proto_tree_add_item(tree, hf_peer_remote_port, tvb, o, 2, ENC_BIG_ENDIAN);
	pi = proto_tree_add_item(tree, hf_peer_port, tvb, o, 2, ENC_BIG_ENDIAN);
	PROTO_ITEM_SET_HIDDEN(pi);
	o += 2;

	/* peer remote port */
#ifdef F5_POP_OTHERFIELDS
	if(pop_other_fields) {
		switch (ipproto)
		{
		case IP_PROTO_TCP:
			pi = proto_tree_add_item(tree, hf_tcp_tcpport, tvb, o, 2, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			break;
		case IP_PROTO_UDP:
			pi = proto_tree_add_item(tree, hf_udp_udpport, tvb, o, 2, ENC_BIG_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(pi);
			break;
		}
	}
#endif
	proto_tree_add_item(tree, hf_peer_local_port, tvb, o, 2, ENC_BIG_ENDIAN);
	pi = proto_tree_add_item(tree, hf_peer_port, tvb, o, 2, ENC_BIG_ENDIAN);
	PROTO_ITEM_SET_HIDDEN(pi);

	return(len);
} /* dissect_dpt_trailer_noise_high() */


/*---------------------------------------------------------------------------*/
/** \brief Render the data for DPT medium noise trailer TVB
 *
 *   @param tvb    The tvbuff containing the TLV block (header and data)
 *   @param pinfo  The pinfo structure for the frame
 *   @param tree   The tree to render the TVB under
 *   @param data   Pointer to tdata for the trailer
 *   @return       The size of the TVB
 */
static int
dissect_dpt_trailer_noise_med(
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	void *data
) {
	proto_item *pi;
	gint        o;
	int         rstcauselen = 0;
	int         badrstcauselen = 0;
	guint       rstcausever = 0xff;
	gint        len;
	gint        ver;
	f5eth_tap_data_t *tdata = (f5eth_tap_data_t *)data;

	DISSECTOR_ASSERT(tdata != NULL);
	len = tvb_get_ntohs(tvb, F5_DPT_V1_TLV_LENGTH_OFF);
	ver = tvb_get_ntohs(tvb, F5_DPT_V1_TLV_VERSION_OFF);

	/* Unknown version, cannot do anything */
	if(ver != 4) {
		return(0);
	}

	pi = proto_tree_add_item(tree, hf_med_id, tvb, 0, len, ENC_NA);
	tree = proto_item_add_subtree(pi, ett_f5ethtrailer_med);

	render_f5dptv1_tlvhdr(tvb, pinfo, tree, data, 0);

	o = F5_DPT_V1_TLV_HDR_LEN;
	rstcauselen = F5TRL_MEDV4_RSTCLEN(tvb,o);
	/* Check for an invalid reset cause length and do not try to reference any of the data if it is
	 * bad
	 */
	if(tvb_reported_length_remaining(tvb, o + F5_MEDV4_LENMIN) < rstcauselen) {
	    badrstcauselen = 1;
		/* Set this to zero to prevent processing of things that utilze it */
		rstcauselen = 0;
	}
	if(rstcauselen) rstcausever = F5TRL_MEDV4_RSTCVER(tvb,o);
	/* If we want the RST cause in the summary, we need to do it here,
	 * before the tree check below */
	if(rstcauselen && rstcause_in_info) {
		if(rstcausever == 0x00) {
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "[F5RST%s: %s]",
				F5TRL_MEDV4_RSTCPEER(tvb, o) ? "(peer)" : "",
				tvb_get_string_enc(wmem_packet_scope(), tvb, o+F5_MEDV4_LENMIN+9,
					rstcauselen-9, ENC_ASCII));
		}
	}

	/* We do not need to do anything more if we don't have a tree and we are not performing
	 * analysis */
	if(pref_perform_analysis == FALSE && tree == NULL) return(len);

	tdata->flow = tvb_get_ntoh64(tvb,o);
	proto_tree_add_item(tree, hf_flow_id,   tvb, o, 8, ENC_BIG_ENDIAN);
	pi = proto_tree_add_item(tree, hf_any_flow,  tvb, o, 8, ENC_BIG_ENDIAN);
	PROTO_ITEM_SET_HIDDEN(pi);
	o += 8;
	tdata->peer_flow = tvb_get_ntoh64(tvb,o);
	proto_tree_add_item(tree, hf_peer_id,   tvb, o, 8, ENC_BIG_ENDIAN);
	pi = proto_tree_add_item(tree, hf_any_flow,  tvb, o, 8, ENC_BIG_ENDIAN);
	PROTO_ITEM_SET_HIDDEN(pi);
	o += 8;
	tdata->flows_set = 1;
	proto_tree_add_item(tree, hf_cf_flags2, tvb, o, 4, ENC_BIG_ENDIAN);
	o += 4;
	proto_tree_add_item(tree, hf_cf_flags,   tvb, o, 4, ENC_BIG_ENDIAN);
	o += 4;
	proto_tree_add_item(tree, hf_flow_type,  tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;

	/* We do not need to do anything if we don't have a tree */
	/* Needed to get here so that analysis and tap will work. */
	if(tree == NULL) {
		return(len);
	}

	proto_tree_add_item(tree, hf_ha_unit,      tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	proto_tree_add_item(tree, hf_ingress_slot, tvb, o, 2, ENC_BIG_ENDIAN);
	o += 2;
	proto_tree_add_item(tree, hf_ingress_port, tvb, o, 2, ENC_BIG_ENDIAN);
	o += 2;
	proto_tree_add_item(tree, hf_priority,     tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	if(badrstcauselen) {
		proto_tree *rc_tree;
		proto_item *rc_item;

		rc_item = proto_tree_add_item(tree, hf_rstcause, tvb, o, len-o, ENC_NA);
		rc_tree = proto_item_add_subtree(rc_item, ett_f5ethtrailer_rstcause);
		rc_item = proto_tree_add_item(rc_tree, hf_rstcause_len, tvb, o, 1, ENC_BIG_ENDIAN);
		expert_add_info(pinfo, rc_item, &ei_f5eth_badlen);
	} else if(rstcauselen) {
		proto_tree *rc_tree;
		proto_item *rc_item;
		guint64 rstcauseval;
		guint64 rstcauseline;
		guint   startcause;
		guint8  rstcausepeer;

		rc_item = proto_tree_add_item(tree, hf_rstcause, tvb, o, rstcauselen+1, ENC_NA);
		rc_tree = proto_item_add_subtree(rc_item, ett_f5ethtrailer_rstcause);
		proto_tree_add_item(rc_tree, hf_rstcause_len, tvb, o, 1, ENC_BIG_ENDIAN);
		o += 1;

		startcause = o;
		switch(rstcausever) {
		case 0x00:
			rstcausepeer = tvb_get_guint8(tvb,o) & 0x1;

			proto_tree_add_item(rc_tree, hf_rstcause_ver,  tvb, o, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(rc_tree, hf_rstcause_peer, tvb, o, 1, ENC_BIG_ENDIAN);
			o += 1;

			rstcauseval  = tvb_get_ntoh64(tvb,o);
			rstcauseline = (rstcauseval & 0x000000000000ffffLL);
			rstcauseval  = (rstcauseval & 0xffffffffffff0000LL) >> 16;
			proto_tree_add_uint64_format_value(rc_tree, hf_rstcause_val, tvb, o, 6,
				rstcauseval, "0x%012" G_GINT64_MODIFIER "x", rstcauseval);
			proto_tree_add_item(rc_tree, hf_rstcause_line, tvb, o+6, 2, ENC_BIG_ENDIAN);
			o += 8;

			proto_item_append_text(rc_item, ": [%" G_GINT64_MODIFIER "x:%" G_GINT64_MODIFIER
				"u]%s %s", rstcauseval, rstcauseline, rstcausepeer ? " {peer}" : "",
				tvb_get_string_enc(wmem_packet_scope(), tvb, o, rstcauselen-(o-startcause),
				ENC_ASCII));
			proto_tree_add_item(rc_tree, hf_rstcause_txt, tvb, o, rstcauselen-(o-startcause),
				ENC_ASCII|ENC_NA);
			/*o = startcause + rstcauselen;*/
			break;
		default:
			break;
		}
	}

	return(len);
} /* dissect_dpt_trailer_noise_med() */


/*---------------------------------------------------------------------------*/
/** \brief Render the data for DPT low noise trailer TVB
 *
 *   @param tvb    The tvbuff containing the TLV block (header and data)
 *   @param pinfo  The pinfo structure for the frame
 *   @param tree   The tree to render the TVB under
 *   @param data   Pointer to tdata for the trailer
 *   @return       The size of the TVB
 */
static int
dissect_dpt_trailer_noise_low(
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	void *data
) {
	proto_item *pi;
	guint       ingress;
	gint        o;
	int         vipnamelen;
	int         badvipnamelen = 0;
	guint       slot_display = 0;
	guint       tmm;
	gint        len;
	gint        ver;
	f5eth_tap_data_t *tdata = (f5eth_tap_data_t *)data;

	DISSECTOR_ASSERT(tdata != NULL);
	len = tvb_get_ntohs(tvb, F5_DPT_V1_TLV_LENGTH_OFF);
	ver = tvb_get_ntohs(tvb, F5_DPT_V1_TLV_VERSION_OFF);

	/* Unknown version, cannot do anything */
	if(ver != 2) {
		return(0);
	}

	pi = proto_tree_add_item(tree, hf_low_id, tvb, 0, len, ENC_NA);
	tree = proto_item_add_subtree(pi, ett_f5ethtrailer_low);

	render_f5dptv1_tlvhdr(tvb, pinfo, tree, data, 0);

	o = F5_DPT_V1_TLV_HDR_LEN;

	/* Direction */
	ingress = tvb_get_guint8(tvb, o);
	tdata->ingress = ingress == 0 ? 0 : 1;
	/* Slot */
	slot_display = tvb_get_guint8(tvb, o + 1) + 1;
	/* TMM */
	tmm = tvb_get_guint8(tvb, o + 2);
	if(tmm < F5ETH_TAP_TMM_MAX && slot_display < F5ETH_TAP_SLOT_MAX) {
		tdata->tmm  = tmm;
		tdata->slot = slot_display;
	}
	/* VIP Name */
	vipnamelen = tvb_get_guint8(tvb, o + 3);
	/* Check for an invalid vip name length and do not try to reference any of the data if it is
	 * bad
	 */
	if(tvb_reported_length_remaining(tvb, o + 4) < vipnamelen) {
		badvipnamelen = 1;
		/* Set this to zero to prevent processing of things that utilze it */
		vipnamelen = 0;
	}
	if(vipnamelen > 0 && have_tap_listener(tap_f5ethtrailer)) {
		tdata->virtual_name = tvb_get_string_enc(wmem_packet_scope(), tvb,
			o + 4, vipnamelen, ENC_ASCII);
	}

	/* Is the column visible? */
	if(pref_info_type != none) {
		f5eth_set_info_col(pinfo, ingress, slot_display, tmm);
	}

	/* We do not need to do anything more if we don't have a tree. */
	if(tree == NULL) {
		return(len);
	}

	/* Use special formatting here so that users do not have to filter on "IN"
	 * and "OUT", but rather can continue to use typical boolean values.  "IN"
	 * and "OUT" are provided as convenience. */
	proto_tree_add_boolean_format_value(tree, hf_ingress, tvb,
			o, 1, ingress, "%s (%s)",
			ingress ? tfs_true_false.true_string : tfs_true_false.false_string,
			ingress ? f5tfs_ing.true_string : f5tfs_ing.false_string);
	o++;

	proto_tree_add_uint(tree, hf_slot1, tvb, o, 1, slot_display);
	o += 1;

	proto_tree_add_item(tree, hf_tmm, tvb, o, 1, ENC_BIG_ENDIAN);
	o += 1;
	pi = proto_tree_add_item(tree, hf_vipnamelen, tvb, o, 1, ENC_BIG_ENDIAN);
	if(badvipnamelen) {
		expert_add_info(pinfo, pi, &ei_f5eth_badlen);
		/* Cannot go any further */
		return(len);
	}
	o += 1;
	proto_tree_add_item(tree, hf_vip, tvb, o, vipnamelen, ENC_ASCII|ENC_NA);

	return(len);
} /* dissect_dpt_trailer_noise_low() */


/*---------------------------------------------------------------------------*/
/* \brief Render the data for DPT noise provider TVB
 *
 *   @param tvb    The tvbuff containing the packet data for this TLV
 *   @param pinfo  The pinfo structure for the frame
 *   @param tree   The tree to render the TVB under
 *   @param data   Pointer to tdata for the trailer
 *   @return       The size of the TVB
 */
static int
dissect_dpt_trailer_noise(
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	void *data
) {
	f5eth_tap_data_t   *tdata = (f5eth_tap_data_t *)data;
	int                 processed;

	switch(tvb_get_ntohs(tvb, F5_DPT_V1_TLV_TYPE_OFF)) {
		case F5TYPE_LOW:
			processed = dissect_dpt_trailer_noise_low(tvb, pinfo, tree, data);
			if(processed > 0) {
				tdata->noise_low = 1;
			}
			break;
		case F5TYPE_MED:
			processed = dissect_dpt_trailer_noise_med(tvb, pinfo, tree, data);
			if(processed > 0)
				tdata->noise_med = 1;
			break;
		case F5TYPE_HIGH:
			processed = dissect_dpt_trailer_noise_high(tvb, pinfo, tree, data);
			if(processed > 0)
				tdata->noise_high = 1;
			break;
		default:
			/* Skip unknown TLV types */
			processed = 0;
			break;
	}
	return(processed);
} /* dissect_dpt_trailer_noise() */


/*---------------------------------------------------------------------------*/
/* \brief Render the data for DPT TVB for an unknown provider
 *
 *   @param tvb    The tvbuff containing the packet data for this DPT
 *   @param pinfo  The pinfo structure for the frame
 *   @param tree   The tree to render the TVB under
 *   @param data   Pointer to tdata for the trailer
 *   @return       The size of the TVB
 */
static int
dissect_dpt_trailer_unknown(
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	void *data
) {
	proto_item *pi;
	gint        len;

	len = tvb_get_ntohs(tvb, F5_DPT_V1_TLV_LENGTH_OFF);

	if(tree) {
		pi = proto_tree_add_item(tree, hf_dpt_unknown, tvb, 0, len, ENC_NA);
		tree = proto_item_add_subtree(pi, ett_f5ethtrailer_unknown);

		render_f5dptv1_tlvhdr(tvb, pinfo, tree, data, 0);

		proto_tree_add_item(tree, hf_data,     tvb, F5_DPT_V1_TLV_HDR_LEN,
				len - F5_DPT_V1_TLV_HDR_LEN, ENC_NA);
	}

	return(len);
} /* dissect_dpt_trailer_unknown() */


/*---------------------------------------------------------------------------*/
/* \brief Render the data for DPT block
 *
 *   @param tvb    The tvbuff containing the packet data for this DPT block
 *   @param pinfo  The pinfo structure for the frame
 *   @param tree   The tree to render the DPT block in
 *   @param data   Pointer to tdata for the trailer
 *   @return       The size of the DPT block
 */
static int
dissect_dpt_trailer(
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	void *data
) {
	proto_item *pi;
	gint        dpt_len;
	gint        dpt_ver;
	gint        o; /* offset*/

	dpt_len = tvb_get_ntohs(tvb, F5_DPT_V1_HDR_LENGTH_OFF);
	dpt_ver = tvb_get_ntohs(tvb, F5_DPT_V1_HDR_VERSION_OFF);

	/* Render the DPT header */
	proto_tree_add_item(tree, hf_dpt_magic, tvb, F5_DPT_V1_HDR_MAGIC_OFF,
			F5_DPT_V1_HDR_MAGIC_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dpt_len,   tvb, F5_DPT_V1_HDR_LENGTH_OFF,
			F5_DPT_V1_HDR_LENGTH_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dpt_ver,   tvb, F5_DPT_V1_HDR_VERSION_OFF,
			F5_DPT_V1_HDR_VERSION_LEN, ENC_BIG_ENDIAN);

	/* If this is an unknown version, return after rendering header and data */
	if(dpt_ver < F5_DPT_V1_HDR_VERSION_MIN || dpt_ver > F5_DPT_V1_HDR_VERSION_MAX ) {
		proto_tree_add_item(tree, hf_data, tvb, F5_DPT_V1_HDR_LEN,
				dpt_len - F5_DPT_V1_HDR_LEN, ENC_NA);
		return(dpt_len);
	}

	o = F5_DPT_V1_HDR_LEN;

	while(tvb_reported_length_remaining(tvb, o) >= F5_DPT_V1_TLV_HDR_LEN) {
		tvbuff_t   *tvb_dpt_tlv;
		gint        tvb_dpt_tlv_len;
		gint        provider_id;

		tvb_dpt_tlv_len = tvb_get_ntohs(tvb, o+F5_DPT_V1_TLV_LENGTH_OFF);
		/* Report an error if the length specified in the header is either
		 *   Not long enough to contain the header
		 *   Indicates that the TLV is longer than the data that would have been captured.
		 */
		if(tvb_dpt_tlv_len < F5_DPT_V1_TLV_HDR_LEN
		   || tvb_dpt_tlv_len > tvb_reported_length_remaining(tvb, o))
		{
			proto_tree *subtree;
			pi = proto_tree_add_item(tree, hf_dpt_unknown, tvb, o,
					F5_DPT_V1_TLV_HDR_LEN, ENC_NA);
			subtree = proto_item_add_subtree(pi, ett_f5ethtrailer_unknown);
			proto_tree_add_item(subtree, hf_provider, tvb, o + F5_DPT_V1_TLV_PROVIDER_OFF,
					F5_DPT_V1_TLV_PROVIDER_LEN, ENC_BIG_ENDIAN);
			proto_tree_add_item(subtree, hf_type,     tvb, o + F5_DPT_V1_TLV_TYPE_OFF,
					F5_DPT_V1_TLV_TYPE_LEN, ENC_BIG_ENDIAN);
			pi = proto_tree_add_item(subtree, hf_length,   tvb, o + F5_DPT_V1_TLV_LENGTH_OFF,
					F5_DPT_V1_TLV_LENGTH_LEN, ENC_BIG_ENDIAN);
			expert_add_info(pinfo, pi, &ei_f5eth_badlen);
			if(tvb_dpt_tlv_len >= F5_DPT_V1_TLV_HDR_LEN) {
				proto_tree_add_item(subtree, hf_version,  tvb, o + F5_DPT_V1_TLV_VERSION_OFF,
						F5_DPT_V1_TLV_VERSION_LEN, ENC_BIG_ENDIAN);
			}
			/* If the length here is bad, then we probably will not index to the next TLV, so
			 * abort and do not try to render anymore TLVs.
			 */
			break;
		}
		provider_id = tvb_get_ntohs(tvb, o+F5_DPT_V1_TLV_PROVIDER_OFF);
		tvb_dpt_tlv = tvb_new_subset_length(tvb, o, tvb_dpt_tlv_len);
		if(dissector_try_uint_new(provider_subdissector_table, provider_id, tvb_dpt_tlv, pinfo,
				tree, FALSE, data) == 0)
		{
			/* Render the TLV header as unknown */
			dissect_dpt_trailer_unknown(tvb_dpt_tlv, pinfo, tree, data);
		}
		o += tvb_dpt_tlv_len;
	}

	return(dpt_len);
} /* dissect_dpt_trailer() */



/*---------------------------------------------------------------------------*/
/* Main dissector entry point for the trailer data
 *
 * TODO Technically, this dissector should return FALSE if it did not find a
 *      valid trailer.  It always returns TRUE at this point.  Since this is
 *      not currently in shipping WS code and only people who are interested
 *      will load it, it's probably not that big of a deal.
 */
static gboolean
dissect_f5ethtrailer(
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	void *data _U_
) {
	proto_tree *type_tree = NULL;
	proto_item *ti = NULL;
	proto_item *trailer_item = NULL;
	struct f5eth_analysis_data_t *ad;
	guint       offset = 0;
	guint       start = 0;
	guint       processed;
	guint       type;
	guint8      len;
	guint8      ver;
	f5eth_tap_data_t *tdata;

	/* Initialize data structure for taps and analysis */
	tdata = wmem_new0(wmem_packet_scope(), f5eth_tap_data_t);

	tdata->magic        = F5ETH_TAP_MAGIC;
	tdata->slot         = F5ETH_TAP_SLOT_MAX;
	tdata->tmm          = F5ETH_TAP_TMM_MAX;

	/* While we still have data in the trailer.  For legacy trailers, this needs
	 * type, length, version (3 bytes) and for new format trailers, the magic header (4 bytes).
	 * All legacy trailers are at least 4 bytes long, so just check for length of magic.
	 */
	while(tvb_reported_length_remaining(tvb, offset) > F5_DPT_V1_HDR_MAGIC_LEN) {
		processed = 0;

		/* Check for new format trailer. (Magic number and at least enough bytes for a header) */
		if(tvb_get_ntohl(tvb,offset) == F5_DPT_V1_HDR_MAGIC
		   && tvb_reported_length_remaining(tvb, offset) >= F5_DPT_V1_HDR_LEN)
		{
			tvbuff_t *tvb_dpt;
			gint dpt_len;

			dpt_len = tvb_get_ntohs(tvb,offset+F5_DPT_V1_HDR_LENGTH_OFF);
			/* Only process this if the length specified in the header is both
			 *   At least as long as the header
			 *   Less than or equal to the data that would have been captured
			 */
			if(dpt_len >= F5_DPT_V1_HDR_LEN
			   && dpt_len <= tvb_reported_length_remaining(tvb, offset))
			{
				tvb_dpt = tvb_new_subset_length(tvb, offset, dpt_len);
				if(trailer_item == NULL && tree) {
					start = offset;
					trailer_item = proto_tree_add_item(tree, proto_f5ethtrailer, tvb,
							start, 0, ENC_NA);
					tree = proto_item_add_subtree(trailer_item, ett_f5ethtrailer);
				}
				dissect_dpt_trailer(tvb_dpt, pinfo, tree, tdata);
				processed = dpt_len;
				tdata->trailer_len += dpt_len;
			}
		}

		type = F5TRAILER_TYPE(tvb, offset);
		len  = F5TRAILER_LEN(tvb, offset);
		ver  = F5TRAILER_VER(tvb, offset);

		/* If there was no new format trailer (processed == 0), need to check for legacy */
		if(processed == 0 && len <= tvb_reported_length_remaining(tvb, offset)
		   && type >= F5TYPE_LOW && type <= F5TYPE_HIGH
		   && len >= F5_MIN_SANE && len <= F5_MAX_SANE
		   && ver <= F5TRAILER_VER_MAX)
		{
			if(trailer_item == NULL && tree)
			{
				start = offset;
				trailer_item = proto_tree_add_item(tree, proto_f5ethtrailer, tvb, start, 0, ENC_NA);
				tree = proto_item_add_subtree(trailer_item, ett_f5ethtrailer);
			}

			/* Parse out the specified trailer. */
			switch(type) {

			case F5TYPE_LOW:
				ti = proto_tree_add_item(tree, hf_low_id, tvb, offset, len, ENC_NA);
				type_tree = proto_item_add_subtree(ti, ett_f5ethtrailer_low);

				processed = dissect_low_trailer(tvb, pinfo, type_tree, offset, len, ver, tdata);
				if(processed == 0) {
					proto_item_set_len(ti, 1);
				} else {
					tdata->trailer_len += processed;
					tdata->noise_low = 1;
				}
				break;

			case F5TYPE_MED:
				ti = proto_tree_add_item(tree, hf_med_id, tvb, offset, len, ENC_NA);
				type_tree = proto_item_add_subtree(ti, ett_f5ethtrailer_med);

				processed = dissect_med_trailer(tvb, pinfo, type_tree, offset, len, ver, tdata);
				if(processed == 0) {
					proto_item_set_len(ti, 1);
				} else {
					tdata->trailer_len += processed;
					tdata->noise_med = 1;
				}
				break;

			case F5TYPE_HIGH:
				ti = proto_tree_add_item(tree, hf_high_id, tvb, offset, len, ENC_NA);
				type_tree = proto_item_add_subtree(ti, ett_f5ethtrailer_high);

				processed = dissect_high_trailer(tvb, pinfo, type_tree, offset, len, ver, tdata);
				if(processed == 0) {
					proto_item_set_len(ti, 1);
				} else {
					tdata->trailer_len += processed;
					tdata->noise_high = 1;
				}
				break;
			}
		}

		if(processed == 0) {
			/* If we've fallen out due to pkt noise, move one and try again. */
			offset++;
		} else {
			offset += processed;
		}
	}

	proto_item_set_len(trailer_item, offset - start);

	if(pref_perform_analysis) {
		/* Get the analysis data information for this packet */
		ad = (struct f5eth_analysis_data_t*)p_get_proto_data(wmem_file_scope(), pinfo,
			proto_f5ethtrailer, 0);
		if(ad == NULL) {
			ad = new_f5eth_analysis_data_t();
			p_add_proto_data(wmem_file_scope(), pinfo, proto_f5ethtrailer, 0, ad);
		}
		if(ad->analysis_done == 0) {
			ad->pkt_ingress = tdata->ingress;
			if(tdata->flows_set == 1) {
				ad->pkt_has_flow = tdata->flow == 0 ? 0 : 1;
				ad->pkt_has_peer = tdata->peer_flow == 0 ? 0 : 1;
			}
			/* Only perform the analysis if we had an opportunity to get the TCP information.  In
			 * this case, if the ip tap ran then they all should have run.  We use IP so we don't
			 * perform analysis every time we visit a UDP/ICMP, etc. packet. */
			if(ad->ip_visited)
				perform_analysis(ad);
		}
		render_analysis(tvb, pinfo, tree, ad);
	}

	/* Call tap handlers if it appears that we got enough data
	 * (should have low noise if there is anything) */
	if(tdata->noise_low != 0) {
		tap_queue_packet(tap_f5ethtrailer, pinfo, tdata);
	}
	return TRUE;
} /* dissect_f5ethtrailer() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Initialization routine called before first pass through a capture.
*/
static void proto_init_f5ethtrailer(void)
{
	/** Need to set display_slot to TRUE when initially reading a capture.  This covers the
	 *  situation when a user loads a capture that turns off slot display and then loads a
	 *  different capture that contains trailers, but does not have the F5INFO frame.  In this
	 *  case, we need to turn the slot display back on. */
	display_slot = TRUE;
	/* Set the info column function to use based on whether or not an in/out only
	 * preference is chosen. */
	switch (pref_info_type)
	{
	case in_out_only:
	case brief_in_out_only:
		f5eth_set_info_col = f5eth_set_info_col_inout;
		break;
	default:
		f5eth_set_info_col = f5eth_set_info_col_slot;
		break;
	}

	/* If we are doing analysis, enable the tap listeners */
	if(pref_perform_analysis) {
		GString *error_string;

		error_string = register_tap_listener("ip", &tap_ip_enabled, NULL, TL_REQUIRES_NOTHING, NULL, ip_tap_pkt, NULL, NULL);
		if (error_string) {
			g_warning("Unable to register tap \"ip\" for f5ethtrailer: %s", error_string->str);
			g_string_free(error_string, TRUE);
		}
		error_string = register_tap_listener("ipv6", &tap_ipv6_enabled, NULL, TL_REQUIRES_NOTHING, NULL, ipv6_tap_pkt, NULL, NULL);
		if (error_string) {
			g_warning("Unable to register tap \"ipv6\" for f5ethtrailer: %s", error_string->str);
			g_string_free(error_string, TRUE);
		}
		error_string = register_tap_listener("tcp", &tap_tcp_enabled, NULL, TL_REQUIRES_NOTHING, NULL, tcp_tap_pkt, NULL, NULL);
		if (error_string) {
			g_warning("Unable to register tap \"tcp\" for f5ethtrailer: %s", error_string->str);
			g_string_free(error_string, TRUE);
		}
	}
}

/** Cleanup after closing a capture file. */
static void
f5ethtrailer_cleanup(void)
{
	remove_tap_listener(&tap_tcp_enabled);
	remove_tap_listener(&tap_ipv6_enabled);
	remove_tap_listener(&tap_ip_enabled);
}

static void f5ethtrailer_prefs(void)
{
	wmem_free(NULL, info_format_in_only);
	wmem_free(NULL, info_format_out_only);
	wmem_free(NULL, info_format_in_slot);
	wmem_free(NULL, info_format_out_slot);
	wmem_free(NULL, info_format_in_noslot);
	wmem_free(NULL, info_format_out_noslot);

	/* Set the set of format specifier strings to use based on whether or not one of the
	 * brief preferences is chosen */
	switch (pref_info_type)
	{
	case brief:
	case brief_in_out_only:
		if(pref_brief_inout_chars != NULL && strlen(pref_brief_inout_chars) >= 2) {
			info_format_in_only     = wmem_strdup_printf(NULL, "%c: ", pref_brief_inout_chars[0]);
			info_format_out_only    = wmem_strdup_printf(NULL, "%c: ", pref_brief_inout_chars[1]);
			info_format_in_slot     = wmem_strdup_printf(NULL, "%c%%u/%%-2u: ", pref_brief_inout_chars[0]);
			info_format_out_slot    = wmem_strdup_printf(NULL, "%c%%u/%%-2u: ", pref_brief_inout_chars[1]);
			info_format_in_noslot   = wmem_strdup_printf(NULL, "%ct%%-2u: ", pref_brief_inout_chars[0]);
			info_format_out_noslot  = wmem_strdup_printf(NULL, "%ct%%-2u: ", pref_brief_inout_chars[1]);
		} else {
			info_format_in_only     = wmem_strdup(NULL, ">: ");
			info_format_out_only    = wmem_strdup(NULL, "<: ");
			info_format_in_slot     = wmem_strdup(NULL, ">%u/%-2u: ");
			info_format_out_slot    = wmem_strdup(NULL, "<%u/%-2u: ");
			info_format_in_noslot   = wmem_strdup(NULL, ">t%-2u: ");
			info_format_out_noslot  = wmem_strdup(NULL, "<t%-2u: ");
		}
		break;
	default:
		info_format_in_only = wmem_strdup(NULL, info_format_full_in_only);
		info_format_out_only = wmem_strdup(NULL, info_format_full_out_only);
		info_format_in_slot = wmem_strdup(NULL, info_format_full_in_slot);
		info_format_out_slot = wmem_strdup(NULL, info_format_full_out_slot);
		info_format_in_noslot = wmem_strdup(NULL, info_format_full_in_noslot);
		info_format_out_noslot = wmem_strdup(NULL, info_format_full_out_noslot);
		break;
	}
}

void proto_register_f5ethtrailer (void)
{
	module_t *f5ethtrailer_module;

	/* A header field is something you can search/filter on.
	 *
	 * We create a structure to register our fields. It consists of an
	 * array of hf_register_info structures, each of which are of the format
	 * {&(field id), {name, abrv, type, display, strs, bitmask, blurb, HFILL}}.
	 */
	static hf_register_info hf[] = {
		{ &hf_provider,
		  { "Provider", "f5ethtrailer.provider", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_type,
		  { "Type", "f5ethtrailer.type", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_length,
		  { "Trailer length", "f5ethtrailer.length", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_version,
		  { "Version", "f5ethtrailer.version", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_dpt_unknown,
		  { "Unknown trailer", "f5ethtrailer.unknown_trailer", FT_NONE, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_data,
		  { "Data", "f5ethtrailer.data", FT_BYTES, SEP_SPACE, NULL,
		    0x0, NULL, HFILL }
		},

	/* Low parameters */
		{ &hf_low_id,
		  { "Low Details", "f5ethtrailer.low", FT_NONE, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_ingress,
		  { "Ingress", "f5ethtrailer.ingress", FT_BOOLEAN, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_slot0,
		  { "Slot (0-based)", "f5ethtrailer.slot", FT_UINT8, BASE_DEC, NULL,
		    0x0, "Slot captured on", HFILL }
		},
		{ &hf_slot1,
		  { "Slot (1-based)", "f5ethtrailer.slot", FT_UINT8, BASE_DEC, NULL,
		    0x0, "Slot captured on", HFILL }
		},
		{ &hf_tmm,
		  { "TMM (0-based)", "f5ethtrailer.tmm", FT_UINT8, BASE_DEC, NULL,
		    0x0, "TMM captured on", HFILL }
		},
		{ &hf_vipnamelen,
		  { "VIP name length", "f5ethtrailer.vipnamelen", FT_UINT8, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_vip,
		  { "VIP", "f5ethtrailer.vip", FT_STRING, BASE_NONE, NULL,
		    0x0, "VIP flow associated with", HFILL }
		},

	/* Medium parameters */
		{ &hf_med_id,
		  { "Medium Details", "f5ethtrailer.medium", FT_NONE, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_any_flow,
		  { "Flow ID or peer flow ID", "f5ethtrailer.anyflowid", FT_UINT64, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_flow_id,
		  { "Flow ID", "f5ethtrailer.flowid", FT_UINT64, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_peer_id,
		  { "Peer ID", "f5ethtrailer.peerid", FT_UINT64, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_cf_flags,
		  { "Connflow Flags", "f5ethtrailer.cfflags", FT_UINT32, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_cf_flags2,
		  { "Connflow Flags High Bits", "f5ethtrailer.cfflags2", FT_UINT32,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_flow_type,
		  { "Flow Type", "f5ethtrailer.flowtype", FT_UINT8, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_ha_unit,
		  { "HA Unit", "f5ethtrailer.haunit", FT_UINT8, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_ingress_slot,
		  { "Ingress Slot", "f5ethtrailer.ingressslot", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_ingress_port,
		  { "Ingress Port", "f5ethtrailer.ingressport", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_priority,
		  { "Priority", "f5ethtrailer.priority", FT_UINT8, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_rstcause,
		  { "RST cause", "f5ethtrailer.rstcause", FT_NONE, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_rstcause_len,
		  { "Length", "f5ethtrailer.rstcauselen", FT_UINT8, BASE_DEC,
		    NULL, 0x0, "RST cause length", HFILL }
		},
		{ &hf_rstcause_ver,
		  { "Version", "f5ethtrailer.rstcausever", FT_UINT8, BASE_DEC_HEX,
		    NULL, 0xfe, "RST cause version", HFILL }
		},
		{ &hf_rstcause_peer,
		  { "Peer", "f5ethtrailer.rstcausepeer", FT_UINT8, BASE_DEC,
		    NULL, 0x01, "RST cause peer", HFILL }
		},
		{ &hf_rstcause_val,
		  { "Value", "f5ethtrailer.rstcauseval", FT_UINT64, BASE_HEX,
		    NULL, 0x0, "RST cause value", HFILL }
		},
		{ &hf_rstcause_line,
		  { "Line", "f5ethtrailer.rstcauseline", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "RST cause line", HFILL }
		},
		{ &hf_rstcause_txt,
		  { "Cause", "f5ethtrailer.rstcausetxt", FT_STRING, BASE_NONE,
		    NULL, 0x0, "RST cause", HFILL }
		},

	/* High parameters */
		{ &hf_high_id,
		  { "High Details", "f5ethtrailer.high", FT_NONE, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_peer_ipproto,
		  { "Peer IP Protocol", "f5ethtrailer.peeripproto", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }
		},
		{ &hf_peer_vlan,
		  { "Peer VLAN", "f5ethtrailer.peervlan", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_peer_remote_addr,
		  { "Peer remote address", "f5ethtrailer.peerremoteaddr", FT_IPv4,
		    BASE_NONE, NULL, 0x0, "Peer remote IPv4 address", HFILL }
		},
		{ &hf_peer_remote_ip6addr,
		  { "Peer remote address", "f5ethtrailer.peerremoteaddr6", FT_IPv6,
		    BASE_NONE, NULL, 0x0, "Peer remote IPv6 address", HFILL }
		},
		{ &hf_peer_local_addr,
		  { "Peer local address", "f5ethtrailer.peerlocaladdr", FT_IPv4,
		    BASE_NONE, NULL, 0x0, "Peer local IPv4 address", HFILL }
		},
		{ &hf_peer_local_ip6addr,
		  { "Peer local address", "f5ethtrailer.peerlocaladdr6", FT_IPv6,
		    BASE_NONE, NULL, 0x0, "Peer local IPv6 address", HFILL }
		},
		{ &hf_peer_ipaddr,
		  { "Peer remote or local address", "f5ethtrailer.peeraddr", FT_IPv4,
		    BASE_NONE, NULL, 0x0, "Peer IPv4 address", HFILL }
		},
		{ &hf_peer_ip6addr,
		  { "Peer remote or local address", "f5ethtrailer.peeraddr6", FT_IPv6,
		    BASE_NONE, NULL, 0x0, "Peer IPv6 address", HFILL }
		},
		{ &hf_peer_remote_rtdom,
		  { "Peer remote route domain", "f5ethtrailer.peerremotertdom", FT_UINT16,
		    BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_peer_local_rtdom,
		  { "Peer local route domain", "f5ethtrailer.peerlocalrtdom", FT_UINT16,
		    BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_peer_rtdom,
		  { "Peer remote or local route domain", "f5ethtrailer.peerrtdom", FT_UINT16,
		    BASE_DEC, NULL, 0x0, "Peer route domain", HFILL }
		},
		{ &hf_peer_remote_port,
		  { "Peer remote port", "f5ethtrailer.peerremoteport", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }
		},
		{ &hf_peer_local_port,
		  { "Peer local port", "f5ethtrailer.peerlocalport", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }
		},
		{ &hf_peer_port,
		  { "Peer remote or local port", "f5ethtrailer.peerport", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Peer port", HFILL }
		},
		{ &hf_peer_nopeer,
		  { "No peer connection information", "f5ethtrailer.nopeer", FT_NONE, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }
		},

	/* Analysis parameters */
		{ &hf_analysis,
		  { "Analysis", "f5ethtrailer.analysis", FT_NONE, BASE_NONE, NULL,
		    0x0, "Analysis of details", HFILL }
		},

		{ &hf_dpt_magic,
		  { "Magic", "f5ethtrailer.trailer_magic", FT_UINT32, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_dpt_ver,
		  { "Version", "f5ethtrailer.trailer_version", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_dpt_len,
		  { "Length", "f5ethtrailer.trailer_length", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		}

	};

	static gint *ett[] = {
		&ett_f5ethtrailer,
		&ett_f5ethtrailer_unknown,
		&ett_f5ethtrailer_low,
		&ett_f5ethtrailer_med,
		&ett_f5ethtrailer_high,
		&ett_f5ethtrailer_rstcause
	};

	expert_module_t *expert_f5ethtrailer;
	static ei_register_info ei[] = {
		{ &ei_f5eth_flowlost,  { "f5ethtrailer.flowlost", PI_SEQUENCE, PI_WARN,
				"Flow lost, incorrect VLAN, loose initiation, tunnel, or SYN cookie use",
				EXPFILL } },
		{ &ei_f5eth_flowreuse, { "f5ethtrailer.flowreuse", PI_SEQUENCE, PI_WARN,
				"Flow reuse or SYN retransmit", EXPFILL } },
		{ &ei_f5eth_badlen, { "f5ethtrailer.badlen", PI_MALFORMED, PI_ERROR,
				"Bad length", EXPFILL } }
	};

	proto_f5ethtrailer = proto_register_protocol ("F5 Ethernet Trailer Protocol", "F5 Ethernet trailer", "f5ethtrailer");

	expert_f5ethtrailer = expert_register_protocol(proto_f5ethtrailer);
	expert_register_field_array(expert_f5ethtrailer, ei, array_length(ei));

	proto_register_field_array(proto_f5ethtrailer, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the dissector preferences */
	f5ethtrailer_module = prefs_register_protocol(proto_f5ethtrailer, f5ethtrailer_prefs);


#ifdef F5_POP_OTHERFIELDS
	prefs_register_bool_preference(f5ethtrailer_module, "pop_other_fields",
		"Populate fields for other dissectors",
		"Disable this if you do not want this dissector to populate"
		" well-known fields in other dissectors (i.e. ip.addr, ipv6.addr,"
		" tcp.port and udp.port).  Enabling this will allow filters that"
		" reference those fields to also find data in the trailers but"
		" will reduce performance.  After disabling, you should restart"
		" Wireshark to get performance back.", &pop_other_fields);
#else
	/* If we are not building with this, silently delete the preference */
	prefs_register_obsolete_preference(f5ethtrailer_module,
		"pop_other_fields");
#endif

	prefs_register_bool_preference(f5ethtrailer_module, "perform_analysis",
		"Perform analysis of trailer data",
		"Enabling this will perform analysis of the trailer data.  It will"
		" enable taps on other protocols and slow down Wireshark.",
		&pref_perform_analysis);

	prefs_register_static_text_preference(f5ethtrailer_module,
		"info_col_section", "Information column preferences",
		"The settings below affect how information from this dissector is"
		" displayed in the info column in the packet list pane.");

	prefs_register_obsolete_preference(f5ethtrailer_module, "summary_in_info");

	prefs_register_enum_preference(f5ethtrailer_module, "info_type",
		"Summary display in info column",
		"In/out only removes slot/tmm information.  Brief shortens the string"
		" to >S/T (for in) or <S/T (for out).  See \"Brief in/out characters\""
		" below.",
		(guint *)&pref_info_type, f5eth_display_strings, TRUE);

	prefs_register_string_preference(f5ethtrailer_module, "brief_inout_chars",
		"Brief in/out characters",
		"A string specifying the characters to use to represent \"in\" and"
		" \"out\" in the brief summary.  The default is \"><\" ('>' for in"
		" and '<' for out).  If this is not set or is less than two"
		" characters, the default is used.  If it is longer than two"
		" characters, the extra characters are ignored.",
		&pref_brief_inout_chars);

	prefs_register_string_preference(f5ethtrailer_module, "slots_regex",
		"Only display slot information for platforms",
		"If the platform in the F5 FILEINFO packet matches the provided regex,"
		" slot information will be displayed in the info column; otherwise, it"
		" will not.  A reasonable value is \"^(A.*|Z101)$\".  If the regex is"
		" empty or there is no platform information in the capture, slot"
		" information is always displayed.",
		&pref_slots_regex);

	prefs_register_bool_preference(f5ethtrailer_module, "rstcause_in_info",
		"Add RST cause string to info",
		"If present, include the RST cause text from the trailer in the "
		"\"info\" column of the packet list pane.",
		&rstcause_in_info);

	register_init_routine(proto_init_f5ethtrailer);
	register_cleanup_routine(f5ethtrailer_cleanup);

	/* Register dissector table for additional providers */
	provider_subdissector_table = register_dissector_table("f5ethtrailer.provider",
			"F5 Ethernet trailer provider", proto_f5ethtrailer, FT_UINT16, BASE_DEC);
	proto_f5ethtrailer_dpt_noise = proto_register_protocol_in_name_only(
			"F5 Ethernet trailer provider - Noise", "Noise", "f5ethtrailer.provider.noise",
			proto_f5ethtrailer, FT_BYTES);

	/* Analyze Menu Items */
	register_conversation_filter("f5ethtrailer", "F5 TCP", f5_tcp_conv_valid, f5_tcp_conv_filter);
	register_conversation_filter("f5ethtrailer", "F5 UDP", f5_udp_conv_valid, f5_udp_conv_filter);
	register_conversation_filter("f5ethtrailer", "F5 IP", f5_ip_conv_valid, f5_ip_conv_filter);

	/* Register the f5ethtrailer tap for statistics */
	tap_f5ethtrailer = register_tap("f5ethtrailer");

	stats_tree_register_plugin("f5ethtrailer", "f5_tmm_dist", st_str_tmmdist,
		(ST_SORT_COL_NAME << ST_FLG_SRTCOL_SHIFT),
		f5eth_tmmdist_stats_tree_packet, f5eth_tmmdist_stats_tree_init, NULL);
	stats_tree_register_plugin("f5ethtrailer", "f5_virt_dist", st_str_virtdist,
		(ST_SORT_COL_NAME << ST_FLG_SRTCOL_SHIFT),
		f5eth_virtdist_stats_tree_packet, f5eth_virtdist_stats_tree_init, NULL);

	/* Setup col info strings */
	f5ethtrailer_prefs();
} /* proto_register_f5ethtrailer() */

void proto_reg_handoff_f5ethtrailer(void)
{
	dissector_handle_t h;

	heur_dissector_add("eth.trailer", dissect_f5ethtrailer, "F5 Ethernet Trailer",
			"f5ethtrailer", proto_f5ethtrailer, HEURISTIC_DISABLE);

	/* Register helper dissectors */
	h = create_dissector_handle(dissect_dpt_trailer_noise, proto_f5ethtrailer_dpt_noise);
	dissector_add_uint("f5ethtrailer.provider", F5_DPT_PROVIDER_NOISE, h);
#ifdef F5_POP_OTHERFIELDS
	/* These fields are duplicates of other, well-known fields so that
	 * filtering on these fields will also pick up data out of the
	 * trailers.  If we do not build with this option, we do not want to
	 * define these as it will add overhead because this dissector would be
	 * called for coloring rules, etc.  As a further performance
	 * improvement, we only register these fields when the populate other
	 * fields option is enabled.  This helps this dissector not run when
	 * its fields are not referenced (if it has no intention of populating
	 * these fields).
	 */

	hf_ip_ipaddr = proto_registrar_get_id_byname("ip.addr");
	hf_ip6_ip6addr = proto_registrar_get_id_byname("ipv6.addr");
	hf_tcp_tcpport = proto_registrar_get_id_byname("tcp.port");
	hf_udp_udpport = proto_registrar_get_id_byname("udp.port");
#endif
}

/*===============================================================================================*/
/* This section is rendering the F5 tcpdump file properties packet.
 *
 * Note that this should technically have a protocol tree item, but it does not.  The data
 * rendered by this dissector should be the only data in the packet.  So, rather than requiring
 * the user to select the packet and expand the tree to view it, putting the items into the top
 * tree essentially renders them expanded.  There is no proto_tree_expand_item() sort of call that
 * can be used to do this in a data-encapsulated manner (it can be hacked, but I opted for this
 * method instead).
 */

/* Platform ID to platform name mapping
 *
 * https://support.f5.com/kb/en-us/products/big-ip_ltm/releasenotes/product/relnote-ltm-11-6-0.html
 * https://support.f5.com/csp/article/K9476
 */

static const string_string f5info_platform_strings[] = {
	{ "A100", "VIPRION B4100 Blade" },
	{ "A105", "VIPRION B4100N Blade" },
	{ "A107", "VIPRION B4200 Blade" },
	{ "A108", "VIPRION B4300 Blade" },
	{ "A109", "VIPRION B2100 Blade" },
	{ "A110", "VIPRION B4340N Blade" },
	{ "A111", "VIPRION B4200N Blade" },
	{ "A112", "VIPRION B2250 Blade" },
	{ "A113", "VIPRION B2150 Blade" },
	{ "A114", "VIPRION B4450 Blade" },
	{ "C102", "BIG-IP 1600" },
	{ "C103", "BIG-IP 3600" },
	{ "C106", "BIG-IP 3900, Enterprise Manager 4000" },
	{ "C109", "BIG-IP 5000s, 5050s, 5200v, 5250v" },
	{ "C112", "BIG-IP 2000 Series (2000s, 2200s)" },
	{ "C113", "BIG-IP 4000 Series (4000s, 4200v)" },
	{ "C114", "BIG-IP 800 (LTM only)" },
	{ "C115", "BIG-IP i4000 Series (i4600, i4800)" },
	{ "C116", "BIG-IP i10000 Series (i10600, i10800)" },
	{ "C117", "BIG-IP i2000 Series (i2600, i2800)" },
	{ "C118", "BIG-IP i7000 Series (i7600, i7800)" },
	{ "C119", "BIG-IP i5000 Series (i5600, i5800)" },
	{ "C120", "Herculon i2800" },
	{ "C121", "Herculon i5800" },
	{ "C122", "Herculon i10800" },
	{ "C123", "BIG-IP i11600, i11800" },
	{ "C124", "BIG-IP i11400-DS, i11600-DS, i11800-DS" },
	{ "C125", "BIG-IP i5820-DF" },
	{ "C126", "BIG-IP i7820-DF" },
	{ "D104", "BIG-IP 6900 Series (6900, 6900S, 6900F, 6900N)" },
	{ "D106", "BIG-IP 8900" },
	{ "D107", "BIG-IP 8950" },
	{ "D110", "BIG-IP 7000 Series (7000s, 7050s, 7055, 7200v, 7250v, 7255)" },
	{ "D111", "BIG-IP 12000 Series (12250v)" },
	{ "D112", "BIG-IP 10050 Series (10150s-NEBS, 10350v (AC), 10350v-NEBS, 10350v-FIPS)" },
	{ "D113", "BIG-IP 10000 Series (10000s, 10050s, 10055, 10200v, 10250v, 10255)" },
	{ "E101", "BIG-IP 11000" },
	{ "E102", "BIG-IP 11050, 11050 NEBS" },
	{ "E103", "11050N" },
	{ "Z100", "Virtual Edition (VE)" },
	{ "Z101", "vCMP Guest" },

	{ NULL, NULL }
};

	/* It currently looks like these do not apply. Kept for completeness only */
#if 0
	{ "C21",  "FirePass 1200" },
	{ "D46",  "FirePass 4100" },
	{ "D63",  "BIG-IP 6400-NEBS" },
	{ "D101", "FirePass 4300" },
	{ "D114", "VIPRION C2200 Chassis" },
	{ "F100", "VIPRION C2400 Chassis" },
	{ "J100", "VIPRION C4400 Chassis" },
	{ "J101", "VIPRION C4400N Chassis" },
	{ "J102", "VIPRION C4480 Chassis" },
	{ "J103", "VIPRION C4480N Chassis" },
	{ "S100", "VIPRION C4800 Chassis" },
	{ "S101", "VIPRION C4800N Chassis" },
#endif

/*---------------------------------------------------------------------------*/
/* Dissector for rendering the F5 tcpdump file properties packet.
 *
 * This is a heuristic dissector because the Ethernet dissector has a hook
 * to pass packets to a dissector before it gets rendered as Ethernet and
 * that seems to make sense here.  This could be a registered dissector on
 * the Ethertype 0x5ff, but this way it can skip a packet and let other
 * dissectors have a chance to dissect (and the Ethernet dissector does not
 * waste its time rendering Ethernet information for no reason).
 */
static gboolean
dissect_f5fileinfo(
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	void *data _U_
) {
	guint offset = 0;
	const guint8 *object;
	const gchar *platform = NULL;
	gint objlen;
	struct f5fileinfo_tap_data* tap_data;

	/* Must be the first packet */
	if(pinfo->fd->num > 1)
		return(FALSE);

	if(tvb_captured_length(tvb) >= (gint)sizeof(fileinfomagic1)) {
		if(tvb_memeql(tvb, 0, fileinfomagic1, sizeof(fileinfomagic1)) == 0)
			offset = sizeof(fileinfomagic1);
	}

	/* Didn't find the magic at the start of the packet. */
	if(offset == 0)
		return(FALSE);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FILEINFO");

	tap_data = wmem_new0(wmem_packet_scope(), struct f5fileinfo_tap_data);
	tap_data->magic = F5FILEINFO_TAP_MAGIC;

	while(tvb_captured_length_remaining(tvb,offset)) {
		object = tvb_get_const_stringz(tvb, offset, &objlen);

		if(objlen <= 0 || object == NULL)
			break;

		if(strncmp(object, "CMD: ", 5) == 0) {
			proto_tree_add_item(tree, hf_fi_command, tvb, offset+5, objlen-5, ENC_ASCII);
			col_add_str(pinfo->cinfo, COL_INFO, &object[5]);
		}
		else if(strncmp(object, "VER: ", 5) == 0) {
			guint i;
			const guint8 *c;

			proto_tree_add_item(tree, hf_fi_version, tvb, offset+5, objlen-5, ENC_ASCII|ENC_NA);
			for(c=object;  *c && (*c < '0' || *c > '9');  c++);
			for(i=0;  i<6 && *c;  c++) {
				if(*c < '0' || *c > '9') {
					i++; continue;
				}
				tap_data->ver[i] = (tap_data->ver[i] * 10) + (*c - '0');
			}
		}
		else if(strncmp(object, "HOST: ", 6) == 0)
			proto_tree_add_item(tree, hf_fi_hostname, tvb, offset+6, objlen-6, ENC_ASCII|ENC_NA);
		else if(strncmp(object, "PLAT: ", 6) == 0) {
			proto_tree_add_item(tree, hf_fi_platform, tvb, offset+6, objlen-6, ENC_ASCII|ENC_NA);
			platform = tvb_get_string_enc(wmem_packet_scope(), tvb, offset+6, objlen-6, ENC_ASCII);
			proto_tree_add_string_format(tree, hf_fi_platformname, tvb, offset+6, objlen-6, "", "%s: %s",
				platform, str_to_str(platform, f5info_platform_strings, "Unknown, please report"));
		}
		else if(strncmp(object, "PROD: ", 6) == 0)
			proto_tree_add_item(tree, hf_fi_product, tvb, offset+6, objlen-6, ENC_ASCII|ENC_NA);

		offset += objlen;
	}
	tvb_set_reported_length(tvb,offset);
	tap_queue_packet(tap_f5fileinfo, pinfo, tap_data);
	f5eth_process_f5info(platform);
	return(TRUE);
} /* dissect_f5fileinfo() */

void proto_register_f5fileinfo(void)
{
	static hf_register_info hf[] =
		{ { &hf_fi_command,
		    { "Tcpdump command line", "f5fileinfo.cmdline", FT_STRINGZ, BASE_NONE,
		      NULL, 0x0, NULL, HFILL }
		  },
		  { &hf_fi_version,
		    { "Platform version", "f5fileinfo.version", FT_STRINGZ, BASE_NONE,
		      NULL, 0x0, NULL, HFILL }
		  },
		  { &hf_fi_hostname,
		    { "Hostname", "f5fileinfo.hostname", FT_STRINGZ, BASE_NONE,
		      NULL, 0x0, NULL, HFILL }
		  },
		  { &hf_fi_platform,
		    { "Platform", "f5fileinfo.platform", FT_STRINGZ, BASE_NONE,
		      NULL, 0x0, NULL, HFILL }
		  },
		  { &hf_fi_platformname,
		    { "Platform name", "f5fileinfo.platformname", FT_STRINGZ, BASE_NONE,
		      NULL, 0x0, NULL, HFILL }
		  },
		  { &hf_fi_product,
		    { "Platform product", "f5fileinfo.product", FT_STRINGZ, BASE_NONE,
		      NULL, 0x0, NULL, HFILL }
		  },
	};

	proto_f5fileinfo = proto_register_protocol("F5 Capture Information", "FILEINFO", "f5fileinfo");
	proto_register_field_array(proto_f5fileinfo, hf, array_length(hf));

	tap_f5fileinfo = register_tap("f5fileinfo");
}

void proto_reg_handoff_f5fileinfo(void)
{
	heur_dissector_add("eth", dissect_f5fileinfo, "F5 Capture Information", "f5fileinfo", proto_f5fileinfo, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
