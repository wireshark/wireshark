/* packet-f5ethtrailer.c
 *
 * F5 Ethernet Trailer Copyright 2008-2017 F5 Networks
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
Supported Platforms:
    BIGIP 9.4.2 and later.

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
#include <wsutil/ws_printf.h>	/* for ws_g_warning */
#define F5FILEINFOTAP_SRC
#include "packet-f5ethtrailer.h"
#undef  F5FILEINFOTAP_SRC

#define PROTO_TAG_F5ETHTRAILER  "F5ETHTRAILER"

/* Wireshark ID of the F5ETHTRAILER protocol */
static int proto_f5ethtrailer = -1;
static int tap_f5ethtrailer = -1;
static int proto_f5fileinfo = -1;
static int tap_f5fileinfo = -1;

void proto_reg_handoff_f5ethtrailer(void);
void proto_register_f5ethtrailer(void);

void proto_reg_handoff_f5fileinfo(void);
void proto_register_f5fileinfo(void);

/* Common Fields */
static gint hf_type = -1;
static gint hf_length = -1;
static gint hf_version = -1;
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

static expert_field ei_f5eth_flowlost = EI_INIT;
static expert_field ei_f5eth_flowreuse = EI_INIT;

/* These are the ids of the subtrees that we may be creating */
static gint ett_f5ethtrailer          = -1;
static gint ett_f5ethtrailer_low      = -1;
static gint ett_f5ethtrailer_med      = -1;
static gint ett_f5ethtrailer_high     = -1;
static gint ett_f5ethtrailer_rstcause = -1;

/* For fileinformation */
static gint hf_fi_command          = -1;
static gint hf_fi_version          = -1;
static gint hf_fi_hostname         = -1;
static gint hf_fi_platform         = -1;
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
	st_node_tmmpktdist = stats_tree_create_node(st, st_str_tmmdist_pkts, 0, TRUE);
	stat_node_set_flags(st, st_str_tmmdist_pkts, 0, TRUE, ST_FLG_SORT_TOP);
	st_node_tmmbytedist = stats_tree_create_node(st, st_str_tmmdist_bytes, 0, TRUE);
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
 *   @return        1 if the data was actually used to alter the statistics, 0 otherwise.
 *
 */
static int f5eth_tmmdist_stats_tree_packet(
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
		return 0;

	/* Unnecessary since this tap packet function and the F5 Ethernet trailer dissector are both in
	 * the same source file.  If you are using this function as an example in a separate tap source
	 * file, you should uncomment this.
	if(check_f5eth_tap_magic(tdata) == 0) return 0;
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

	return 1;
} /* f5eth_tmmdist_stats_tree_packet() */

/*-----------------------------------------------------------------------------------------------*/
static void f5eth_virtdist_stats_tree_init(
	stats_tree *st
) {
	st_node_virtpktdist = stats_tree_create_node(st, st_str_virtdist_pkts, 0, TRUE);
	stat_node_set_flags(st, st_str_virtdist_pkts, 0, TRUE, ST_FLG_SORT_TOP);
	st_node_virtbytedist = stats_tree_create_node(st, st_str_virtdist_bytes, 0, TRUE);

	stats_tree_create_node(st, st_str_virtdist_noflow, st_node_virtpktdist, TRUE);
	stat_node_set_flags(st, st_str_virtdist_noflow, st_node_virtpktdist, TRUE, ST_FLG_SORT_TOP);
	stats_tree_create_node(st, st_str_virtdist_novirt, st_node_virtpktdist, TRUE);
	stat_node_set_flags(st, st_str_virtdist_novirt, st_node_virtpktdist, TRUE, ST_FLG_SORT_TOP);

	stats_tree_create_node(st, st_str_virtdist_noflow, st_node_virtbytedist, TRUE);
	stat_node_set_flags(st, st_str_virtdist_noflow, st_node_virtbytedist, TRUE, ST_FLG_SORT_TOP);
	stats_tree_create_node(st, st_str_virtdist_novirt, st_node_virtbytedist, TRUE);
	stat_node_set_flags(st, st_str_virtdist_novirt, st_node_virtbytedist, TRUE, ST_FLG_SORT_TOP);
} /* f5eth_virtdist_stats_tree_init() */

/*-----------------------------------------------------------------------------------------------*/
static int f5eth_virtdist_stats_tree_packet(
	stats_tree *st,
	packet_info *pinfo,
	epan_dissect_t *edt _U_,
	const void *data
) {
	const f5eth_tap_data_t *tdata = (const f5eth_tap_data_t *)data;
	guint32 pkt_len;

	if (tdata == NULL)
		return 0;
	/* Unnecessary since this tap packet function and the F5 Ethernet trailer dissector are both in
	 * the same source file.  If you are using this function as an example in a separate tap source
	 * file, you should uncomment this.
	if(check_f5eth_tap_magic(tdata) == 0) return 0;
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

	return 1;
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
 */
#define F5_MIN_SANE 7
#define F5_MAX_SANE 140


#define F5_HIV0_LEN                   42

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


/*-----------------------------------------------------------------------------------------------*/
/** \brief Retrieves the analysis data structure from the packet info.  If it doesn't exist, it
 *  creates one and attaches it.
 *
 *   @param pinfo  A pointer to the packet info to look at for the analysis data.
 *   @return       A pointer to the analysis data structure retrieved or created.  NULL if error.
 */
static struct f5eth_analysis_data_t *get_f5eth_analysis_data(packet_info *pinfo)
{
	struct f5eth_analysis_data_t *analysis_data;

	analysis_data = (struct f5eth_analysis_data_t*)p_get_proto_data(wmem_file_scope(), pinfo,
		proto_f5ethtrailer, 0);
	if(analysis_data == NULL) {
		analysis_data = new_f5eth_analysis_data_t();
		p_add_proto_data(wmem_file_scope(), pinfo, proto_f5ethtrailer, 0, analysis_data);
	}
	return(analysis_data);
} /* get_f5eth_analysis_data() */

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
static gboolean ip_tap_pkt(
	void *tapdata _U_,
	packet_info *pinfo,
	epan_dissect_t *edt _U_,
	const void *data
) {
	struct f5eth_analysis_data_t *ad = get_f5eth_analysis_data(pinfo);
	const ws_ip4 *iph;

	if(ad->ip_visited == 1) return(FALSE);
	ad->ip_visited = 1;

	if(data == NULL) return(FALSE);
	iph = (const ws_ip4 *)data;

	/* Only care about TCP at this time */
	/* We wait until here to make this check so that if TCP in encapsulated in something else, we
	 * don't work on the encapsulated header.  So, we only want to work on TCP if it associated
	 * with the first IP header (not if it's embedded in an ICMP datagram or some sort of tunnel).
	 */
	if(iph->ip_proto != IP_PROTO_TCP) {
		ad->ip_istcp = 0;
		return(FALSE);
	}

	ad->ip_istcp = 1;
	ad->ip_isfrag = ((iph->ip_off & IP_OFFSET_MASK) || (iph->ip_off & IP_MF)) ? 1 : 0;

	return(TRUE);
} /* ip_tap_pkt() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Tap call back to retrieve information about the IPv6 headers.
 */
static gboolean ipv6_tap_pkt(
	void *tapdata _U_,
	packet_info *pinfo,
	epan_dissect_t *edt _U_,
	const void *data
) {
	struct f5eth_analysis_data_t *ad = get_f5eth_analysis_data(pinfo);
	const struct ws_ip6_hdr *ipv6h;

	if(ad->ip_visited == 1) return(FALSE);
	ad->ip_visited = 1;

	if(data == NULL) return(FALSE);
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
		return(FALSE);
	}

	ad->ip_istcp = 1;

	return(TRUE);
} /* ipv6_tap_pkt() */

/*-----------------------------------------------------------------------------------------------*/
/** \brief Tap call back to retrieve information about the TCP headers.
 */
static gboolean tcp_tap_pkt(
	void *tapdata _U_,
	packet_info *pinfo,
	epan_dissect_t *edt _U_,
	const void *data
) {
	struct f5eth_analysis_data_t *ad = get_f5eth_analysis_data(pinfo);
	const tcp_info_t *tcph;

	if(ad->tcp_visited == 1) return(FALSE);
	ad->tcp_visited = 1;

	if(data == NULL) return(FALSE);
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

	return(TRUE);
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
			pi = proto_tree_add_item(tree, addrfield, tvb, offset+sizeof(ipv4as6prefix), 4, ENC_BIG_ENDIAN);
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
			pi = proto_tree_add_item(tree, addrfield, tvb, offset+sizeof(f5rtdomprefix)+2, 4, ENC_BIG_ENDIAN);
			if(hidden) PROTO_ITEM_SET_HIDDEN(pi);
		}
		if(rtdomfield >= 0) {
			pi = proto_tree_add_item(tree, rtdomfield, tvb, offset+sizeof(f5rtdomprefix), 2, ENC_BIG_ENDIAN);
			if(hidden) PROTO_ITEM_SET_HIDDEN(pi);
		}
	}

	return(pi);
} /* displayIPv6as4() */


/*---------------------------------------------------------------------------*/
/* Render the flow flags field */
static guint render_flow_flags(
	tvbuff_t       *tvb,
	packet_info    *pinfo _U_,
	proto_tree     *tree,
	guint           offset,
	guint8          trailer_type _U_,
	guint8          trailer_length _U_,
	guint8          trailer_ver,
	f5eth_tap_data_t *tdata _U_)
{
	guint o;

	o = offset;
	if(trailer_ver >= 3) {
		proto_tree_add_item(tree, hf_cf_flags2, tvb, o, 4, ENC_BIG_ENDIAN);
		o += 4;
	}
	proto_tree_add_item(tree, hf_cf_flags, tvb, o, 4, ENC_BIG_ENDIAN);
	o += 4;
	return(o - offset);
} /* render_flow_flags() */


/*---------------------------------------------------------------------------*/
/* Render the flow type field */
static guint render_flow_type(
	tvbuff_t       *tvb,
	packet_info    *pinfo _U_,
	proto_tree     *tree,
	guint           offset,
	guint8          trailer_type _U_,
	guint8          trailer_length _U_,
	guint8          trailer_ver _U_,
	f5eth_tap_data_t *tdata _U_)
{
	proto_tree_add_item(tree, hf_flow_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	return(1);
} /* render_flow_type() */


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
	guint8      trailer_type;

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

	/* We don't need to see type and versions of the TLV trailers. */
	trailer_type = tvb_get_guint8(tvb,o);
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
		o += render_flow_flags(tvb,pinfo,tree,o,trailer_type,trailer_length,trailer_ver,tdata);
		o += render_flow_type(tvb,pinfo,tree,o,trailer_type,trailer_length,trailer_ver,tdata);
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
	guint8      trailer_type;

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

	/* We don't need to see type and versions of the TLV trailers. */
	trailer_type = tvb_get_guint8(tvb,o);
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
		o += render_flow_flags(tvb,pinfo,tree,o,trailer_type,trailer_length,trailer_ver,tdata);
		o += render_flow_type(tvb,pinfo,tree,o,trailer_type,trailer_length,trailer_ver,tdata);
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

	/* If there is no reference to the fields here, then there is no need to
	 * populate a tree.  We only need to populate the column information.  Set
	 * tree to NULL to prevent the subdissectors from doing much work. */
	if(!proto_field_is_referenced(tree, proto_f5ethtrailer))
		tree = NULL;

	/* While we still have data in the trailer
	 * (need type, length, version)... */
	while(tvb_reported_length_remaining(tvb, offset) > F5_OFF_VERSION) {
		processed = 0;
		len = F5TRAILER_LEN(tvb, offset);
		ver = F5TRAILER_VER(tvb,offset);
		if(len <= tvb_reported_length_remaining(tvb, offset)
		   && len >= F5_MIN_SANE && len <= F5_MAX_SANE
		   && ver <= F5TRAILER_VER_MAX)
		{
			type = F5TRAILER_TYPE(tvb, offset);
			processed = 0;

			/* This should probably be in the case statements below, but putting it here
			 * prevents the code duplication.  We only want to create the trailer subtree
			 * if we believe that we have actually found a trailer.
			 */
			if(trailer_item == NULL && type >= F5TYPE_LOW && type <= F5TYPE_HIGH && tree)
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
		ad = get_f5eth_analysis_data(pinfo);

		if(ad != NULL && ad->analysis_done == 0) {
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

		error_string = register_tap_listener("ip", &tap_ip_enabled, NULL, TL_REQUIRES_NOTHING, NULL, ip_tap_pkt, NULL);
		if (error_string) {
			ws_g_warning("Unable to register tap \"ip\" for f5ethtrailer: %s", error_string->str);
			g_string_free(error_string, TRUE);
		}
		error_string = register_tap_listener("ipv6", &tap_ipv6_enabled, NULL, TL_REQUIRES_NOTHING, NULL, ipv6_tap_pkt, NULL);
		if (error_string) {
			ws_g_warning("Unable to register tap \"ipv6\" for f5ethtrailer: %s", error_string->str);
			g_string_free(error_string, TRUE);
		}
		error_string = register_tap_listener("tcp", &tap_tcp_enabled, NULL, TL_REQUIRES_NOTHING, NULL, tcp_tap_pkt, NULL);
		if (error_string) {
			ws_g_warning("Unable to register tap \"tcp\" for f5ethtrailer: %s", error_string->str);
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
		{ &hf_type,
		  { "Type", "f5ethtrailer.type", FT_UINT8, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_length,
		  { "Trailer length", "f5ethtrailer.length", FT_UINT8, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},
		{ &hf_version,
		  { "Version", "f5ethtrailer.version", FT_UINT8, BASE_DEC, NULL,
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
		}
	};

	static gint *ett[] = {
		&ett_f5ethtrailer,
		&ett_f5ethtrailer_low,
		&ett_f5ethtrailer_med,
		&ett_f5ethtrailer_high,
		&ett_f5ethtrailer_rstcause
	};

	expert_module_t *expert_f5ethtrailer;
	static ei_register_info ei[] = {
		{ &ei_f5eth_flowlost,  { "f5ethtrailer.flowlost", PI_SEQUENCE, PI_WARN, "Flow lost, incorrect VLAN, loose initiation, tunnel, or SYN cookie use", EXPFILL } },
		{ &ei_f5eth_flowreuse, { "f5ethtrailer.flowreuse", PI_SEQUENCE, PI_WARN, "Flow reuse or SYN retransmit", EXPFILL } }
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
		" Wireshark to get perfomance back.", &pop_other_fields);
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
	heur_dissector_add("eth.trailer", dissect_f5ethtrailer, "F5 Ethernet Trailer",
			"f5ethtrailer", proto_f5ethtrailer, HEURISTIC_DISABLE);

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
	const guint8 *platform = NULL;
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
			proto_tree_add_item(tree, hf_fi_command, tvb, offset+5, objlen-6, ENC_ASCII);
			col_add_str(pinfo->cinfo, COL_INFO, &object[5]);
		}
		else if(strncmp(object, "VER: ", 5) == 0) {
			guint i;
			const guint8 *c;

			proto_tree_add_item(tree, hf_fi_version, tvb, offset+5, objlen-6, ENC_ASCII|ENC_NA);
			for(c=object;  *c && (*c < '0' || *c > '9');  c++);
			for(i=0;  i<6 && *c;  c++) {
				if(*c < '0' || *c > '9') {
					i++; continue;
				}
				tap_data->ver[i] = (tap_data->ver[i] * 10) + (*c - '0');
			}
		}
		else if(strncmp(object, "HOST: ", 6) == 0)
			proto_tree_add_item(tree, hf_fi_hostname, tvb, offset+6, objlen-7, ENC_ASCII|ENC_NA);
		else if(strncmp(object, "PLAT: ", 6) == 0) {
			proto_tree_add_item(tree, hf_fi_platform, tvb, offset+6, objlen-7, ENC_ASCII|ENC_NA);
			platform = tvb_get_string_enc(wmem_packet_scope(), tvb, offset+6, objlen-7, ENC_ASCII);
		}
		else if(strncmp(object, "PROD: ", 6) == 0)
			proto_tree_add_item(tree, hf_fi_product, tvb, offset+6, objlen-7, ENC_ASCII|ENC_NA);

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
