/* packet-wol.c
 * Routines for WOL dissection
 * Copyright 2007, Christopher Maynard <Chris.Maynard[AT]gtech.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This dissector for "Wake On LAN" was not copied from any other existing
 * dissector.  It uses the template from SVN23520 docs/README.devloper, which
 * was the latest one available at the time of this writing.  This dissector is
 * a heuristic one though, so appropriate changes have made to the template
 * as needed.
 *
 * The "Wake On LAN" dissector was written based primarily on the AMD white
 * paper, available from: http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/20213.pdf.
 *
 * In addition, testing of the dissector was conducted using 2 utilities
 * downloaded from http://www.moldaner.de/wakeonlan/wakeonlan.html and
 * http://www.depicus.com/wake-on-lan/, as well as with the ether-wake utility
 * on a Linux Fedora Core 4 system.
 *
 * From what I can tell from the tools available, even though the white paper
 * indicates that the so-called, "MagicPacket" can be located anywhere within
 * the Ethernet frame, in practice, there seem to be only 2 variations of the
 * implementation of the MagicPacket.  Ether-wake implements it as an Ethernet
 * frame with ether type 0x0842 (ETHERTYPE_WOL), and the other tools all seem
 * to implement it as a UDP packet, both with the payload as nothing but the
 * MagicPacket.
 *
 * To keep things simple, this dissector will only indicate a frame as
 * Wake-On-Lan if the MagicPacket is found for a frame marked as etherytpe
 * 0x0842 or if it's a UDP packet.  To fully support Wake-On-Lan dissection
 * though, we would need a way to have this dissector called only if the frame
 * hasn't already been classified as some other type of dissector ... but I
 * don't know how to do that?  The only alternative I am aware of would be to
 * register as a heuristic dissector for pretty much every possible protocol
 * there is, which seems unreasonable to do to me.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/etypes.h>

void proto_register_wol(void);
void proto_reg_handoff_wol(void);

/* Initialize the protocol and registered fields */
static int proto_wol = -1;
static int hf_wol_sync = -1;
static int hf_wol_mac = -1;
static int hf_wol_passwd = -1;

/* Initialize the subtree pointers */
static gint ett_wol = -1;
static gint ett_wol_macblock = -1;

/* Code to actually dissect the packets */
static int
dissect_wol_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint         len;
    gint          offset;
    guint8       *mac;
    const guint8 *passwd;
    guint64       qword;
    address      mac_addr;

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *wol_tree;
    proto_tree *mac_tree;

/*  First, if at all possible, do some heuristics to check if the packet cannot
 *  possibly belong to your protocol.  This is especially important for
 *  protocols directly on top of TCP or UDP where port collisions are
 *  common place (e.g., even though your protocol uses a well known port,
 *  someone else may set up, for example, a web server on that port which,
 *  if someone analyzed that web server's traffic in Wireshark, would result
 *  in Wireshark handing an HTTP packet to your dissector).  For example:
 */
    /* Check that there's enough data */
    len = tvb_reported_length(tvb);
    if ( len < 102 )    /* wol's smallest packet size is 102 */
        return (0);

    /* Get some values from the packet header, probably using tvb_get_*() */

    /* Regardless of what the AMD white paper states, don't search the entire
     * tvb for the synchronization stream.  My feeling is that this could be
     * quite expensive and seriously hinder Wireshark performance.  For now,
     * unless we need to change it later, just compare the 1st 6 bytes. */
    qword = tvb_get_ntoh48(tvb,0);
    if(qword != G_GUINT64_CONSTANT(0xffffffffffff))
        return (0);

    /* So far so good.  Now get the next 6 bytes, which we'll assume is the
     * target's MAC address, and do 15 memory chunk comparisons, since if this
     * is a real MagicPacket, the target's MAC will be duplicated 16 times. */
    mac = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, 6, 6);
    for ( offset = 12; offset < 102; offset += 6 )
        if ( tvb_memeql(tvb, offset, mac, 6) != 0 )
            return (0);

    /* OK, we're going to assume it's a MagicPacket.  If there's a password,
     * grab it now, and in case there's any extra bytes after the only 3 valid
     * and expected lengths, truncate the length so the extra byte(s) aren't
     * included as being part of the WOL payload. */
    if ( len >= 106 && len < 108 )
    {
        len = 106;
        passwd = tvb_ip_to_str(tvb, 102);
    }
    else if ( len >= 108 )
    {
        len = 108;
        passwd = tvb_ether_to_str(tvb, 102);
    }
    else
    {
        len = 102;
        passwd = NULL;
    }

/* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WOL");

/* This field shows up as the "Info" column in the display; you should use
   it, if possible, to summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. See section 1.5
   for more information.

   If you are setting the column to a constant string, use "col_set_str()",
   as it's more efficient than the other "col_set_XXX()" calls.

   If you're setting it to a string you've constructed, or will be
   appending to the column later, use "col_add_str()".

   "col_add_fstr()" can be used instead of "col_add_str()"; it takes
   "printf()"-like arguments.  Don't use "col_add_fstr()" with a format
   string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
   more efficient than "col_add_fstr()".

   If you will be fetching any data from the packet before filling in
   the Info column, clear that column first, in case the calls to fetch
   data from the packet throw an exception because they're fetching data
   past the end of the packet, so that the Info column doesn't have data
   left over from the previous dissector; do

    col_clear(pinfo->cinfo, COL_INFO);

   */
    set_address(&mac_addr, AT_ETHER, 6, mac);

    col_add_fstr(pinfo->cinfo, COL_INFO, "MagicPacket for %s",
        address_with_resolution_to_str(wmem_packet_scope(), &mac_addr));

    /* NOTE: ether-wake uses a dotted-decimal format for specifying a
        * 4-byte password or an Ethernet mac address format for specifying
        * a 6-byte password, so display them in that format, even if the
        * password isn't really an IP or MAC address. */
    if ( passwd )
        col_append_fstr(pinfo->cinfo, COL_INFO, ", password %s", passwd);

/* A protocol dissector can be called in 2 different ways:

    (a) Operational dissection

        In this mode, Wireshark is only interested in the way protocols
        interact, protocol conversations are created, packets are
        reassembled and handed over to higher-level protocol dissectors.
        In this mode Wireshark does not build a so-called "protocol
        tree".

    (b) Detailed dissection

        In this mode, Wireshark is also interested in all details of
        a given protocol, so a "protocol tree" is created.

   Wireshark distinguishes between the 2 modes with the proto_tree pointer:
    (a) <=> tree == NULL
    (b) <=> tree != NULL

   In the interest of speed, if "tree" is NULL, avoid building a
   protocol tree and adding stuff to it, or even looking at any packet
   data needed only if you're building the protocol tree, if possible.

   Note, however, that you must fill in column information, create
   conversations, reassemble packets, build any other persistent state
   needed for dissection, and call subdissectors regardless of whether
   "tree" is NULL or not.  This might be inconvenient to do without
   doing most of the dissection work; the routines for adding items to
   the protocol tree can be passed a null protocol tree pointer, in
   which case they'll return a null item pointer, and
   "proto_item_add_subtree()" returns a null tree pointer if passed a
   null item pointer, so, if you're careful not to dereference any null
   tree or item pointers, you can accomplish this by doing all the
   dissection work.  This might not be as efficient as skipping that
   work if you're not building a protocol tree, but if the code would
   have a lot of tests whether "tree" is null if you skipped that work,
   you might still be better off just doing all that work regardless of
   whether "tree" is null or not. */
    if (tree) {

/* NOTE: The offset and length values in the call to
   "proto_tree_add_item()" define what data bytes to highlight in the hex
   display window when the line in the protocol tree display
   corresponding to that item is selected.

   Supplying a length of -1 is the way to highlight all data from the
   offset to the end of the packet. */

/* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_wol, tvb, 0, len, ENC_NA);
        proto_item_append_text(ti, ", MAC: %s",
            address_with_resolution_to_str(wmem_packet_scope(), &mac_addr));
        if ( passwd )
            proto_item_append_text(ti, ", password: %s", passwd);
        wol_tree = proto_item_add_subtree(ti, ett_wol);

/* add an item to the subtree, see section 1.6 for more information */
        proto_tree_add_item(wol_tree, hf_wol_sync, tvb, 0, 6, ENC_NA);

/* Continue adding tree items to process the packet here */
        mac_tree = proto_tree_add_subtree_format(wol_tree, tvb, 6, 96,
            ett_wol_macblock, NULL, "MAC: %s",
            address_with_resolution_to_str(wmem_packet_scope(), &mac_addr));
        for ( offset = 6; offset < 102; offset += 6 )
            proto_tree_add_ether(mac_tree, hf_wol_mac, tvb, offset, 6, mac);

        if ( len == 106 )
            proto_tree_add_bytes_format_value(wol_tree, hf_wol_passwd, tvb, offset,
                4, passwd, "%s", passwd);
        else if ( len == 108 )
            proto_tree_add_bytes_format_value(wol_tree, hf_wol_passwd, tvb, offset,
                6, passwd, "%s", passwd);
    }

    return (len);
}

static int
dissect_wol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_wol_pdu(tvb, pinfo, tree, data);
}

static gboolean
dissect_wolheur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (dissect_wol_pdu(tvb, pinfo, tree, data) > 0)
        return TRUE;

    return FALSE;
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_wol(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_wol_sync,
            { "Sync stream", "wol.sync",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_wol_mac,
            { "MAC", "wol.mac",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_wol_passwd,
            { "Password", "wol.passwd",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }}
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_wol,
        &ett_wol_macblock
    };

/* Register the protocol name and description */
    proto_wol = proto_register_protocol("Wake On LAN", "WOL", "wol");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_wol, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This exact format is required because a script is used to find these
   routines and create the code that calls these routines.

*/
void
proto_reg_handoff_wol(void)
{
    dissector_handle_t wol_handle;

/*  Use create_dissector_handle() to indicate that dissect_wol()
 *  returns the number of bytes it dissected (or 0 if it thinks the packet
 *  does not belong to PROTONAME).
 */
    wol_handle = create_dissector_handle(dissect_wol, proto_wol);

    /* We don't really want to register with EVERY possible dissector,
     * do we?  I know that the AMD white paper specifies that the
     * MagicPacket could be present in any frame, but are we seriously
     * going to register WOL with every other dissector!?  I think not.
     *
     * Unless anyone has a better idea, just register with only those that
     * are in "common usage" and grow this list as needed.  Yeah, I'm sure
     * we'll miss some, but how else to do this ... add a thousand of
     * these dissector_add_uint()'s and heur_dissector_add()'s??? */
    dissector_add_uint("ethertype", ETHERTYPE_WOL, wol_handle);
    heur_dissector_add("udp", dissect_wolheur, "Wake On LAN over UDP", "wol_udp", proto_wol, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
