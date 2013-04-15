/* packet-PROTOABBREV.c
 * Routines for PROTONAME dissection
 * Copyright 201x, YOUR_NAME <YOUR_EMAIL_ADDRESS>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#if 0
/* Include only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

/* IF PROTO exposes code to other dissectors, then it must be exported
    in a header file. If not, a header file is not needed at all. */
#include "packet-PROTOABBREV.h"

/* Forward declaration we need below (if using proto_reg_handoff...
    as a prefs callback)       */
void proto_reg_handoff_PROTOABBREV(void);

/* Initialize the protocol and registered fields */
static int proto_PROTOABBREV = -1;
static int hf_PROTOABBREV_FIELDABBREV = -1;

/* Global sample preference ("controls" display of numbers) */
static gboolean gPREF_HEX = FALSE;
/* Global sample port pref */
static guint gPORT_PREF = 1234;

/* Initialize the subtree pointers */
static gint ett_PROTOABBREV = -1;

/* Code to actually dissect the packets */
static int
dissect_PROTOABBREV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

/*  Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *PROTOABBREV_tree;

/*  First, if at all possible, do some heuristics to check if the packet cannot
 *  possibly belong to your protocol.  This is especially important for
 *  protocols directly on top of TCP or UDP where port collisions are
 *  common place (e.g., even though your protocol uses a well known port,
 *  someone else may set up, for example, a web server on that port which,
 *  if someone analyzed that web server's traffic in Wireshark, would result
 *  in Wireshark handing an HTTP packet to your dissector).  For example:
 */
    /* Check that there's enough data */
    if (tvb_length(tvb) < /* your protocol's smallest packet size */)
        return 0;

    /* Get some values from the packet header, probably using tvb_get_*() */
    if ( /* these values are not possible in PROTONAME */ )
        /*  This packet does not appear to belong to PROTONAME.
         *  Return 0 to give another dissector a chance to dissect it.
         */
        return 0;

/*  Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROTOABBREV");

/*  This field shows up as the "Info" column in the display; you should use
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

    col_set_str(pinfo->cinfo, COL_INFO, "XXX Request");

/*  A protocol dissector may be called in 2 different ways - with, or
    without a non-null "tree" argument.

    If the proto_tree argument is null, Wireshark does not need to use
    the protocol tree information from your dissector, and therefore is
    passing the dissector a null "tree" argument so that it doesn't
    need to do work necessary to build the protocol tree.

    In the interest of speed, if "tree" is NULL, avoid building a
    protocol tree and adding stuff to it, or even looking at any packet
    data needed only if you're building the protocol tree, if possible.

    Note, however, that you must fill in column information, create
    conversations, reassemble packets, do calls to "expert" functions,
    build any other persistent state needed for dissection, and call
    subdissectors regardless of whether "tree" is NULL or not.

    This might be inconvenient to do without doing most of the
    dissection work; the routines for adding items to the protocol tree
    can be passed a null protocol tree pointer, in which case they'll
    return a null item pointer, and "proto_item_add_subtree()" returns
    a null tree pointer if passed a null item pointer, so, if you're
    careful not to dereference any null tree or item pointers, you can
    accomplish this by doing all the dissection work.  This might not
    be as efficient as skipping that work if you're not building a
    protocol tree, but if the code would have a lot of tests whether
    "tree" is null if you skipped that work, you might still be better
    off just doing all that work regardless of whether "tree" is null
    or not.

    Note also that there is no guarantee, the first time the dissector is
    called, whether "tree" will be null or not; your dissector must work
    correctly, building or updating whatever state information is
    necessary, in either case. */
    if (tree) {

/*  NOTE: The offset and length values in the call to
    "proto_tree_add_item()" define what data bytes to highlight in the hex
    display window when the line in the protocol tree display
    corresponding to that item is selected.

    Supplying a length of -1 is the way to highlight all data from the
    offset to the end of the packet. */

/*  create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_PROTOABBREV, tvb, 0, -1, ENC_NA);

        PROTOABBREV_tree = proto_item_add_subtree(ti, ett_PROTOABBREV);

/* add an item to the subtree, see section 1.6 for more information */
        proto_tree_add_item(PROTOABBREV_tree,
            hf_PROTOABBREV_FIELDABBREV, tvb, offset, len, ENC_xxx);


/* Continue adding tree items to process the packet here */


    }

/* If this protocol has a sub-dissector call it here, see section 1.8 */

/* Return the amount of data this dissector was able to dissect */
    return tvb_length(tvb);
}


/* Register the protocol with Wireshark */

/*  This format is require because a script is used to build the C function
    that calls all the protocol registration.
*/

void
proto_register_PROTOABBREV(void)
{
    module_t *PROTOABBREV_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_PROTOABBREV_FIELDABBREV,
            { "FIELDNAME", "PROTOABBREV.FIELDABBREV",
            FIELDTYPE, FIELDDISPLAY, FIELDCONVERT, BITMASK,
            "FIELDDESCR", HFILL }
        }
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_PROTOABBREV
    };

/* Register the protocol name and description */
    proto_PROTOABBREV = proto_register_protocol("PROTONAME",
        "PROTOSHORTNAME", "PROTOABBREV");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_PROTOABBREV, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

/* Register preferences module (See Section 2.6 for more on preferences) */
/* (Registration of a prefs callback is not required if there are no     */
/*  prefs-dependent registration functions (eg: a port pref).            */
/*  See proto_reg_handoff below.                                         */
/*  If a prefs callback is not needed, use NULL instead of               */
/*  proto_reg_handoff_PROTOABBREV in the following).                     */
    PROTOABBREV_module = prefs_register_protocol(proto_PROTOABBREV,
        proto_reg_handoff_PROTOABBREV);

/* Register preferences module under preferences subtree.
   Use this function instead of prefs_register_protocol if you want to group
   preferences of several protocols under one preferences subtree.
   Argument subtree identifies grouping tree node name, several subnodes can be
   specified using slash '/' (e.g. "OSI/X.500" - protocol preferences will be
   accessible under Protocols->OSI->X.500-><PROTOSHORTNAME> preferences node.
*/
  PROTOABBREV_module = prefs_register_protocol_subtree(const char *subtree,
       proto_PROTOABBREV, proto_reg_handoff_PROTOABBREV);

/* Register a sample preference */
    prefs_register_bool_preference(PROTOABBREV_module, "show_hex",
         "Display numbers in Hex",
         "Enable to display numerical values in hexadecimal.",
         &gPREF_HEX);

/* Register a sample port preference   */
    prefs_register_uint_preference(PROTOABBREV_module, "tcp.port", "PROTOABBREV TCP Port",
         " PROTOABBREV TCP port if other than the default",
         10, &gPORT_PREF);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This exact format is required because a script is used to find these
   routines and create the code that calls these routines.

   If this function is registered as a prefs callback (see prefs_register_protocol
   above) this function is also called by preferences whenever "Apply" is pressed;
   In that case, it should accommodate being called more than once.

   This form of the reg_handoff function is used if if you perform
   registration functions which are dependent upon prefs. See below
   for a simpler form  which can be used if there are no
   prefs-dependent registration functions.
*/
void
proto_reg_handoff_PROTOABBREV(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t PROTOABBREV_handle;
    static int currentPort;

    if (!initialized) {

/*  Use new_create_dissector_handle() to indicate that dissect_PROTOABBREV()
 *  returns the number of bytes it dissected (or 0 if it thinks the packet
 *  does not belong to PROTONAME).
 */
        PROTOABBREV_handle = new_create_dissector_handle(dissect_PROTOABBREV,
                                                        proto_PROTOABBREV);
        initialized = TRUE;
        } else {

        /*
        If you perform registration functions which are dependent upon
        prefs the you should de-register everything which was associated
        with the previous settings and re-register using the new prefs
        settings here. In general this means you need to keep track of
        the PROTOABBREV_handle and the value the preference had at the time
        you registered.  The PROTOABBREV_handle value and the value of the
        preference can be saved using local statics in this
        function (proto_reg_handoff).
        */

        dissector_delete_uint("tcp.port", currentPort, PROTOABBREV_handle);
    }

    currentPort = gPORT_PREF;

    dissector_add_uint("tcp.port", currentPort, PROTOABBREV_handle);

}

#if 0
/* Simple form of proto_reg_handoff_PROTOABBREV which can be used if there are
   no prefs-dependent registration function calls.
 */

void
proto_reg_handoff_PROTOABBREV(void)
{
    dissector_handle_t PROTOABBREV_handle;

/*  Use new_create_dissector_handle() to indicate that dissect_PROTOABBREV()
 *  returns the number of bytes it dissected (or 0 if it thinks the packet
 *  does not belong to PROTONAME).
 */
    PROTOABBREV_handle = new_create_dissector_handle(dissect_PROTOABBREV,
                                                     proto_PROTOABBREV);
    dissector_add_uint("PARENT_SUBFIELD", ID_VALUE, PROTOABBREV_handle);
}
#endif


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


