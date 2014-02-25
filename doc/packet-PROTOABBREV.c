/* packet-PROTOABBREV.c
 * Routines for PROTONAME dissection
 * Copyright 201x, YOUR_NAME <YOUR_EMAIL_ADDRESS>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
#include <epan/expert.h>
#include <epan/prefs.h>

#if 0
/* IF AND ONLY IF your protocol dissector exposes code to other dissectors
 * (which most dissectors don't need to do) then the 'public' prototypes and
 * data structures can go in the header file packet-PROTOABBREV.h. If not, then
 * a header file is not needed at all and this #include statement can be
 * removed. */
#include "packet-PROTOABBREV.h"
#endif

/* Forward declaration that is needed below if using the
 * proto_reg_handoff_PROTOABBREV function as a callback for when protocol
 * preferences get changed. */
void proto_reg_handoff_PROTOABBREV(void);
void proto_register_PROTOABBREV(void);

/* Initialize the protocol and registered fields */
static int proto_PROTOABBREV = -1;
static int hf_PROTOABBREV_FIELDABBREV = -1;
static expert_field ei_PROTOABBREV_EXPERTABBREV = EI_INIT;

/* Global sample preference ("controls" display of numbers) */
static gboolean gPREF_HEX = FALSE;
/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
static guint gPORT_PREF = 1234;

/* Initialize the subtree pointers */
static gint ett_PROTOABBREV = -1;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define PROTOABBREV_MIN_LENGTH 8

/* Code to actually dissect the packets */
static int
dissect_PROTOABBREV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti, *expert_ti;
    proto_tree *PROTOABBREV_tree;
    /* Other misc. local variables. */
    guint offset = 0;
    int len = 0;

    /*** HEURISTICS ***/

    /* First, if at all possible, do some heuristics to check if the packet
     * cannot possibly belong to your protocol.  This is especially important
     * for protocols directly on top of TCP or UDP where port collisions are
     * common place (e.g., even though your protocol uses a well known port,
     * someone else may set up, for example, a web server on that port which,
     * if someone analyzed that web server's traffic in Wireshark, would result
     * in Wireshark handing an HTTP packet to your dissector).
     *
     * For example:
     */

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < PROTOABBREV_MIN_LENGTH)
        return 0;

    /* Check that there's enough data present to run the heuristics. If there
     * isn't, reject the packet; it will probably be dissected as data and if
     * the user wants it dissected despite it being short they can use the
     * "Decode-As" functionality. If your heuristic needs to look very deep into
     * the packet you may not want to require *all* data to be present, but you
     * should ensure that the heuristic does not access beyond the captured
     * length of the packet regardless. */
    if (tvb_captured_length(tvb) < MAX_NEEDED_FOR_HEURISTICS)
        return 0;

    /* Fetch some values from the packet header using tvb_get_*(). If these
     * values are not valid/possible in your protocol then return 0 to give
     * some other dissector a chance to dissect it. */
    if ( TEST_HEURISTICS_FAIL )
        return 0;

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'PROTOABBREV',
     * and the 'Info' column which can be much wider and contain misc. summary
     * information (for example, the port number for TCP packets).
     *
     * If you are setting the column to a constant string, use "col_set_str()",
     * as it's more efficient than the other "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
     * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
     * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
     * more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of PROTOABBREV */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROTOABBREV");

#if 0
    /* If you will be fetching any data from the packet before filling in
     * the Info column, clear that column first in case the calls to fetch
     * data from the packet throw an exception so that the Info column doesn't
     * contain data left over from the previous dissector: */
    col_clear(pinfo->cinfo, COL_INFO);
#endif

    col_set_str(pinfo->cinfo, COL_INFO, "XXX Request");

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_PROTOABBREV, tvb, 0, -1, ENC_NA);

    PROTOABBREV_tree = proto_item_add_subtree(ti, ett_PROTOABBREV);

    /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */
    expert_ti = proto_tree_add_item(PROTOABBREV_tree, hf_PROTOABBREV_FIELDABBREV, tvb,
            offset, len, ENC_xxx);
    offset += len;
    /* Some fields or situations may require "expert" analysis that can be
     * specifically highlighted. */
    if ( TEST_EXPERT_condition )
        /* value of hf_PROTOABBREV_FIELDABBREV isn't what's expected */
        expert_add_info(pinfo, expert_ti, &ei_PROTOABBREV_EXPERTABBREV);

    /* Continue adding tree items to process the packet here... */

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_PROTOABBREV(void)
{
    module_t *PROTOABBREV_module;
    expert_module_t* expert_PROTOABBREV;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
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

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_PROTOABBREV_EXPERTABBREV, { "PROTOABBREV.EXPERTABBREV", PI_SEVERITY, PI_GROUP, "EXPERTDESCR", EXPFILL }},
    };

    /* Register the protocol name and description */
    proto_PROTOABBREV = proto_register_protocol("PROTONAME",
            "PROTOSHORTNAME", "PROTOABBREV");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_PROTOABBREV, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    /* Required function calls to register expert items */
    expert_PROTOABBREV = expert_register_protocol(proto_PROTOABBREV);
    expert_register_field_array(expert_PROTOABBREV, ei, array_length(ei));

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_PROTOABBREV in the following.
     */
    PROTOABBREV_module = prefs_register_protocol(proto_PROTOABBREV,
            proto_reg_handoff_PROTOABBREV);

    /* Register a preferences module under the preferences subtree.
     * Only use this function instead of prefs_register_protocol (above) if you
     * want to group preferences of several protocols under one preferences
     * subtree.
     * 
     * Argument subtree identifies grouping tree node name, several subnodes can
     * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
     * will be accessible under Protocols->OSI->X.500-><PROTOSHORTNAME>
     * preferences node.
     */
    PROTOABBREV_module = prefs_register_protocol_subtree(const char *subtree,
            proto_PROTOABBREV, proto_reg_handoff_PROTOABBREV);

    /* Register a simple example preference */
    prefs_register_bool_preference(PROTOABBREV_module, "show_hex",
            "Display numbers in Hex",
            "Enable to display numerical values in hexadecimal.",
            &gPREF_HEX);

    /* Register an example port preference */
    prefs_register_uint_preference(PROTOABBREV_module, "tcp.port", "PROTOABBREV TCP Port",
            " PROTOABBREV TCP port if other than the default",
            10, &gPORT_PREF);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_PROTOABBREV(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t PROTOABBREV_handle;
    static int currentPort;

    if (!initialized) {
        /* Use new_create_dissector_handle() to indicate that
         * dissect_PROTOABBREV() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to PROTONAME).
         */
        PROTOABBREV_handle = new_create_dissector_handle(dissect_PROTOABBREV,
                proto_PROTOABBREV);
        initialized = TRUE;

    } else {
        /* If you perform registration functions which are dependent upon
         * prefs then you should de-register everything which was associated
         * with the previous settings and re-register using the new prefs
         * settings here. In general this means you need to keep track of
         * the PROTOABBREV_handle and the value the preference had at the time
         * you registered.  The PROTOABBREV_handle value and the value of the
         * preference can be saved using local statics in this
         * function (proto_reg_handoff).
         */
        dissector_delete_uint("tcp.port", currentPort, PROTOABBREV_handle);
    }

    currentPort = gPORT_PREF;

    dissector_add_uint("tcp.port", currentPort, PROTOABBREV_handle);
}

#if 0
/* Simpler form of proto_reg_handoff_PROTOABBREV which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_PROTOABBREV(void)
{
    dissector_handle_t PROTOABBREV_handle;

    /* Use new_create_dissector_handle() to indicate that dissect_PROTOABBREV()
     * returns the number of bytes it dissected (or 0 if it thinks the packet
     * does not belong to PROTONAME).
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
