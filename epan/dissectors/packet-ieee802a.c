/* packet-ieee802a.c
 * Routines for IEEE 802a
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/etypes.h>

#include "packet-ieee802a.h"

void proto_register_ieee802a(void);
void proto_reg_handoff_ieee802a(void);

static int proto_ieee802a = -1;
static int hf_ieee802a_oui = -1;
static int hf_ieee802a_pid = -1;

static gint ett_ieee802a = -1;

/*
 * Hash table for translating OUIs to a dissector table/field info pair;
 * the dissector table maps PID values to dissectors, and the field
 * corresponds to the PID for that OUI.
 */
typedef struct {
	dissector_table_t table;
	hf_register_info *field_info;
} oui_info_t;

static GHashTable *oui_info_table = NULL;

/*
 * Add an entry for a new OUI.
 */
void
ieee802a_add_oui(guint32 oui, const char *table_name, const char *table_ui_name,
		 hf_register_info *hf_item, const int proto)
{
	oui_info_t *new_info;

	new_info = (oui_info_t *)g_malloc(sizeof (oui_info_t));
	new_info->table = register_dissector_table(table_name,
	    table_ui_name, proto, FT_UINT16, BASE_HEX);
	new_info->field_info = hf_item;

	/*
	 * Create the hash table for OUI information, if it doesn't
	 * already exist.
	 */
	if (oui_info_table == NULL) {
		oui_info_table = g_hash_table_new(g_direct_hash,
		    g_direct_equal);
	}
	g_hash_table_insert(oui_info_table, GUINT_TO_POINTER(oui), new_info);
}

static int
dissect_ieee802a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*ieee802a_tree;
	proto_item	*ti;
	tvbuff_t	*next_tvb;
	const gchar	*manuf;
	guint8		oui[3];
	guint32		oui32;
	guint16		pid;
	oui_info_t	*oui_info;
	dissector_table_t subdissector_table;
	int		hf;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE802a");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_ieee802a, tvb, 0, 5, ENC_NA);
	ieee802a_tree = proto_item_add_subtree(ti, ett_ieee802a);

	tvb_memcpy(tvb, oui, 0, 3);
	oui32 = oui[0] << 16 | oui[1] << 8 | oui[2];
	manuf = get_manuf_name_if_known(oui);
	pid = tvb_get_ntohs(tvb, 3);

	col_add_fstr(pinfo->cinfo, COL_INFO, "OUI %s (%s), PID 0x%04X",
	    bytestring_to_str(wmem_packet_scope(), oui, 3, ':'),
	    manuf ? manuf : "Unknown", pid);

	proto_tree_add_uint_format_value(ieee802a_tree, hf_ieee802a_oui,
	    tvb, 0, 3, oui32, "%s (%s)",
	    bytestring_to_str(wmem_packet_scope(), oui, 3, ':'), manuf ? manuf : "Unknown");

	/*
	 * Do we have information for this OUI?
	 */
	if (oui_info_table != NULL &&
	    (oui_info = (oui_info_t *)g_hash_table_lookup(oui_info_table,
	      GUINT_TO_POINTER(oui32))) != NULL) {
		/*
		 * Yes - use it.
		 */
		hf = *oui_info->field_info->p_id;
		subdissector_table = oui_info->table;
	} else {
		/*
		 * No, use hf_ieee802a_pid for the PID and just dissect
		 * the payload as data.
		 */
		hf = hf_ieee802a_pid;
		subdissector_table = NULL;
	}

	proto_tree_add_uint(ieee802a_tree, hf, tvb, 3, 2, pid);
	next_tvb = tvb_new_subset_remaining(tvb, 5);
	if ((subdissector_table == NULL) ||
		/* do lookup with the subdissector table */
		(!dissector_try_uint(subdissector_table, pid, next_tvb, pinfo, tree))) {
			call_data_dissector(next_tvb, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

void
proto_register_ieee802a(void)
{
	static hf_register_info hf[] = {
		{ &hf_ieee802a_oui,
		  { "Organization Code",	"ieee802a.oui", FT_UINT24, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_ieee802a_pid,
		  { "Protocol ID", "ieee802a.pid", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }}
	};
	static gint *ett[] = {
		&ett_ieee802a,
	};

	proto_ieee802a = proto_register_protocol("IEEE802a OUI Extended Ethertype", "IEEE802a", "ieee802a");
	proto_register_field_array(proto_ieee802a, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

static void
register_hf(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	oui_info_t *info = (oui_info_t *)value;

	proto_register_field_array(proto_ieee802a, info->field_info, 1);
}

void
proto_reg_handoff_ieee802a(void)
{
	dissector_handle_t ieee802a_handle;

	ieee802a_handle = create_dissector_handle(dissect_ieee802a,
	    proto_ieee802a);
	dissector_add_uint("ethertype", ETHERTYPE_IEEE802_OUI_EXTENDED,
	    ieee802a_handle);

	/*
	 * Register all the fields for PIDs for various OUIs.
	 */
	if (oui_info_table != NULL)
		g_hash_table_foreach(oui_info_table, register_hf, NULL);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
