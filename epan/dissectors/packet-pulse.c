/* packet-pulse.c
 * Routines for pulse dissection
 * Copyright 2013, Masatake YAMATO <yamato@redhat.com>
 * Copyright 2013, Red Hat, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


/* About pulse, see
    http://sourceware.org/piranha/ */

# include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#define PORT_PULSE 539


static guint  pulse_port = PORT_PULSE;

void proto_register_pulse(void);
void proto_reg_handoff_pulse(void);

static int  proto_pulse    = -1;
static int  hf_pulse_magic = -1;
static gint ett_pulse      = -1;

/* piranha/pulse.c */
#define PULSE_HEARTBEAT_RUNNING_MAGIC     0xbdaddbda
#define PULSE_HEARTBEAT_STOPPED_MAGIC     0xadbddabd

static const value_string pulse_magic_type[] = {
    { PULSE_HEARTBEAT_RUNNING_MAGIC,   "running" },
    { PULSE_HEARTBEAT_STOPPED_MAGIC,   "stopped" },
    { 0, NULL                                    }
};

static int
dissect_pulse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    proto_item *item;
    proto_tree *tree;

    guint32 magic;
    const char* magic_str;
    guint little_endian;

    if (tvb_length(tvb) < 4)
        return 0;

    /* Try to read MAGIC in both endians */
    little_endian = ENC_LITTLE_ENDIAN;
    magic = tvb_get_letohl(tvb, 0);
    magic_str = try_val_to_str(magic, pulse_magic_type);
    if (magic_str == NULL) {
      magic = tvb_get_ntohl(tvb, 0);
      magic_str = try_val_to_str(magic, pulse_magic_type);
      if (magic_str == NULL) {
        return 0;
      }
      little_endian = ENC_BIG_ENDIAN;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PULSE");
    col_set_str(pinfo->cinfo, COL_INFO, magic_str);

    if (parent_tree) {
        item = proto_tree_add_item(parent_tree, proto_pulse, tvb, 0,
                                   -1, little_endian);
        tree = proto_item_add_subtree(item, ett_pulse);
        proto_tree_add_item(tree, hf_pulse_magic, tvb, 0, 4, little_endian);
    }
    return 4;
}

void
proto_register_pulse(void)
{
    module_t *pulse_module;

    static hf_register_info hf[] = {
        { &hf_pulse_magic,
          { "Magic", "pulse.magic",
            FT_UINT32, BASE_HEX, VALS(pulse_magic_type), 0x0,
            NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_pulse,
    };


    proto_pulse = proto_register_protocol("PULSE protocol for Linux Virtual Server redundancy",
                                          "PULSE",
                                          "pulse");
    proto_register_field_array(proto_pulse, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pulse_module = prefs_register_protocol(proto_pulse, proto_reg_handoff_pulse);
    prefs_register_uint_preference(pulse_module, "udp.port",
                                   "UDP Port",
                                   "Set the UDP port for pulse",
                                   10,
                                   &pulse_port);
}

void
proto_reg_handoff_pulse(void)
{
    static gboolean initialized = FALSE;

    static int port = 0;

    static dissector_handle_t pulse_handle;

    if (initialized)
        {
            dissector_delete_uint("udp.port", port, pulse_handle);
        }
    else
        {
            pulse_handle = new_create_dissector_handle(dissect_pulse,
                                                       proto_pulse);
            initialized = TRUE;
        }

    port  = pulse_port;
    dissector_add_uint("udp.port", port, pulse_handle);
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
