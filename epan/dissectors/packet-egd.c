/* packet-egd.c
 * Routines for Ethernet Global Data dissection
 * EGD Home: www.gefanuc.com
 *
 * Copyright 2008
 * 29 July 2008 -- ryan wamsley
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

#define EGD_PORT 18246 /* 0x4746 */

#define EGD_ST_NONEW        0
#define EGD_ST_NOERROR      1
#define EGD_ST_CONSUMED     2
#define EGD_ST_SNTPERR      3
#define EGD_ST_SPECERR      4
#define EGD_ST_REFRESHERR   6
#define EGD_ST_REFEXDERR    7
#define EGD_ST_IPERR        10
#define EGD_ST_RESOURSEERR  12
#define EGD_ST_NAMERES      16
#define EGD_ST_ETHERR       18
#define EGD_ST_NOSUPPORT    22
#define EGD_ST_NORESP       26
#define EGD_ST_CREATEERR    28
#define EGD_ST_DELETED      30


void proto_register_egd(void);
void proto_reg_handoff_egd(void);

/* Translate status to string */
static const value_string egd_stat_vals[] = {
  { EGD_ST_NONEW,                  "No new status event has occurred" },
  { EGD_ST_NOERROR,                "No error currently exists" },
  { EGD_ST_CONSUMED,               "No error, data consumed" },
  { EGD_ST_SNTPERR,                "SNTP error"  },
  { EGD_ST_SPECERR,                "Specification error" },
  { EGD_ST_REFRESHERR,             "Data refresh error" },
  { EGD_ST_REFEXDERR,              "Data refresh period exceeded" },
  { EGD_ST_IPERR,                  "IP Layer not currently initialized" },
  { EGD_ST_RESOURSEERR,            "Lack of resource error" },
  { EGD_ST_NAMERES,                "Name Resolution in progress" },
  { EGD_ST_ETHERR,                 "Loss of Ethernet Interface error" },
  { EGD_ST_NOSUPPORT,              "Ethernet Interface does not support EGD" },
  { EGD_ST_NORESP,                 "No Response from Ethernet Interface" },
  { EGD_ST_CREATEERR,              "Failed to create an exchange." },
  { EGD_ST_DELETED,                "Configured exchange deleted." },
  { 0,                             NULL }
};

static int proto_egd = -1;

static int hf_egd_ver = -1;
static int hf_egd_type = -1;
static int hf_egd_rid = -1;
static int hf_egd_pid = -1;
static int hf_egd_exid = -1;
static int hf_egd_time = -1;
static int hf_egd_notime = -1;
static int hf_egd_stat = -1;
static int hf_egd_csig = -1;
static int hf_egd_resv = -1;

static gint ett_egd = -1;
static gint ett_status_item = -1;

static int dissect_egd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  /* replace UDP with EGD in display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "EGD");

  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "Data Msg: ExchangeID=0x%08X, RequestID=%05u",
                 tvb_get_letohl(tvb, 8), tvb_get_letohs(tvb, 2));

  if (tree)
  {
    proto_item *ti = NULL;
    proto_item *notime = NULL;
    proto_tree *egd_tree = NULL;
    tvbuff_t *next_tvb = NULL;
    gint offset, data_length;
    guint32 sectime;
    nstime_t egd_time;

    memset(&egd_time, 0, sizeof(nstime_t));
    offset = 0;

    ti = proto_tree_add_item(tree, proto_egd, tvb, 0, -1, ENC_NA);
    egd_tree = proto_item_add_subtree(ti, ett_egd);
    proto_tree_add_item(egd_tree, hf_egd_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(egd_tree, hf_egd_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(egd_tree, hf_egd_rid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(egd_tree, hf_egd_pid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(egd_tree, hf_egd_exid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* time */
    sectime = tvb_get_letohl(tvb, offset);
    if (0 == sectime)
    {
      notime = proto_tree_add_item(egd_tree, hf_egd_notime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      proto_item_append_text(notime, "--No TimeStamp");
    }
    else
    {
      egd_time.secs  = tvb_get_letohl(tvb, offset);
      egd_time.nsecs = tvb_get_letohl(tvb, offset+4);
      proto_tree_add_time(egd_tree, hf_egd_time, tvb, offset, 8, &egd_time);
    }
    offset += 8;

    proto_tree_add_item(egd_tree, hf_egd_stat, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(egd_tree, hf_egd_csig, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(egd_tree, hf_egd_resv, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    data_length = tvb_reported_length_remaining(tvb, offset);
    if (data_length > 0)
    {
      next_tvb = tvb_new_subset_remaining(tvb, offset);
      call_data_dissector(next_tvb, pinfo, egd_tree);
    }
  }
  return tvb_captured_length(tvb);
}

void proto_register_egd(void)
{
  static hf_register_info hf[] =
    {
      { &hf_egd_ver,
        { "Version", "egd.ver",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_egd_type,
        { "Type", "egd.type",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_egd_rid,
        { "RequestID", "egd.rid",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_egd_pid,
        { "ProducerID", "egd.pid",
          FT_IPv4, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_egd_exid,
        { "ExchangeID", "egd.exid",
          FT_UINT32, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_egd_time,
        { "Timestamp", "egd.time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
          NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_egd_notime,
        { "Timestamp", "egd.notime",
          FT_UINT64, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_egd_stat,
        { "Status", "egd.stat",
          FT_UINT32, BASE_DEC,
          VALS(egd_stat_vals), 0x0,
          NULL, HFILL }
      },
      { &hf_egd_csig,
        { "ConfigSignature", "egd.csig",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_egd_resv,
        { "Reserved", "egd.rsrv",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL }
      }
    };

  static gint *ett[] =
    {
      &ett_egd,
      &ett_status_item
    };

  proto_egd = proto_register_protocol (
    "Ethernet Global Data",  /* name */
    "EGD",                   /* short name */
    "egd"                    /* abbrev */
    );
  proto_register_field_array(proto_egd, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_egd(void)
{
  dissector_handle_t egd_handle;

  egd_handle = create_dissector_handle(dissect_egd, proto_egd);
  dissector_add_uint("udp.port", EGD_PORT, egd_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
