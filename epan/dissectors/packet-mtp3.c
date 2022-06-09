/* packet-mtp3.c
 * Routines for Message Transfer Part Level 3 dissection
 *
 * It is (hopefully) compliant to:
 *   ANSI T1.111.4-1996
 *   ITU-T Q.704 7/1996
 *   GF 001-9001 (Chinese ITU variant)
 *   JT-Q704 and NTT-Q704 (Japan)
 *
 *   Note that the division of the Japan SLS into the SLC and A/B bit (for
 *   management messages) is not done.
 *
 * Copyright 2001, Michael Tuexen <tuexen [AT] fh-muenster.de>
 * Updated for ANSI, Chinese ITU, and Japan support by
 *  Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>
#include <epan/prefs.h>
#include <epan/address_types.h>
#include <wiretap/wtap.h>
#include <epan/addr_resolv.h>

#include "packet-q708.h"
#include "packet-sccp.h"
#include "packet-frame.h"

void proto_register_mtp3(void);
void proto_reg_handoff_mtp3(void);

/* Initialize the protocol and registered fields */
static int proto_mtp3  = -1;

static int mtp3_tap = -1;

static dissector_handle_t mtp3_handle;

static module_t *mtp3_module;

static int hf_mtp3_service_indicator = -1;
static int hf_mtp3_network_indicator = -1;
static int hf_mtp3_itu_spare = -1;
static int hf_mtp3_itu_priority = -1;
static int hf_mtp3_ansi_priority = -1;
static int hf_mtp3_itu_pc = -1;
static int hf_mtp3_24bit_pc = -1;
static int hf_mtp3_itu_opc = -1;
static int hf_mtp3_24bit_opc = -1;
static int hf_mtp3_ansi_opc = -1;
static int hf_mtp3_chinese_opc = -1;
static int hf_mtp3_opc_network = -1;
static int hf_mtp3_opc_cluster = -1;
static int hf_mtp3_opc_member = -1;
static int hf_mtp3_itu_dpc = -1;
static int hf_mtp3_24bit_dpc = -1;
static int hf_mtp3_ansi_dpc = -1;
static int hf_mtp3_chinese_dpc = -1;
static int hf_mtp3_dpc_network = -1;
static int hf_mtp3_dpc_cluster = -1;
static int hf_mtp3_dpc_member = -1;
static int hf_mtp3_itu_sls = -1;
static int hf_mtp3_ansi_5_bit_sls = -1;
static int hf_mtp3_ansi_8_bit_sls = -1;
static int hf_mtp3_chinese_itu_sls = -1;
static int hf_mtp3_japan_dpc = -1;
static int hf_mtp3_japan_opc = -1;
static int hf_mtp3_japan_pc = -1;
static int hf_mtp3_japan_4_bit_sls = -1;
static int hf_mtp3_japan_4_bit_sls_spare = -1;
static int hf_mtp3_japan_5_bit_sls = -1;
static int hf_mtp3_japan_5_bit_sls_spare = -1;
static int hf_mtp3_heuristic_standard = -1;

/* Initialize the subtree pointers */
static gint ett_mtp3 = -1;
static gint ett_mtp3_sio = -1;
static gint ett_mtp3_label = -1;
static gint ett_mtp3_label_dpc = -1;
static gint ett_mtp3_label_opc = -1;

static dissector_table_t mtp3_sio_dissector_table;

static int mtp3_address_type = -1;

typedef enum {
  ITU_PC_STRUCTURE_NONE    = 1,
  ITU_PC_STRUCTURE_3_8_3   = 2,
  ITU_PC_STRUCTURE_4_3_4_3 = 3
} ITU_PC_Structure_Type;

typedef enum {
  JAPAN_PC_STRUCTURE_NONE    = 1,
  JAPAN_PC_STRUCTURE_7_4_5   = 2,
  JAPAN_PC_STRUCTURE_3_4_4_5 = 3
} JAPAN_PC_Structure_Type;

static gint itu_pc_structure   = ITU_PC_STRUCTURE_NONE;
static gint japan_pc_structure = JAPAN_PC_STRUCTURE_NONE;

#include "packet-mtp3.h"

gint mtp3_standard = ITU_STANDARD;
gboolean mtp3_heuristic_standard = FALSE;

static gint pref_mtp3_standard;

const value_string mtp3_standard_vals[] = {
  { ITU_STANDARD,         "ITU_STANDARD" },
  { ANSI_STANDARD,        "ANSI_STANDARD" },
  { CHINESE_ITU_STANDARD, "CHINESE_ITU_STANDARD" },
  { JAPAN_STANDARD,       "JAPAN_STANDARD" },
  { 0,        NULL }
};

static gboolean mtp3_use_ansi_5_bit_sls = FALSE;
static gboolean mtp3_use_japan_5_bit_sls = FALSE;
static gboolean mtp3_show_itu_priority = FALSE;
static gint mtp3_addr_fmt = MTP3_ADDR_FMT_DASHED;

#define SIO_LENGTH                1
#define SLS_LENGTH                1
#define SIO_OFFSET                0
#define ROUTING_LABEL_OFFSET      (SIO_OFFSET + SIO_LENGTH)

#define ITU_ROUTING_LABEL_LENGTH  4
#define ITU_HEADER_LENGTH         (SIO_LENGTH + ITU_ROUTING_LABEL_LENGTH)

#define ITU_SLS_OFFSET            (SIO_OFFSET + ITU_HEADER_LENGTH - SLS_LENGTH)
#define ITU_MTP_PAYLOAD_OFFSET    (SIO_OFFSET + ITU_HEADER_LENGTH)

#define ANSI_ROUTING_LABEL_LENGTH (ANSI_PC_LENGTH + ANSI_PC_LENGTH + SLS_LENGTH)
#define ANSI_HEADER_LENGTH        (SIO_LENGTH + ANSI_ROUTING_LABEL_LENGTH)

#define ANSI_DPC_OFFSET           ROUTING_LABEL_OFFSET
#define ANSI_OPC_OFFSET           (ANSI_DPC_OFFSET + ANSI_PC_LENGTH)
#define ANSI_SLS_OFFSET           (ANSI_OPC_OFFSET + ANSI_PC_LENGTH)
#define ANSI_MTP_PAYLOAD_OFFSET   (SIO_OFFSET + ANSI_HEADER_LENGTH)

#define JAPAN_SLS_SPARE_LENGTH           1
#define JAPAN_ROUTING_LABEL_LENGTH (JAPAN_PC_LENGTH + JAPAN_PC_LENGTH + JAPAN_SLS_SPARE_LENGTH)
#define JAPAN_HEADER_LENGTH        (SIO_LENGTH + JAPAN_ROUTING_LABEL_LENGTH)

#define JAPAN_OPC_OFFSET           (ROUTING_LABEL_OFFSET + JAPAN_PC_LENGTH)
#define JAPAN_SLS_OFFSET           (JAPAN_OPC_OFFSET + JAPAN_PC_LENGTH)
#define JAPAN_SPARE_OFFSET         (ROUTING_LABEL_OFFSET + JAPAN_ROUTING_LABEL_LENGTH)
#define JAPAN_MTP_PAYLOAD_OFFSET   (SIO_OFFSET + JAPAN_HEADER_LENGTH)

#define SERVICE_INDICATOR_MASK     0x0F
#define SPARE_MASK                 0x30
#define ANSI_PRIORITY_MASK         SPARE_MASK
#define NETWORK_INDICATOR_MASK     0xC0
#define ITU_DPC_MASK               0x00003FFF
#define ITU_OPC_MASK               0x0FFFC000
#define ITU_SLS_MASK               0xF0000000

#define ANSI_5BIT_SLS_MASK         0x1F
#define ANSI_8BIT_SLS_MASK         0xFF
#define CHINESE_ITU_SLS_MASK       0xF
#define JAPAN_4_BIT_SLS_MASK       0xF
#define JAPAN_4_BIT_SLS_SPARE_MASK 0xF0
#define JAPAN_5_BIT_SLS_MASK       0x1F
#define JAPAN_5_BIT_SLS_SPARE_MASK 0xE0

/* the higher values are taken from the M3UA RFC */
static const value_string mtp3_service_indicator_code_vals[] = {
  { MTP_SI_SNM,      "Signalling Network Management Message (SNM)" },
  { MTP_SI_MTN,      "Maintenance Regular Message (MTN)" },
  { MTP_SI_MTNS,     "Maintenance Special Message (MTNS)" },
  { MTP_SI_SCCP,     "SCCP" },
  { MTP_SI_TUP,      "TUP" },
  { MTP_SI_ISUP,     "ISUP" },
  { MTP_SI_DUP_CC,   "DUP (call and circuit related messages)" },
  { MTP_SI_DUP_FAC,  "DUP (facility registration and cancellation message)" },
  { MTP_SI_MTP_TEST, "MTP testing user part" },
  { MTP_SI_ISUP_B,   "Broadband ISUP" },
  { MTP_SI_ISUP_S,   "Satellite ISUP" },
  { 0xb,             "Spare" },
  { MTP_SI_AAL2,     "AAL type2 Signaling" },
  { MTP_SI_BICC,     "Bearer Independent Call Control (BICC)" },
  { MTP_SI_GCP,      "Gateway Control Protocol" },
  { 0xf,             "Spare" },
  { 0,        NULL }
};

const value_string mtp3_service_indicator_code_short_vals[] = {
  { MTP_SI_SNM,      "SNM" },
  { MTP_SI_MTN,      "MTN" },
  { MTP_SI_MTNS,     "MTNS" },
  { MTP_SI_SCCP,     "SCCP" },
  { MTP_SI_TUP,      "TUP" },
  { MTP_SI_ISUP,     "ISUP" },
  { MTP_SI_DUP_CC,   "DUP (CC)" },
  { MTP_SI_DUP_FAC,  "DUP (FAC/CANC)" },
  { MTP_SI_MTP_TEST, "MTP Test" },
  { MTP_SI_ISUP_B,   "ISUP-b" },
  { MTP_SI_ISUP_S,   "ISUP-s" },
  { MTP_SI_AAL2,     "AAL type 2" },
  { MTP_SI_BICC,     "BICC" },
  { MTP_SI_GCP,      "GCP" },
  { 0,      NULL }
};

const value_string mtp3_network_indicator_vals[] = {
  { MTP3_NI_INT0,  "International network" },
  { MTP3_NI_INT1,  "Spare (for international use only)" },
  { MTP3_NI_NAT0,  "National network" },
  { MTP3_NI_NAT1,  "Reserved for national use" },
  { 0,    NULL }
};


/*
 * helper routine to format a point code in structured form
 */

static void
mtp3_pc_to_str_buf(const guint32 pc, gchar *buf, int buf_len)
{
  switch (mtp3_standard)
  {
    case ITU_STANDARD:
      switch (itu_pc_structure) {
        case ITU_PC_STRUCTURE_NONE:
          snprintf(buf, buf_len, "%u", pc);
          break;
        case ITU_PC_STRUCTURE_3_8_3:
          /* this format is used in international ITU networks */
          snprintf(buf, buf_len, "%u-%u-%u", (pc & 0x3800)>>11, (pc & 0x7f8) >> 3, (pc & 0x07) >> 0);
          break;
        case ITU_PC_STRUCTURE_4_3_4_3:
          /* this format is used in some national ITU networks, the German one for example. */
          snprintf(buf, buf_len, "%u-%u-%u-%u", (pc & 0x3c00) >>10, (pc & 0x0380) >> 7, (pc & 0x0078) >> 3, (pc & 0x0007) >> 0);
          break;
        default:
          DISSECTOR_ASSERT_NOT_REACHED();
      }
      break;
    case ANSI_STANDARD:
    case CHINESE_ITU_STANDARD:
      snprintf(buf, buf_len, "%u-%u-%u", (pc & ANSI_NETWORK_MASK) >> 16, (pc & ANSI_CLUSTER_MASK) >> 8, (pc & ANSI_MEMBER_MASK));
      break;
    case JAPAN_STANDARD:
      switch (japan_pc_structure) {
        case JAPAN_PC_STRUCTURE_NONE:
          snprintf(buf, buf_len, "%u", pc);
          break;
        case JAPAN_PC_STRUCTURE_7_4_5:
          /* This format is specified by NTT */
          snprintf(buf, buf_len, "%u-%u-%u", (pc & 0xfe00)>>9, (pc & 0x1e0)>>5, (pc & 0x1f));
          break;
        case JAPAN_PC_STRUCTURE_3_4_4_5:
          /* Where does this format come from? */
          snprintf(buf, buf_len, "%u-%u-%u-%u", (pc & 0xe000)>>13, (pc & 0x1e00)>>9, (pc & 0x1e0)>>5, (pc & 0x1f));
          break;
        default:
          DISSECTOR_ASSERT_NOT_REACHED();
      }
      break;
    default:
      DISSECTOR_ASSERT_NOT_REACHED();
  }
}

#define MAX_STRUCTURED_PC_LENGTH 20

gchar *
mtp3_pc_to_str(const guint32 pc)
{
  gchar *str;

  str=(gchar *)wmem_alloc(wmem_packet_scope(), MAX_STRUCTURED_PC_LENGTH);
  mtp3_pc_to_str_buf(pc, str, MAX_STRUCTURED_PC_LENGTH);
  return str;
}

gboolean
mtp3_pc_structured(void)
{
  if ((mtp3_standard == ITU_STANDARD) && (itu_pc_structure == ITU_PC_STRUCTURE_NONE))
    return FALSE;
  else if ((mtp3_standard == JAPAN_STANDARD) && (japan_pc_structure == JAPAN_PC_STRUCTURE_NONE))
    return FALSE;
  else
    return TRUE;
}

/*
 * helper routine to format address to string
 */

static void
mtp3_addr_to_str_buf(const mtp3_addr_pc_t  *addr_pc_p,
                     gchar *buf, int buf_len)
{
  switch (mtp3_addr_fmt)
  {
    case MTP3_ADDR_FMT_DEC:
      switch (addr_pc_p->type)
      {
        case ITU_STANDARD:
          snprintf(buf, buf_len, "%u", addr_pc_p->pc & ITU_PC_MASK);
          break;
        case JAPAN_STANDARD:
          snprintf(buf, buf_len, "%u", addr_pc_p->pc & JAPAN_PC_MASK);
          break;
        default:
          /* assuming 24-bit */
          snprintf(buf, buf_len, "%u", addr_pc_p->pc & ANSI_PC_MASK);
          break;
      }
      break;

    case MTP3_ADDR_FMT_HEX:
      switch (addr_pc_p->type)
      {
        case ITU_STANDARD:
          snprintf(buf, buf_len, "%x", addr_pc_p->pc & ITU_PC_MASK);
          break;
        case JAPAN_STANDARD:
          snprintf(buf, buf_len, "%x", addr_pc_p->pc & JAPAN_PC_MASK);
          break;
        default:
          /* assuming 24-bit */
          snprintf(buf, buf_len, "%x", addr_pc_p->pc & ANSI_PC_MASK);
          break;
      }
      break;

    case MTP3_ADDR_FMT_NI_DEC:
      switch (addr_pc_p->type)
      {
        case ITU_STANDARD:
          snprintf(buf, buf_len, "%u:%u", addr_pc_p->ni, addr_pc_p->pc & ITU_PC_MASK);
          break;
        case JAPAN_STANDARD:
          snprintf(buf, buf_len, "%u:%u", addr_pc_p->ni, addr_pc_p->pc & JAPAN_PC_MASK);
          break;
        default:
          /* assuming 24-bit */
          snprintf(buf, buf_len, "%u:%u", addr_pc_p->ni, addr_pc_p->pc & ANSI_PC_MASK);
          break;
      }
      break;

    case MTP3_ADDR_FMT_NI_HEX:
      switch (addr_pc_p->type)
      {
        case ITU_STANDARD:
          snprintf(buf, buf_len, "%u:%x", addr_pc_p->ni, addr_pc_p->pc & ITU_PC_MASK);
          break;
        case JAPAN_STANDARD:
          snprintf(buf, buf_len, "%u:%x", addr_pc_p->ni, addr_pc_p->pc & JAPAN_PC_MASK);
          break;
        default:
          /* assuming 24-bit */
          snprintf(buf, buf_len, "%u:%x", addr_pc_p->ni, addr_pc_p->pc & ANSI_PC_MASK);
          break;
      }
      break;

    default:
      /* FALLTHRU */

    case MTP3_ADDR_FMT_DASHED:
      mtp3_pc_to_str_buf(addr_pc_p->pc, buf, buf_len);
      break;
  }
}

guint32
mtp3_pc_hash(const mtp3_addr_pc_t *addr_pc_p) {
  guint32 pc;

  switch (addr_pc_p->type)
  {
    case ITU_STANDARD:
      pc = (addr_pc_p->pc & ITU_PC_MASK) | ((addr_pc_p->ni % 4) << 14) ;
      break;
    default:
      /* assuming 24-bit */
      pc = (addr_pc_p->pc & ANSI_PC_MASK) | ((addr_pc_p->ni) << 24) ;
      break;
  }

  return pc;
}

static int mtp3_addr_to_str(const address* addr, gchar *buf, int buf_len)
{
    mtp3_addr_to_str_buf((const mtp3_addr_pc_t *)addr->data, buf, buf_len);
    return (int)(strlen(buf)+1);
}

static int mtp3_str_addr_len(const address* addr _U_)
{
    return 50;
}

int mtp3_addr_len(void)
{
    return sizeof(mtp3_addr_pc_t);
}

static const gchar* mtp3_addr_name_res_str(const address* addr)
{
    const mtp3_addr_pc_t *mtp3_addr = (const mtp3_addr_pc_t *)addr->data;
    const gchar *tmp;

    tmp = get_hostname_ss7pc(mtp3_addr->ni, mtp3_addr->pc);

    if (tmp[0] == '\0') {
        gchar* str;
        str = (gchar *)wmem_alloc(NULL, MAXNAMELEN);
        mtp3_addr_to_str_buf(mtp3_addr, str, MAXNAMELEN);
        fill_unresolved_ss7pc(str, mtp3_addr->ni, mtp3_addr->pc);
        wmem_free(NULL, str);
        return get_hostname_ss7pc(mtp3_addr->ni, mtp3_addr->pc);
    }
    return tmp;

}

static int mtp3_addr_name_res_len(void)
{
    return MAXNAMELEN;
}




/*  Common function for dissecting 3-byte (ANSI or China) PCs. */
void
dissect_mtp3_3byte_pc(tvbuff_t *tvb, guint offset, proto_tree *tree, gint ett_pc, int hf_pc_string, int hf_pc_network,
                      int hf_pc_cluster, int hf_pc_member, int hf_dpc, int hf_pc)
{
  guint32 pc;
  proto_item *pc_item, *hidden_item;
  proto_tree *pc_tree;
  char pc_string[MAX_STRUCTURED_PC_LENGTH];

  pc = tvb_get_letoh24(tvb, offset);
  mtp3_pc_to_str_buf(pc, pc_string, sizeof(pc_string));

  pc_item = proto_tree_add_string(tree, hf_pc_string, tvb, offset, ANSI_PC_LENGTH, pc_string);

  /* Add alternate formats of the PC
   * NOTE: each of these formats is shown to the user,
   * so I think that using hidden fields in this case is OK.
   */
  snprintf(pc_string, sizeof(pc_string), "%u", pc);
  proto_item_append_text(pc_item, " (%s)", pc_string);
  hidden_item = proto_tree_add_string(tree, hf_pc_string, tvb, offset, ANSI_PC_LENGTH, pc_string);
  proto_item_set_hidden(hidden_item);
  snprintf(pc_string, sizeof(pc_string), "0x%x", pc);
  proto_item_append_text(pc_item, " (%s)", pc_string);
  hidden_item = proto_tree_add_string(tree, hf_pc_string, tvb, offset, ANSI_PC_LENGTH, pc_string);
  proto_item_set_hidden(hidden_item);

  pc_tree = proto_item_add_subtree(pc_item, ett_pc);

  proto_tree_add_uint(pc_tree, hf_pc_network, tvb, offset + ANSI_NETWORK_OFFSET, ANSI_NCM_LENGTH, pc);
  proto_tree_add_uint(pc_tree, hf_pc_cluster, tvb, offset + ANSI_CLUSTER_OFFSET, ANSI_NCM_LENGTH, pc);
  proto_tree_add_uint(pc_tree, hf_pc_member,  tvb, offset + ANSI_MEMBER_OFFSET,  ANSI_NCM_LENGTH, pc);

  /* add full integer values of DPC as hidden for filtering purposes */
  if (hf_dpc) {
    hidden_item = proto_tree_add_uint(pc_tree, hf_dpc, tvb, offset, ANSI_PC_LENGTH, pc);
    proto_item_set_hidden(hidden_item);
  }
  if (hf_pc) {
    hidden_item = proto_tree_add_uint(pc_tree, hf_pc,  tvb, offset, ANSI_PC_LENGTH, pc);
    proto_item_set_hidden(hidden_item);
  }
}

static void
dissect_mtp3_sio(tvbuff_t *tvb, proto_tree *mtp3_tree,
                 mtp3_addr_pc_t *mtp3_addr_opc, mtp3_addr_pc_t *mtp3_addr_dpc)
{
  guint8 sio;
  proto_tree *sio_tree;

  sio_tree = proto_tree_add_subtree(mtp3_tree, tvb, SIO_OFFSET, SIO_LENGTH, ett_mtp3_sio, NULL, "Service information octet");

  sio = tvb_get_guint8(tvb, SIO_OFFSET);
  proto_tree_add_uint(sio_tree, hf_mtp3_network_indicator, tvb, SIO_OFFSET, SIO_LENGTH, sio);

  mtp3_addr_opc->ni = (sio & NETWORK_INDICATOR_MASK) >> 6;
  mtp3_addr_dpc->ni = (sio & NETWORK_INDICATOR_MASK) >> 6;

  switch(mtp3_standard){
    case ANSI_STANDARD:
      proto_tree_add_uint(sio_tree, hf_mtp3_ansi_priority, tvb, SIO_OFFSET, SIO_LENGTH, sio);
      break;
    case ITU_STANDARD:
    case CHINESE_ITU_STANDARD:
      if (mtp3_show_itu_priority)
        proto_tree_add_uint(sio_tree, hf_mtp3_itu_priority, tvb, SIO_OFFSET, SIO_LENGTH, sio);
      else
        proto_tree_add_uint(sio_tree, hf_mtp3_itu_spare, tvb, SIO_OFFSET, SIO_LENGTH, sio);
      break;
    case JAPAN_STANDARD:
      /*  The Japan variant has priority but it's on the LI which belongs to
       *  layer 2.  Not sure what we can do about that...
       */
      proto_tree_add_uint(sio_tree, hf_mtp3_itu_spare, tvb, SIO_OFFSET, SIO_LENGTH, sio);
      break;
  }

  proto_tree_add_uint(sio_tree, hf_mtp3_service_indicator, tvb, SIO_OFFSET, SIO_LENGTH, sio);
}

static void
dissect_mtp3_routing_label(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mtp3_tree,
                           mtp3_addr_pc_t *mtp3_addr_opc, mtp3_addr_pc_t *mtp3_addr_dpc)
{
  guint32 label, dpc, opc;
  proto_item *label_dpc_item, *label_opc_item;
  proto_item *hidden_item;
  proto_tree *label_tree;
  proto_tree *pc_subtree;
  int hf_dpc_string;
  int hf_opc_string;


  switch (mtp3_standard) {
    case ITU_STANDARD:
      label_tree = proto_tree_add_subtree(mtp3_tree, tvb, ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, ett_mtp3_label, NULL, "Routing label");

      label = tvb_get_letohl(tvb, ROUTING_LABEL_OFFSET);

      opc = (label & ITU_OPC_MASK) >> 14;
      dpc =  label & ITU_DPC_MASK;

      hidden_item = proto_tree_add_uint(label_tree, hf_mtp3_itu_pc, tvb, ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, opc);
      proto_item_set_hidden(hidden_item);
      hidden_item = proto_tree_add_uint(label_tree, hf_mtp3_itu_pc, tvb, ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, dpc);
      proto_item_set_hidden(hidden_item);

      label_dpc_item = proto_tree_add_uint(label_tree, hf_mtp3_itu_dpc, tvb, ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, label);
      if (mtp3_pc_structured())
        proto_item_append_text(label_dpc_item, " (%s)", mtp3_pc_to_str(dpc));

      if(mtp3_addr_dpc->ni == MTP3_NI_INT0) {
        pc_subtree = proto_item_add_subtree(label_dpc_item, ett_mtp3_label_dpc);
        analyze_q708_ispc(tvb, pc_subtree, ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, dpc);
      }


      label_opc_item = proto_tree_add_uint(label_tree, hf_mtp3_itu_opc, tvb, ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, label);
      if (mtp3_pc_structured())
        proto_item_append_text(label_opc_item, " (%s)", mtp3_pc_to_str(opc));

      if(mtp3_addr_opc->ni == MTP3_NI_INT0) {
        pc_subtree = proto_item_add_subtree(label_opc_item, ett_mtp3_label_opc);
        analyze_q708_ispc(tvb, pc_subtree, ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, opc);
      }

      proto_tree_add_uint(label_tree, hf_mtp3_itu_sls, tvb, ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, label);
      break;

    case ANSI_STANDARD:
    case CHINESE_ITU_STANDARD:
      if (mtp3_standard == ANSI_STANDARD)
      {
        hf_dpc_string = hf_mtp3_ansi_dpc;
        hf_opc_string = hf_mtp3_ansi_opc;
      } else /* CHINESE_ITU_STANDARD */ {
        hf_dpc_string = hf_mtp3_chinese_dpc;
        hf_opc_string = hf_mtp3_chinese_opc;
      }

      /* Create the Routing Label Tree */
      label_tree = proto_tree_add_subtree(mtp3_tree, tvb, ROUTING_LABEL_OFFSET, ANSI_ROUTING_LABEL_LENGTH, ett_mtp3_label, NULL, "Routing label");

      /* create and fill the DPC tree */
      dissect_mtp3_3byte_pc(tvb, ANSI_DPC_OFFSET, label_tree, ett_mtp3_label_dpc, hf_dpc_string, hf_mtp3_dpc_network,
                            hf_mtp3_dpc_cluster, hf_mtp3_dpc_member, hf_mtp3_24bit_dpc, hf_mtp3_24bit_pc);
      /* Store dpc for mtp3_addr below */
      dpc = tvb_get_letoh24(tvb, ANSI_DPC_OFFSET);

      /* create and fill the OPC tree */
      dissect_mtp3_3byte_pc(tvb, ANSI_OPC_OFFSET, label_tree, ett_mtp3_label_opc, hf_opc_string, hf_mtp3_opc_network,
                            hf_mtp3_opc_cluster, hf_mtp3_opc_member, hf_mtp3_24bit_opc, hf_mtp3_24bit_pc);
      /* Store opc for mtp3_addr below */
      opc = tvb_get_letoh24(tvb, ANSI_OPC_OFFSET);

      /* SLS */
      if (mtp3_standard == ANSI_STANDARD) {
        if (mtp3_use_ansi_5_bit_sls)
          proto_tree_add_item(label_tree, hf_mtp3_ansi_5_bit_sls, tvb, ANSI_SLS_OFFSET, SLS_LENGTH, ENC_LITTLE_ENDIAN);
        else
          proto_tree_add_item(label_tree, hf_mtp3_ansi_8_bit_sls, tvb, ANSI_SLS_OFFSET, SLS_LENGTH, ENC_LITTLE_ENDIAN);
      } else /* CHINESE_ITU_STANDARD */ {
        proto_tree_add_item(label_tree, hf_mtp3_chinese_itu_sls, tvb, ANSI_SLS_OFFSET, SLS_LENGTH, ENC_LITTLE_ENDIAN);
      }
      break;

    case JAPAN_STANDARD:
      label_tree = proto_tree_add_subtree(mtp3_tree, tvb, ROUTING_LABEL_OFFSET, JAPAN_ROUTING_LABEL_LENGTH, ett_mtp3_label, NULL, "Routing label");

      label_dpc_item = proto_tree_add_item(label_tree, hf_mtp3_japan_dpc, tvb, ROUTING_LABEL_OFFSET, JAPAN_PC_LENGTH, ENC_LITTLE_ENDIAN);
      dpc = tvb_get_letohs(tvb, ROUTING_LABEL_OFFSET);
      if (mtp3_pc_structured()) {
        proto_item_append_text(label_dpc_item, " (%s)", mtp3_pc_to_str(dpc));
      }

      label_opc_item = proto_tree_add_item(label_tree, hf_mtp3_japan_opc, tvb, JAPAN_OPC_OFFSET, JAPAN_PC_LENGTH, ENC_LITTLE_ENDIAN);
      opc = tvb_get_letohs(tvb, JAPAN_OPC_OFFSET);
      if (mtp3_pc_structured()) {
        proto_item_append_text(label_opc_item, " (%s)", mtp3_pc_to_str(opc));
      }

      hidden_item = proto_tree_add_item(label_tree, hf_mtp3_japan_pc, tvb, ROUTING_LABEL_OFFSET, JAPAN_PC_LENGTH, ENC_LITTLE_ENDIAN);
      proto_item_set_hidden(hidden_item);
      hidden_item = proto_tree_add_item(label_tree, hf_mtp3_japan_pc, tvb, JAPAN_OPC_OFFSET, JAPAN_PC_LENGTH, ENC_LITTLE_ENDIAN);
      proto_item_set_hidden(hidden_item);

      if (mtp3_use_japan_5_bit_sls) {
        proto_tree_add_item(label_tree, hf_mtp3_japan_5_bit_sls, tvb, JAPAN_SLS_OFFSET, JAPAN_SLS_SPARE_LENGTH, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(label_tree, hf_mtp3_japan_5_bit_sls_spare, tvb, JAPAN_SLS_OFFSET, JAPAN_SLS_SPARE_LENGTH, ENC_LITTLE_ENDIAN);
      } else {
        proto_tree_add_item(label_tree, hf_mtp3_japan_4_bit_sls, tvb, JAPAN_SLS_OFFSET, JAPAN_SLS_SPARE_LENGTH, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(label_tree, hf_mtp3_japan_4_bit_sls_spare, tvb, JAPAN_SLS_OFFSET, JAPAN_SLS_SPARE_LENGTH, ENC_LITTLE_ENDIAN);
      }

      break;
    default:
      DISSECTOR_ASSERT_NOT_REACHED();
  }

  mtp3_addr_opc->type = (Standard_Type)mtp3_standard;
  mtp3_addr_opc->pc = opc;
  set_address(&pinfo->src, mtp3_address_type, mtp3_addr_len(), (guint8 *) mtp3_addr_opc);

  mtp3_addr_dpc->type = (Standard_Type)mtp3_standard;
  mtp3_addr_dpc->pc = dpc;
  set_address(&pinfo->dst, mtp3_address_type, mtp3_addr_len(), (guint8 *) mtp3_addr_dpc);
}

static void
dissect_mtp3_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 sio;
  guint8 service_indicator;
  tvbuff_t *payload_tvb = NULL;

  sio               = tvb_get_guint8(tvb, SIO_OFFSET);
  service_indicator = sio & SERVICE_INDICATOR_MASK;

  switch (mtp3_standard) {
    case ITU_STANDARD:
      payload_tvb = tvb_new_subset_remaining(tvb, ITU_MTP_PAYLOAD_OFFSET);
      break;
    case ANSI_STANDARD:
    case CHINESE_ITU_STANDARD:
      payload_tvb = tvb_new_subset_remaining(tvb, ANSI_MTP_PAYLOAD_OFFSET);
      break;
    case JAPAN_STANDARD:
      payload_tvb = tvb_new_subset_remaining(tvb, JAPAN_MTP_PAYLOAD_OFFSET);
      break;
    default:
      DISSECTOR_ASSERT_NOT_REACHED();
  }

  col_set_str(pinfo->cinfo, COL_INFO, "DATA ");

  if (!dissector_try_uint(mtp3_sio_dissector_table, service_indicator, payload_tvb, pinfo, tree))
    call_data_dissector(payload_tvb, pinfo, tree);
}

static guint
heur_mtp3_standard(tvbuff_t *tvb, packet_info *pinfo, guint8 si)
{
  tvbuff_t *payload;

  switch (si) {
    case MTP_SI_SCCP:
    {
      payload = tvb_new_subset_remaining(tvb, ITU_HEADER_LENGTH);
      if (looks_like_valid_sccp(pinfo->num, payload, ITU_STANDARD)) {
        return ITU_STANDARD;
      }
      payload = tvb_new_subset_remaining(tvb, ANSI_HEADER_LENGTH);
      if (looks_like_valid_sccp(pinfo->num, payload, ANSI_STANDARD)) {
        return ANSI_STANDARD;
      }
      payload = tvb_new_subset_remaining(tvb, ANSI_HEADER_LENGTH);
      if (looks_like_valid_sccp(pinfo->num, payload, CHINESE_ITU_STANDARD)) {
        return CHINESE_ITU_STANDARD;
      }
      payload = tvb_new_subset_remaining(tvb, JAPAN_HEADER_LENGTH);
      if (looks_like_valid_sccp(pinfo->num, payload, JAPAN_STANDARD)) {
        return JAPAN_STANDARD;
      }

      return HEURISTIC_FAILED_STANDARD;

    }
    default:
      return HEURISTIC_FAILED_STANDARD;
  }

}

static void
reset_mtp3_standard(void)
{
    mtp3_standard = pref_mtp3_standard;
}

/* Code to actually dissect the packets */
static int
dissect_mtp3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  mtp3_tap_rec_t* tap_rec = wmem_new0(wmem_packet_scope(), mtp3_tap_rec_t);
  gint heuristic_standard;
  guint8 si;
  mtp3_addr_pc_t* mtp3_addr_dpc;
  mtp3_addr_pc_t* mtp3_addr_opc;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *mtp3_item = NULL, *gen_item;
  proto_tree *mtp3_tree;

  pref_mtp3_standard = mtp3_standard;

  mtp3_item = proto_tree_add_item(tree, proto_mtp3, tvb, 0, -1, ENC_NA);

  si = tvb_get_guint8(tvb, SIO_OFFSET) & SERVICE_INDICATOR_MASK;
  if (mtp3_heuristic_standard) {
    heuristic_standard = heur_mtp3_standard(tvb, pinfo, si);
    if (heuristic_standard == HEURISTIC_FAILED_STANDARD) {
      gen_item = proto_tree_add_uint_format(tree, hf_mtp3_heuristic_standard, tvb, 0, 0, mtp3_standard,
                                            "Could not determine Heuristic using %s", val_to_str_const(mtp3_standard, mtp3_standard_vals, "unknown"));
    } else {
      gen_item = proto_tree_add_uint_format(tree, hf_mtp3_heuristic_standard, tvb, 0, 0, heuristic_standard,
                                            "%s", val_to_str_const(heuristic_standard, mtp3_standard_vals, "unknown"));
      mtp3_standard = heuristic_standard;

      /* Register a frame-end routine to ensure mtp3_standard is set
       * back even if an exception is thrown.
       */
      register_frame_end_routine(pinfo, reset_mtp3_standard);
    }
    proto_item_set_generated(gen_item);
  }

  /* Make entries in Protocol column on summary display */
  switch(mtp3_standard) {
    case ITU_STANDARD:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP3 (Int. ITU)");
      proto_item_set_len(mtp3_item, ITU_HEADER_LENGTH);
      break;
    case ANSI_STANDARD:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP3 (ANSI)");
      proto_item_set_len(mtp3_item, ANSI_HEADER_LENGTH);
      break;
    case CHINESE_ITU_STANDARD:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP3 (Chin. ITU)");
      proto_item_set_len(mtp3_item, ANSI_HEADER_LENGTH);
      break;
    case JAPAN_STANDARD:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP3 (Japan)");
      proto_item_set_len(mtp3_item, JAPAN_HEADER_LENGTH);
      break;
  };

  /* create display subtree for the protocol */
  mtp3_tree = proto_item_add_subtree(mtp3_item, ett_mtp3);

  mtp3_addr_opc = wmem_new0(pinfo->pool, mtp3_addr_pc_t);
  mtp3_addr_dpc = wmem_new0(pinfo->pool, mtp3_addr_pc_t);

  /* Dissect the packet (even if !tree so can call sub-dissectors and update
   * the source and destination address columns) */
  dissect_mtp3_sio(tvb, mtp3_tree, mtp3_addr_opc, mtp3_addr_dpc);
  dissect_mtp3_routing_label(tvb, pinfo, mtp3_tree, mtp3_addr_opc, mtp3_addr_dpc);

  memcpy(&(tap_rec->addr_opc), mtp3_addr_opc, sizeof(mtp3_addr_pc_t));
  memcpy(&(tap_rec->addr_dpc), mtp3_addr_dpc, sizeof(mtp3_addr_pc_t));

  tap_rec->mtp3_si_code = (tvb_get_guint8(tvb, SIO_OFFSET) & SERVICE_INDICATOR_MASK);
  tap_rec->size = tvb_reported_length(tvb);

  tap_queue_packet(mtp3_tap, pinfo, tap_rec);

  dissect_mtp3_payload(tvb, pinfo, tree);

  mtp3_standard = pref_mtp3_standard;
  return tvb_captured_length(tvb);
}

/* TAP STAT INFO */

typedef enum
{
  OPC_COLUMN,
  DPC_COLUMN,
  SI_COLUMN,
  NUM_MSUS_COLUMN,
  NUM_BYTES_COLUMN,
  AVG_BYTES_COLUMN
} mtp3_stat_columns;

static stat_tap_table_item mtp3_stat_fields[] = {
  {TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "OPC", "%-25s"},
  {TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "DPC", "%-25s"},
  {TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "SI", "%-25s"},
  {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "MSUs", "%d"},
  {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Bytes", "%d"},
  {TABLE_ITEM_FLOAT, TAP_ALIGN_RIGHT, "Avg Bytes", "%f"},
};

static void mtp3_stat_init(stat_tap_table_ui* new_stat)
{
  const char *table_name = "MTP3 Statistics";
  int num_fields = sizeof(mtp3_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table *table;

  table = stat_tap_find_table(new_stat, table_name);
  if (table) {
    if (new_stat->stat_tap_reset_table_cb) {
      new_stat->stat_tap_reset_table_cb(table);
    }
    return;
  }

  table = stat_tap_init_table(table_name, num_fields, 0, NULL);
  stat_tap_add_table(new_stat, table);
}

static tap_packet_status
mtp3_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *m3tr_ptr, tap_flags_t flags _U_)
{
  stat_data_t* stat_data = (stat_data_t*)tapdata;
  const mtp3_tap_rec_t  *m3tr = (const mtp3_tap_rec_t *)m3tr_ptr;
  gboolean found = FALSE;
  guint element;
  stat_tap_table* table;
  stat_tap_table_item_type* item_data;
  guint msu_count;
  guint byte_count;
  double avg_bytes = 0.0;

  if (m3tr->mtp3_si_code >= MTP3_NUM_SI_CODE)
  {
    /*
     * we thought this si_code was not used ?
     * is MTP3_NUM_SI_CODE out of date ?
     */
    return TAP_PACKET_DONT_REDRAW;
  }

  /*
   * look for opc/dpc pair
   */
  table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);
  for (element = 0; element < table->num_elements; element++)
  {
    stat_tap_table_item_type *opc_data, *dpc_data, *si_data;
    opc_data = stat_tap_get_field_data(table, element, OPC_COLUMN);
    dpc_data = stat_tap_get_field_data(table, element, DPC_COLUMN);
    si_data = stat_tap_get_field_data(table, element, SI_COLUMN);

    if (memcmp(&m3tr->addr_opc, opc_data->user_data.ptr_value, sizeof(mtp3_addr_pc_t)) == 0)
    {
      if (memcmp(&m3tr->addr_dpc, dpc_data->user_data.ptr_value, sizeof(mtp3_addr_pc_t)) == 0)
      {
        if (m3tr->mtp3_si_code == si_data->user_data.uint_value)
        {
          found = TRUE;
          break;
        }
      }
    }
  }

  if (!found) {
    /* Add a new row */
    /* XXX The old version added a row per SI. */
    int num_fields = sizeof(mtp3_stat_fields)/sizeof(stat_tap_table_item);
    stat_tap_table_item_type items[sizeof(mtp3_stat_fields)/sizeof(stat_tap_table_item)];
    char str[256];
    const char *sis;
    char *col_str;

    memset(items, 0, sizeof(items));

    items[OPC_COLUMN].type = TABLE_ITEM_STRING;
    items[DPC_COLUMN].type = TABLE_ITEM_STRING;
    items[SI_COLUMN].type = TABLE_ITEM_STRING;
    items[NUM_MSUS_COLUMN].type = TABLE_ITEM_UINT;
    items[NUM_BYTES_COLUMN].type = TABLE_ITEM_UINT;
    items[AVG_BYTES_COLUMN].type = TABLE_ITEM_FLOAT;

    stat_tap_init_table_row(table, element, num_fields, items);

    item_data = stat_tap_get_field_data(table, element, OPC_COLUMN);
    mtp3_addr_to_str_buf(&m3tr->addr_opc, str, 256);
    item_data->value.string_value = g_strdup(str);
    item_data->user_data.ptr_value = g_memdup2(&m3tr->addr_opc, sizeof(mtp3_tap_rec_t));
    stat_tap_set_field_data(table, element, OPC_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, DPC_COLUMN);
    mtp3_addr_to_str_buf(&m3tr->addr_dpc, str, 256);
    item_data->value.string_value = g_strdup(str);
    item_data->user_data.ptr_value = g_memdup2(&m3tr->addr_dpc, sizeof(mtp3_tap_rec_t));
    stat_tap_set_field_data(table, element, DPC_COLUMN, item_data);

    sis = try_val_to_str(m3tr->mtp3_si_code, mtp3_service_indicator_code_short_vals);
    if (sis) {
      col_str = g_strdup(sis);
    } else {
      col_str = ws_strdup_printf("Unknown service indicator %d", m3tr->mtp3_si_code);
    }

    item_data = stat_tap_get_field_data(table, element, SI_COLUMN);
    item_data->value.string_value = col_str;
    item_data->user_data.uint_value = m3tr->mtp3_si_code;
    stat_tap_set_field_data(table, element, SI_COLUMN, item_data);
  }

  item_data = stat_tap_get_field_data(table, element, NUM_MSUS_COLUMN);
  item_data->value.uint_value++;
  msu_count = item_data->value.uint_value;
  stat_tap_set_field_data(table, element, NUM_MSUS_COLUMN, item_data);

  item_data = stat_tap_get_field_data(table, element, NUM_BYTES_COLUMN);
  item_data->value.uint_value += m3tr->size;
  byte_count = item_data->value.uint_value;
  stat_tap_set_field_data(table, element, NUM_BYTES_COLUMN, item_data);

  if (msu_count > 0) {
    avg_bytes = (double) byte_count / msu_count;
  }
  item_data = stat_tap_get_field_data(table, element, AVG_BYTES_COLUMN);
  item_data->value.float_value = avg_bytes;
  stat_tap_set_field_data(table, element, AVG_BYTES_COLUMN, item_data);

  return TAP_PACKET_REDRAW;
}

static void
mtp3_stat_reset(stat_tap_table* table)
{
  guint element;
  stat_tap_table_item_type* item_data;

  for (element = 0; element < table->num_elements; element++)
  {
    item_data = stat_tap_get_field_data(table, element, NUM_MSUS_COLUMN);
    item_data->value.uint_value = 0;
    stat_tap_set_field_data(table, element, NUM_MSUS_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, NUM_BYTES_COLUMN);
    item_data->value.uint_value = 0;
    stat_tap_set_field_data(table, element, NUM_BYTES_COLUMN, item_data);
  }
}

static void
mtp3_stat_free_table_item(stat_tap_table* table _U_, guint row _U_, guint column, stat_tap_table_item_type* field_data)
{
  switch(column) {
    case OPC_COLUMN:
    case DPC_COLUMN:
      g_free((char*)field_data->user_data.ptr_value);
      /* Fall through */
    case SI_COLUMN:
      g_free((char*)field_data->value.string_value);
      break;
    default:
      break;
  }
}


void
proto_register_mtp3(void)
{

  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_mtp3_service_indicator,     { "Service indicator",        "mtp3.service_indicator", FT_UINT8,  BASE_HEX,  VALS(mtp3_service_indicator_code_vals), SERVICE_INDICATOR_MASK,     NULL, HFILL }},
    { &hf_mtp3_network_indicator,     { "Network indicator",        "mtp3.network_indicator", FT_UINT8,  BASE_HEX,  VALS(mtp3_network_indicator_vals),      NETWORK_INDICATOR_MASK,     NULL, HFILL }},
    { &hf_mtp3_itu_spare,             { "Spare",                    "mtp3.spare",             FT_UINT8,  BASE_HEX,  NULL,                                   SPARE_MASK,                 NULL, HFILL }},
    { &hf_mtp3_itu_priority,          { "ITU priority",             "mtp3.priority",          FT_UINT8,  BASE_DEC,  NULL,                                   SPARE_MASK,                 NULL, HFILL }},
    { &hf_mtp3_ansi_priority,         { "ANSI Priority",            "mtp3.priority",          FT_UINT8,  BASE_DEC,  NULL,                                   ANSI_PRIORITY_MASK,         NULL, HFILL }},
    { &hf_mtp3_itu_opc,               { "OPC",                      "mtp3.opc",               FT_UINT32, BASE_DEC,  NULL,                                   ITU_OPC_MASK,               NULL, HFILL }},
    { &hf_mtp3_itu_pc,                { "PC",                       "mtp3.pc",                FT_UINT32, BASE_DEC,  NULL,                                   0x0,                        NULL, HFILL }},
    { &hf_mtp3_24bit_pc,              { "PC",                       "mtp3.pc",                FT_UINT32, BASE_DEC,  NULL,                                   ANSI_PC_MASK,               NULL, HFILL }},
    { &hf_mtp3_24bit_opc,             { "OPC",                      "mtp3.opc",               FT_UINT32, BASE_DEC,  NULL,                                   ANSI_PC_MASK,               NULL, HFILL }},
    { &hf_mtp3_ansi_opc,              { "OPC",                      "mtp3.ansi_opc",          FT_STRING, BASE_NONE, NULL,                                   0x0,                        NULL, HFILL }},
    { &hf_mtp3_chinese_opc,           { "OPC",                      "mtp3.chinese_opc",       FT_STRING, BASE_NONE, NULL,                                   0x0,                        NULL, HFILL }},
    { &hf_mtp3_opc_network,           { "OPC Network",              "mtp3.opc.network",       FT_UINT24, BASE_DEC,  NULL,                                   ANSI_NETWORK_MASK,          NULL, HFILL }},
    { &hf_mtp3_opc_cluster,           { "OPC Cluster",              "mtp3.opc.cluster",       FT_UINT24, BASE_DEC,  NULL,                                   ANSI_CLUSTER_MASK,          NULL, HFILL }},
    { &hf_mtp3_opc_member,            { "OPC Member",               "mtp3.opc.member",        FT_UINT24, BASE_DEC,  NULL,                                   ANSI_MEMBER_MASK,           NULL, HFILL }},
    { &hf_mtp3_japan_opc,             { "OPC",                      "mtp3.opc",               FT_UINT16, BASE_DEC,  NULL,                                   JAPAN_PC_MASK,              NULL, HFILL }},
    { &hf_mtp3_japan_pc,              { "PC",                       "mtp3.pc",                FT_UINT16, BASE_DEC,  NULL,                                   JAPAN_PC_MASK,              NULL, HFILL }},
    { &hf_mtp3_itu_dpc,               { "DPC",                      "mtp3.dpc",               FT_UINT32, BASE_DEC,  NULL,                                   ITU_DPC_MASK,               NULL, HFILL }},
    { &hf_mtp3_24bit_dpc,             { "DPC",                      "mtp3.dpc",               FT_UINT32, BASE_DEC,  NULL,                                   ANSI_PC_MASK,               NULL, HFILL }},
    { &hf_mtp3_ansi_dpc,              { "DPC",                      "mtp3.ansi_dpc",          FT_STRING, BASE_NONE, NULL,                                   0x0,                        NULL, HFILL }},
    { &hf_mtp3_chinese_dpc,           { "DPC",                      "mtp3.chinese_dpc",       FT_STRING, BASE_NONE, NULL,                                   0x0,                        NULL, HFILL }},
    { &hf_mtp3_dpc_network,           { "DPC Network",              "mtp3.dpc.network",       FT_UINT24, BASE_DEC,  NULL,                                   ANSI_NETWORK_MASK,          NULL, HFILL }},
    { &hf_mtp3_dpc_cluster,           { "DPC Cluster",              "mtp3.dpc.cluster",       FT_UINT24, BASE_DEC,  NULL,                                   ANSI_CLUSTER_MASK,          NULL, HFILL }},
    { &hf_mtp3_dpc_member,            { "DPC Member",               "mtp3.dpc.member",        FT_UINT24, BASE_DEC,  NULL,                                   ANSI_MEMBER_MASK,           NULL, HFILL }},
    { &hf_mtp3_japan_dpc,             { "DPC",                      "mtp3.dpc",               FT_UINT16, BASE_DEC,  NULL,                                   JAPAN_PC_MASK,              NULL, HFILL }},
    { &hf_mtp3_itu_sls,               { "Signalling Link Selector", "mtp3.sls",               FT_UINT32, BASE_DEC,  NULL,                                   ITU_SLS_MASK,               NULL, HFILL }},
    { &hf_mtp3_japan_4_bit_sls,       { "Signalling Link Selector", "mtp3.sls",               FT_UINT8,  BASE_DEC,  NULL,                                   JAPAN_4_BIT_SLS_MASK,       NULL, HFILL }},
    { &hf_mtp3_japan_4_bit_sls_spare, { "SLS Spare",                "mtp3.sls_spare",         FT_UINT8,  BASE_HEX,  NULL,                                   JAPAN_4_BIT_SLS_SPARE_MASK, NULL, HFILL }},
    { &hf_mtp3_japan_5_bit_sls,       { "Signalling Link Selector", "mtp3.sls",               FT_UINT8,  BASE_DEC,  NULL,                                   JAPAN_5_BIT_SLS_MASK,       NULL, HFILL }},
    { &hf_mtp3_japan_5_bit_sls_spare, { "SLS Spare",                "mtp3.sls_spare",         FT_UINT8,  BASE_HEX,  NULL,                                   JAPAN_5_BIT_SLS_SPARE_MASK, NULL, HFILL }},
    { &hf_mtp3_ansi_5_bit_sls,        { "Signalling Link Selector", "mtp3.sls",               FT_UINT8,  BASE_DEC,  NULL,                                   ANSI_5BIT_SLS_MASK,         NULL, HFILL }},
    { &hf_mtp3_ansi_8_bit_sls,        { "Signalling Link Selector", "mtp3.sls",               FT_UINT8,  BASE_DEC,  NULL,                                   ANSI_8BIT_SLS_MASK,         NULL, HFILL }},
    { &hf_mtp3_chinese_itu_sls,       { "Signalling Link Selector", "mtp3.sls",               FT_UINT8,  BASE_DEC,  NULL,                                   CHINESE_ITU_SLS_MASK,       NULL, HFILL }},
    { &hf_mtp3_heuristic_standard,    { "Heuristic standard",       "mtp3.heuristic_standard",FT_UINT32, BASE_DEC,  NULL,                                   0x0,                        NULL, HFILL }},
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_mtp3,
    &ett_mtp3_sio,
    &ett_mtp3_label,
    &ett_mtp3_label_dpc,
    &ett_mtp3_label_opc
  };

  static const enum_val_t mtp3_options[] = {
    { "itu",          "ITU",          ITU_STANDARD },
    { "ansi",         "ANSI",         ANSI_STANDARD },
    { "chinese-itu",  "Chinese ITU",  CHINESE_ITU_STANDARD },
    { "japan",        "Japan",        JAPAN_STANDARD },
    { NULL,   NULL,   0 }
  };

  static const enum_val_t mtp3_addr_fmt_str_e[] = {
    { "decimal",        "Decimal",        MTP3_ADDR_FMT_DEC },
    { "hexadecimal",    "Hexadecimal",    MTP3_ADDR_FMT_HEX },
    { "ni-decimal",     "NI-Decimal",     MTP3_ADDR_FMT_NI_DEC },
    { "ni-hexadecimal", "NI-Hexadecimal", MTP3_ADDR_FMT_NI_HEX },
    { "dashed",         "Dashed",         MTP3_ADDR_FMT_DASHED },
    { NULL,   NULL,     0 }
  };

  static const enum_val_t itu_pc_structures[] = {
    { "unstructured", "Unstructured", ITU_PC_STRUCTURE_NONE},
    { "3-8-3",        "3-8-3",        ITU_PC_STRUCTURE_3_8_3 },
    { "4-3-4-3",      "4-3-4-3",      ITU_PC_STRUCTURE_4_3_4_3 },
    { NULL,   NULL,   0 }
  };

  static const enum_val_t japan_pc_structures[] = {
    { "unstructured", "Unstructured", JAPAN_PC_STRUCTURE_NONE},
    { "7-4-5",        "7-4-5",        JAPAN_PC_STRUCTURE_7_4_5 },
    { "3-4-4-5",      "3-4-4-5",      JAPAN_PC_STRUCTURE_3_4_4_5 },
    { NULL,   NULL,   0 }
  };

  static tap_param mtp3_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui mtp3_stat_table = {
    REGISTER_STAT_GROUP_TELEPHONY_MTP3,
    "MTP3 Statistics",
    "mtp3",
    "mtp3,msus",
    mtp3_stat_init,
    mtp3_stat_packet,
    mtp3_stat_reset,
    mtp3_stat_free_table_item,
    NULL,
    sizeof(mtp3_stat_fields)/sizeof(stat_tap_table_item), mtp3_stat_fields,
    sizeof(mtp3_stat_params)/sizeof(tap_param), mtp3_stat_params,
    NULL,
    0
  };

 /* Register the protocol name and description */
  proto_mtp3 = proto_register_protocol("Message Transfer Part Level 3",
               "MTP3", "mtp3");
  mtp3_handle = register_dissector("mtp3", dissect_mtp3, proto_mtp3);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_mtp3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  mtp3_sio_dissector_table = register_dissector_table("mtp3.service_indicator",
                  "MTP3 Service indicator",
                  proto_mtp3, FT_UINT8, BASE_HEX);

  mtp3_address_type = address_type_dissector_register("AT_SS7PC", "SS7 Point Code", mtp3_addr_to_str, mtp3_str_addr_len, NULL, NULL,
                                                            mtp3_addr_len, mtp3_addr_name_res_str, mtp3_addr_name_res_len);


  mtp3_tap = register_tap("mtp3");

  mtp3_module = prefs_register_protocol(proto_mtp3, NULL);

  prefs_register_bool_preference(mtp3_module, "heuristic_standard",
         "Try to determine the MTP3 standard heuristically",
         "This only works for SCCP traffic for now",
         &mtp3_heuristic_standard);

  prefs_register_enum_preference(mtp3_module, "standard", "MTP3 standard",
         "The SS7 standard used in MTP3 packets",
         &mtp3_standard, mtp3_options, FALSE);

  prefs_register_enum_preference(mtp3_module, "itu_pc_structure", "ITU Pointcode structure",
         "The structure of the pointcodes in ITU networks",
         &itu_pc_structure, itu_pc_structures, FALSE);

  prefs_register_enum_preference(mtp3_module, "japan_pc_structure", "Japan Pointcode structure",
         "The structure of the pointcodes in Japan networks",
         &japan_pc_structure, japan_pc_structures, FALSE);

  prefs_register_bool_preference(mtp3_module, "ansi_5_bit_sls",
         "Use 5-bit SLS (ANSI only)",
         "Use 5-bit (instead of 8-bit) SLS in ANSI MTP3 packets",
         &mtp3_use_ansi_5_bit_sls);

  prefs_register_bool_preference(mtp3_module, "japan_5_bit_sls",
         "Use 5-bit SLS (Japan only)",
         "Use 5-bit (instead of 4-bit) SLS in Japan MTP3 packets",
         &mtp3_use_japan_5_bit_sls);

  prefs_register_enum_preference(mtp3_module, "addr_format", "Address Format",
         "Format for point code in the address columns",
         &mtp3_addr_fmt, mtp3_addr_fmt_str_e, FALSE);

  prefs_register_bool_preference(mtp3_module, "itu_priority",
         "Show MSU priority (national option, ITU and China ITU only)",
         "Decode the spare bits of the SIO as the MSU priority (a national option in ITU)",
         &mtp3_show_itu_priority);

  register_stat_tap_table_ui(&mtp3_stat_table);
}

void
proto_reg_handoff_mtp3(void)
{
  dissector_add_uint("wtap_encap", WTAP_ENCAP_MTP3, mtp3_handle);
  dissector_add_string("tali.opcode", "mtp3", mtp3_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
