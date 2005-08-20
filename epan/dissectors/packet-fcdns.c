/* packet-fc-dns.c
 * Routines for FC distributed Name Server (dNS)
 * Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include "etypes.h"
#include "packet-fc.h"
#include "packet-fcct.h"
#include "packet-fcdns.h"
#include "packet-fcswils.h"

/*
 * See FC-GS-2.
 */

/* Initialize the protocol and registered fields */
static int proto_fcdns              = -1;
static int hf_fcdns_gssubtype       = -1;
static int hf_fcdns_opcode          = -1;
static int hf_fcdns_reason          = -1;
static int hf_fcdns_vendor          = -1;
static int hf_fcdns_req_portid      = -1;
static int hf_fcdns_rply_pname      = -1;
static int hf_fcdns_rply_nname      = -1;
static int hf_fcdns_rply_cos        = -1;
static int hf_fcdns_rply_gft        = -1;
static int hf_fcdns_rply_snamelen   = -1;
static int hf_fcdns_rply_sname      = -1;
static int hf_fcdns_rply_ptype      = -1;
static int hf_fcdns_rply_fpname     = -1;
static int hf_fcdns_fc4type         = -1;
static int hf_fcdns_rply_fc4type    = -1;
static int hf_fcdns_rply_fc4desc    = -1;
static int hf_fcdns_rply_fc4feat    = -1;
static int hf_fcdns_req_pname       = -1;
static int hf_fcdns_rply_portid     = -1;
static int hf_fcdns_req_nname       = -1;
static int hf_fcdns_req_domainscope = -1;
static int hf_fcdns_req_areascope   = -1;
static int hf_fcdns_req_fc4type     = -1;
static int hf_fcdns_req_ptype       = -1;
static int hf_fcdns_req_fc4feature  = -1;
static int hf_fcdns_req_cos         = -1;
static int hf_fcdns_req_fc4types    = -1;
static int hf_fcdns_req_snamelen    = -1;
static int hf_fcdns_req_sname       = -1;
static int hf_fcdns_rply_spnamelen  = -1;
static int hf_fcdns_rply_spname     = -1;
static int hf_fcdns_req_spnamelen   = -1;
static int hf_fcdns_req_spname      = -1;
static int hf_fcdns_rply_ipa        = -1;
static int hf_fcdns_rply_ipnode     = -1;
static int hf_fcdns_rply_ipport     = -1;
static int hf_fcdns_rply_fc4desclen = -1;
static int hf_fcdns_rply_hrdaddr    = -1;
static int hf_fcdns_req_fdesclen    = -1;
static int hf_fcdns_req_fdesc       = -1;
static int hf_fcdns_req_ip          = -1;
static int hf_fcdns_rjtdetail       = -1;
static int hf_fcdns_zone_mbrtype    = -1;
static int hf_fcdns_zone_mbrid      = -1;
static int hf_fcdns_zonenm          = -1;
static int hf_fcdns_portip          = -1;
static int hf_fcdns_sw2_objfmt      = -1;
static int hf_fcdns_num_fc4desc     = -1;
static int hf_fcdns_rply_ownerid    = -1;
static int hf_fcdns_maxres_size = -1;


/* Initialize the subtree pointers */
static gint ett_fcdns = -1;

typedef struct _fcdns_conv_key {
    guint32 conv_idx;
} fcdns_conv_key_t;

typedef struct _fcdns_conv_data {
    guint32 opcode;
} fcdns_conv_data_t;

GHashTable *fcdns_req_hash = NULL;

static dissector_handle_t data_handle;

/*
 * Hash Functions
 */
static gint
fcdns_equal(gconstpointer v, gconstpointer w)
{
  const fcdns_conv_key_t *v1 = v;
  const fcdns_conv_key_t *v2 = w;

  return (v1->conv_idx == v2->conv_idx);
}

static guint
fcdns_hash (gconstpointer v)
{
	const fcdns_conv_key_t *key = v;
	guint val;

	val = key->conv_idx;

	return val;
}

/*
 * Protocol initialization
 */
static void
fcdns_init_protocol(void)
{
	if (fcdns_req_hash)
            g_hash_table_destroy(fcdns_req_hash);

	fcdns_req_hash = g_hash_table_new(fcdns_hash, fcdns_equal);
}

static gchar *
fccos_to_str (tvbuff_t *tvb, int offset, gchar *cosstr)
{
    int stroff = 0,
        cos = 0;
    
    if (cosstr == NULL)
        return NULL;

    cos = tvb_get_ntohl (tvb, offset);

    cosstr[0] = '\0';

    if (cos & 0x1) {
        strcpy (cosstr, "F, ");
        stroff += 3;
    }
    
    if (cos & 0x2) {
        strcpy (&cosstr[stroff], "1, ");
        stroff += 3;
    }

    if (cos & 0x4) {
        strcpy (&cosstr[stroff], "2, ");
        stroff += 3;
    }

    if (cos & 0x8) {
        strcpy (&cosstr[stroff], "3, ");
        stroff += 3;
    }

    if (cos & 0x10) {
        strcpy (&cosstr[stroff], "4, ");
        stroff += 3;
    }

    if (cos & 0x40) {
        strcpy (&cosstr[stroff], "6");
    }

    return (cosstr);
}

/* The feature routines just decode FCP's FC-4 features field */
static gchar *
fc4feature_to_str (guint8 fc4feature, guint8 fc4type, gchar *str, int len)
{
    int stroff = 0;
    
    *str = '\0';

    if (fc4type == FC_TYPE_SCSI) {
        if (fc4feature & 0x1) {
            strcpy (str, "T, ");
            stroff += 3;
        }
        
        if (fc4feature & 0x2) {
            strcpy (&str[stroff], "I");
        }
    }
    else {
        g_snprintf (str, len, "0x%x", fc4feature);
    }
    return (str);
}

static gchar *
fc4ftrs_to_str (tvbuff_t *tvb, int offset, gchar *str)
{
    guint8 fc4feature;
    int stroff = 0;
    
    if (str == NULL) {
        return NULL;
    }

    *str = '\0';
    fc4feature = tvb_get_guint8 (tvb, offset+7);

    if (fc4feature & 0x1) {
        strcpy (str, "T, ");
        stroff += 3;
    }

    if (fc4feature & 0x2) {
        strcpy (&str[stroff], "I");
    }

    return (str);
}

/* Decodes LLC/SNAP, IP, FCP, VI, GS, SW_ILS types only */
/* Max len of str to be allocated by caller is 40 */
static gchar *
fc4type_to_str (tvbuff_t *tvb, int offset, gchar *str)
{
    guint32 fc4tword;
    int stroff = 0;

    if (str == NULL) {
        return NULL;
    }

    *str = '\0';

    fc4tword = tvb_get_ntohl (tvb, offset);
        
    if (fc4tword & 0x10) {
        strcpy (str, "LLC/SNAP, ");
        stroff += 10;
    }
    
    if (fc4tword & 0x20) {
        strcpy (&str[stroff], "IP, ");
        stroff += 4;
    }

    if (fc4tword & 0x0100) {
        strcpy (&str[stroff], "FCP, ");
        stroff += 5;
    }

    fc4tword = tvb_get_ntohl (tvb, offset+4);
    
    if (fc4tword & 0x1) {
        strcpy (&str[stroff], "GS3, ");
        stroff += 5;
    }

    if (fc4tword & 0x4) {
        strcpy (&str[stroff], "SNMP, ");
        stroff += 6;
    }

    if (fc4tword & 0x10) {
        strcpy (&str[stroff], "SW_ILS, ");
        stroff += 8;
    }

    fc4tword = tvb_get_ntohl (tvb, offset+8);
    if (fc4tword & 0x1) {
        strcpy (&str[stroff], "VI, ");
        stroff += 3;
    }
    return (str);
}

/* Code to actually dissect the packets */

/* A bunch of get routines have a similar req packet format. The first few
 * routines deal with this decoding. All assume that tree is valid */
static void
dissect_fcdns_req_portid (tvbuff_t *tvb, proto_tree *tree, int offset)
{
    if (tree) {
        proto_tree_add_string (tree, hf_fcdns_req_portid, tvb, offset, 3,
                               fc_to_str (tvb_get_ptr (tvb, offset, 3)));
    }
}

static void
dissect_fcdns_ganxt (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;
    gchar str[128];

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_ptype, tvb, offset,
                                 1, 0);
            proto_tree_add_string (req_tree, hf_fcdns_rply_portid, tvb,
                                   offset+1, 3,
                                   fc_to_str (tvb_get_ptr (tvb, offset+1, 3)));
            proto_tree_add_string (req_tree, hf_fcdns_rply_pname, tvb,
                                   offset+4, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset+4,
                                                              8)));
            len = tvb_get_guint8 (tvb, offset+12);
            proto_tree_add_item (req_tree, hf_fcdns_rply_spnamelen, tvb,
                                 offset+12, 1, 0);
            if (!tvb_offset_exists (tvb, 29+len))
                return;
            
            if (len) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_spname, tvb,
                                     offset+13, len, 0);
            }

            if (tvb_offset_exists (tvb, 292)) {
                proto_tree_add_string (req_tree, hf_fcdns_rply_nname, tvb,
                                       offset+268, 8,
                                       fcwwn_to_str (tvb_get_ptr (tvb,
                                                                  offset+268,
                                                                  0)));
            }
            if (tvb_offset_exists (tvb, 548)) {
                len = tvb_get_guint8 (tvb, offset+276);
                proto_tree_add_item (req_tree, hf_fcdns_rply_snamelen, tvb,
                                     offset+276, 1, 0);
                if (len) {
                    proto_tree_add_item (req_tree, hf_fcdns_rply_sname, tvb,
                                         offset+277, len, 0);
                }
            }
            if (tvb_offset_exists (tvb, 556)) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_ipa, tvb,
                                     offset+532, 8, 0);
            }
            if (tvb_offset_exists (tvb, 572)) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_ipnode, tvb,
                                     offset+540, 16, 0);
            }
            if (tvb_offset_exists (tvb, 576)) {
                proto_tree_add_string (req_tree, hf_fcdns_rply_cos, tvb, offset+556,
                                       4,
                                       fccos_to_str (tvb, offset+556, str));
            }
            if (tvb_offset_exists (tvb, 608)) {
                proto_tree_add_string (req_tree, hf_fcdns_rply_gft, tvb, offset+560,
                                       32,
                                       fc4type_to_str (tvb, offset+560, str));
            }
            if (tvb_offset_exists (tvb, 624)) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_ipport, tvb,
                                     offset+592, 16, 0);
            }
            if (tvb_offset_exists (tvb, 632)) {
                proto_tree_add_string (req_tree, hf_fcdns_rply_fpname, tvb,
                                       offset+608, 8,
                                       fcwwn_to_str (tvb_get_ptr (tvb, offset+608,
                                                                  8)));
            }
            if (tvb_offset_exists (tvb, 635)) {
                proto_tree_add_string (req_tree, hf_fcdns_rply_hrdaddr, tvb,
                                       offset+617, 3,
                                       fc_to_str (tvb_get_ptr (tvb, offset+617,
                                                               3)));
            }
        }
    }
}

static void
dissect_fcdns_gpnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_string (req_tree, hf_fcdns_rply_pname, tvb, offset,
                                   8, fcwwn_to_str (tvb_get_ptr (tvb, offset,
                                                                 8)));
        }
    }
}

static void
dissect_fcdns_gnnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_string (req_tree, hf_fcdns_rply_nname, tvb,
                                   offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset,
                                                              8)));
        }
    }
}

static void
dissect_fcdns_gcsid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    gchar cosstr[64];

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset);
        }
        else {
            proto_tree_add_string (req_tree, hf_fcdns_rply_cos, tvb,
                                   offset, 4,
                                   fccos_to_str (tvb, offset, cosstr));
        }
    }
}

static void
dissect_fcdns_gftid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    gchar fc4str[64];

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_string (req_tree, hf_fcdns_rply_gft, tvb,
                                   offset, 32,
                                   fc4type_to_str (tvb, offset, fc4str));
        }
    }
}

static void
dissect_fcdns_gspnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_item (req_tree, hf_fcdns_rply_spnamelen, 
                                 tvb, offset, 1, 0);
            proto_tree_add_string (req_tree, hf_fcdns_rply_spname, tvb,
                                   offset+1, len,
                                   tvb_get_ptr (tvb, offset+1, len));
        }
    }
}

static void
dissect_fcdns_gptid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_ptype, tvb,
                                 offset, 1, 0);
        }
    }
}

static void
dissect_fcdns_gfpnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_string (req_tree, hf_fcdns_rply_fpname, tvb,
                                   offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset,
                                                              8)));
        }
    }

}

static void
dissect_fcdns_gfdid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    gchar fc4str[128];
    int tot_len, desclen;

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
            proto_tree_add_string (req_tree, hf_fcdns_fc4type, tvb, offset+4,
                                   32,
                                   fc4type_to_str (tvb, offset+4, fc4str));
        }
        else {
            tot_len = tvb_length (tvb) - offset; /* excluding CT header */
            while (tot_len > 0) {
                /* The count of the descriptors is not returned and so we have
                 * to track the display by the length field */
                desclen = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_fc4desc, tvb,
                                     offset, desclen, 0);
                tot_len -= 255; /* descriptors are aligned to 255 bytes */
                offset += 256;
            }
        }
    }
}

static void
dissect_fcdns_gffid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    gchar fc4fstr[128];

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_string (req_tree, hf_fcdns_rply_fc4feat, tvb,
                                   offset, 128,
                                   fc4ftrs_to_str (tvb, offset, fc4fstr));
        }
    }
}

static void
dissect_fcdns_gidpn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, hf_fcdns_req_pname, tvb,
                                   offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset,
                                                              8)));
        }
        else {
            proto_tree_add_string (req_tree, hf_fcdns_rply_portid, tvb,
                                   offset+1, 3,
                                   fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                           3)));
        }
    }
}

static void
dissect_fcdns_gipppn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, hf_fcdns_req_pname, tvb,
                                   offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset,
                                                              8)));
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_ipport, tvb, offset,
                                 16, 0);
        }
    }
}

static void
dissect_fcdns_gidnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, hf_fcdns_req_nname, tvb,
                                   offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset,
                                                              8)));
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                               3)));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gipnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, hf_fcdns_req_nname, tvb,
                                   offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset,
                                                              8)));
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_ipnode, tvb, offset,
                                 16, 0);
        }
    }
}

static void
dissect_fcdns_gpnnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, hf_fcdns_req_nname, tvb,
                                   offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset,
                                                              8)));
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                               3)));
                proto_tree_add_string (req_tree, hf_fcdns_rply_pname,
                                       tvb, offset+8, 8,
                                       fcwwn_to_str (tvb_get_ptr (tvb,
                                                                  offset+8,
                                                                  8)));
                offset += 16;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gsnnnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, hf_fcdns_req_nname, tvb,
                                   offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset,
                                                              8)));
        }
        else {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_item (req_tree, hf_fcdns_rply_snamelen, tvb,
                                 offset, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_rply_sname, tvb,
                                 offset+1, len, 0);
        }
    }
}

static void
dissect_fcdns_gidft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope,
                                 tvb, offset+1, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope,
                                 tvb, offset+2, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_fc4type,
                                 tvb, offset+3, 1, 0);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                               3)));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gpnft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope,
                                 tvb, offset+1, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope,
                                 tvb, offset+2, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_fc4type,
                                 tvb, offset+3, 1, 0);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                               3)));
                proto_tree_add_string (req_tree, hf_fcdns_rply_pname,
                                       tvb, offset+4, 8,
                                       fcwwn_to_str (tvb_get_ptr (tvb, offset+8,
                                                                  8)));
                offset += 16;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gnnft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope,
                                 tvb, offset+1, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope,
                                 tvb, offset+2, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_fc4type,
                                 tvb, offset+3, 1, 0);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                               3)));
                proto_tree_add_string (req_tree, hf_fcdns_rply_nname,
                                       tvb, offset+4, 8,
                                       fcwwn_to_str (tvb_get_ptr (tvb, offset+8,
                                                                  8)));
                offset += 16;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gidpt (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast = 0;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_ptype,
                                 tvb, offset, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope,
                                 tvb, offset+1, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope,
                                 tvb, offset+2, 1, 0);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                               3)));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gidipp (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_ip, tvb, offset,
                                 16, 0);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                               3)));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gidff (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;
    gchar *str;

    str=ep_alloc(64);
    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope, tvb,
                                 offset+1, 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope, tvb,
                                 offset+2, 1, 0);
            proto_tree_add_string (req_tree, hf_fcdns_req_fc4feature, tvb,
                                   offset+6, 1,
                                   fc4feature_to_str (tvb_get_guint8 (tvb, offset+6),
                                                      tvb_get_guint8 (tvb, offset+7),
                                                      str, 64));
            proto_tree_add_item (req_tree, hf_fcdns_req_fc4type, tvb,
                                 offset+7, 1, 0);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                               3)));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_rpnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, hf_fcdns_req_portid,
                                   tvb, offset+1, 3,
                                   fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                           3)));
            proto_tree_add_string (req_tree, hf_fcdns_req_pname, tvb,
                                   offset+4, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset+4,
                                                              8)));
        }
    }
}

static void
dissect_fcdns_rnnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, hf_fcdns_req_portid,
                                   tvb, offset+1, 3,
                                   fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                           3)));
            proto_tree_add_string (req_tree, hf_fcdns_req_nname, tvb, 
                                   offset+4, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset+4,
                                                              8)));
        }
    }
}

static void
dissect_fcdns_rcsid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    gchar cos[64];

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3,
                               fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                       3)));
        proto_tree_add_string (req_tree, hf_fcdns_req_cos, tvb,
                               offset+4, 4,
                               fccos_to_str (tvb, offset+4, cos));
    }
}

static void
dissect_fcdns_rptid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3,
                               fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                       3)));
        proto_tree_add_item (req_tree, hf_fcdns_req_ptype, tvb,
                             offset+4, 1, 0);
    }
}

static void
dissect_fcdns_rftid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    gchar fc4str[128];

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3,
                               fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                       3)));
        proto_tree_add_string (req_tree, hf_fcdns_req_fc4types, tvb,
                               offset+4, 32,
                               fc4type_to_str (tvb, offset+4, fc4str));
    }
}

static void
dissect_fcdns_rspnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3,
                               fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                       3)));
        proto_tree_add_item (req_tree, hf_fcdns_req_spnamelen, tvb,
                             offset+4, 1, 0);
        len = tvb_get_guint8 (tvb, offset+4);
        
        proto_tree_add_item (req_tree, hf_fcdns_req_spname, tvb, offset+5,
                             len, 0);
    }
}

static void
dissect_fcdns_rippid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3,
                               fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                       3)));
        proto_tree_add_item (req_tree, hf_fcdns_req_ip, tvb,
                             offset+4, 16, 0);
    }
}

static void
dissect_fcdns_rfdid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len, dlen;
    gchar fc4str[128];

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3,
                               fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                       3)));
        proto_tree_add_string (req_tree, hf_fcdns_req_fc4types, tvb,
                               offset+4, 32,
                               fc4type_to_str (tvb, offset+4, fc4str));

        len = tvb_length (tvb) - offset - 36;
        offset += 36;
        
        while (len > 0) {
            dlen = tvb_get_guint8 (tvb, offset);
            proto_tree_add_item (req_tree, hf_fcdns_req_fdesclen, tvb, offset,
                                 1, 0);
            proto_tree_add_item (req_tree, hf_fcdns_req_fdesc, tvb, offset+1,
                                 len, 0);
            offset += 256;
            len -= 256;
        }
    }
}

static void
dissect_fcdns_rffid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    gchar *fc4str;

    fc4str=ep_alloc(64);
    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_portid, tvb, offset+1, 3,
                               fc_to_str (tvb_get_ptr (tvb, offset+1, 3)));
        proto_tree_add_string (req_tree, hf_fcdns_req_fc4feature, tvb,
                               offset+6, 1,
                               fc4feature_to_str (tvb_get_guint8 (tvb,
                                                                  offset+6),
                                                  tvb_get_guint8 (tvb,
                                                                  offset+7),
                                                  fc4str, 64));
        proto_tree_add_item (req_tree, hf_fcdns_req_fc4type, tvb, offset+7,
                             1, 0);
    }
}

static void
dissect_fcdns_ripnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_nname, tvb, offset, 8,
                               fcwwn_to_str (tvb_get_ptr (tvb, offset, 8)));
        proto_tree_add_item (req_tree, hf_fcdns_req_ip, tvb, offset+8, 16, 0);
    }
}

static void
dissect_fcdns_rsnnnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_nname, tvb, offset, 8,
                               fcwwn_to_str (tvb_get_ptr (tvb, offset, 8)));
        len = tvb_get_guint8 (tvb, offset+8);

        proto_tree_add_item (req_tree, hf_fcdns_req_snamelen, tvb, offset+8,
                             1, 0);
        proto_tree_add_item (req_tree, hf_fcdns_req_sname, tvb, offset+9,
                             len, 0);
    }
}

static void
dissect_fcdns_daid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, hf_fcdns_req_portid, tvb, offset+1, 3,
                               fc_to_str (tvb_get_ptr (tvb, offset+1, 3)));
    }
}

static guint8 *
zonenm_to_str (tvbuff_t *tvb, gint offset)
{
    int len = tvb_get_guint8 (tvb, offset);
    return tvb_get_ephemeral_string (tvb, offset+4, len);
}

static void
dissect_fcdns_zone_mbr (tvbuff_t *tvb, proto_tree *zmbr_tree, int offset)
{
    guint8 mbrtype;
    int idlen;
    char dpbuf[2+8+1];
    char *str;

    mbrtype = tvb_get_guint8 (tvb, offset);
    proto_tree_add_uint (zmbr_tree, hf_fcdns_zone_mbrtype, tvb,
                         offset, 1, mbrtype);
    proto_tree_add_text (zmbr_tree, tvb, offset+2, 1, "Flags: 0x%x",
                         tvb_get_guint8 (tvb, offset+2));
    idlen = tvb_get_guint8 (tvb, offset+3);
    proto_tree_add_text (zmbr_tree, tvb, offset+3, 1,
                         "Identifier Length: %d", idlen);
    switch (mbrtype) {
    case FC_SWILS_ZONEMBR_WWN:
        proto_tree_add_string (zmbr_tree, hf_fcdns_zone_mbrid, tvb,
                               offset+4, 8,
                               fcwwn_to_str (tvb_get_ptr (tvb,
                                                          offset+4,
                                                          8)));
        break;
    case FC_SWILS_ZONEMBR_DP:
        g_snprintf(dpbuf, sizeof(dpbuf), "0x%08x", tvb_get_ntohl (tvb, offset+4));
        proto_tree_add_string (zmbr_tree, hf_fcdns_zone_mbrid, tvb,
                               offset+4, 4, dpbuf);
        break;
    case FC_SWILS_ZONEMBR_FCID:
        proto_tree_add_string (zmbr_tree, hf_fcdns_zone_mbrid, tvb,
                               offset+4, 4,
                               fc_to_str (tvb_get_ptr (tvb,
                                                       offset+5,
                                                       3)));
        break;
    case FC_SWILS_ZONEMBR_ALIAS:
        str = zonenm_to_str (tvb, offset+4);
        proto_tree_add_string (zmbr_tree, hf_fcdns_zone_mbrid, tvb,
                               offset+4, idlen, str);
        break;
    default:
        proto_tree_add_string (zmbr_tree, hf_fcdns_zone_mbrid, tvb,
                               offset+4, idlen,
                               "Unknown member type format");
            
    }
}

static void
dissect_fcdns_swils_entries (tvbuff_t *tvb, proto_tree *tree, int offset)
{
    int numrec, i, len;
    guint8 objfmt;
    gchar str[512];

    numrec = tvb_get_ntohl (tvb, offset);

    if (tree) {
        proto_tree_add_text (tree, tvb, offset, 4, "Number of Entries: %d",
                             numrec);
        offset += 4;

        for (i = 0; i < numrec; i++) {
            objfmt = tvb_get_guint8 (tvb, offset);

            proto_tree_add_item (tree, hf_fcdns_sw2_objfmt, tvb, offset, 1, 0);
            proto_tree_add_string (tree, hf_fcdns_rply_ownerid, tvb, offset+1, 
                                   3, fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                              3)));
            proto_tree_add_item (tree, hf_fcdns_rply_ptype, tvb, offset+4,
                                 1, 0);
            proto_tree_add_string (tree, hf_fcdns_rply_portid, tvb, offset+5, 3,
                                   fc_to_str (tvb_get_ptr (tvb, offset+5, 3)));
            proto_tree_add_string (tree, hf_fcdns_rply_pname, tvb, offset+8, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset+8,
                                                              8)));
            offset += 16;
            if (!(objfmt & 0x1)) {
                len = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (tree, hf_fcdns_rply_spnamelen, tvb,
                                     offset, 1, 0);
                proto_tree_add_item (tree, hf_fcdns_rply_spname, tvb,
                                     offset+1, len, 0);
                offset += 256;
            }
            proto_tree_add_string (tree, hf_fcdns_rply_nname, tvb, offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset, 8)));
            offset += 8;
            if (!(objfmt & 0x1)) {
                len = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (tree, hf_fcdns_rply_snamelen, tvb,
                                     offset, 1, 0);
                proto_tree_add_item (tree, hf_fcdns_rply_sname, tvb,
                                     offset+1, len, 0);
                offset += 256;
            }
            proto_tree_add_item (tree, hf_fcdns_rply_ipa, tvb, offset, 8, 0);
            proto_tree_add_item (tree, hf_fcdns_rply_ipnode, tvb, offset+8, 16,
                                 0);
            proto_tree_add_string (tree, hf_fcdns_rply_cos, tvb, offset+24, 4,
                                   fccos_to_str (tvb, offset+24, str));
            proto_tree_add_string (tree, hf_fcdns_rply_gft, tvb, offset+28,
                                   32,
                                   fc4type_to_str (tvb, offset+28, str));
            proto_tree_add_item (tree, hf_fcdns_rply_ipport, tvb, offset+60,
                                 16, 0);
            proto_tree_add_string (tree, hf_fcdns_rply_fpname, tvb, offset+76,
                                   8, fcwwn_to_str (tvb_get_ptr (tvb,
                                                                 offset+76,
                                                                 8)));
            proto_tree_add_string (tree, hf_fcdns_rply_hrdaddr, tvb, offset+85,
                                   3, fc_to_str (tvb_get_ptr (tvb, offset+85,
                                                              3)));
            offset += 88;
            if (objfmt & 0x2) {
                proto_tree_add_string (tree, hf_fcdns_rply_fc4feat, tvb,
                                       offset, 128,
                                       fc4ftrs_to_str (tvb, offset, str));
                if (tvb_get_guint8 (tvb, offset+129)) {
                    proto_tree_add_item (tree, hf_fcdns_rply_fc4type, tvb,
                                         offset+128, 1, 0);
                    proto_tree_add_item (tree, hf_fcdns_num_fc4desc, tvb,
                                         offset+129, 1, 0);
                    len = tvb_get_guint8 (tvb, offset+132);
                    proto_tree_add_item (tree, hf_fcdns_rply_fc4desclen, tvb,
                                         offset+132, 1, 0);
                    proto_tree_add_item (tree, hf_fcdns_rply_fc4desc, tvb,
                                         offset+133, len, 0);
                }
                else {
                    proto_tree_add_item (tree, hf_fcdns_num_fc4desc, tvb,
                                         offset+129, 1, 0);
                }
                offset += 388;  /* FC4 desc is 260 bytes, maybe padded */ 
            }
        }
    }
}

static void
dissect_fcdns_geid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_string (req_tree, hf_fcdns_req_portid, tvb, offset+1,
                                   3, fc_to_str (tvb_get_ptr (tvb, offset+1,
                                                              3)));
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gepn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    if (isreq) {
        if (req_tree) {
            proto_tree_add_string (req_tree, hf_fcdns_req_pname, tvb, offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset, 8)));
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_genn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_string (req_tree, hf_fcdns_req_nname, tvb, offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset, 8)));
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geip (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_item (req_tree, hf_fcdns_req_ip, tvb, offset, 16, 0);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    gchar str[128];

    if (isreq) {
        if (req_tree) {
            proto_tree_add_string (req_tree, hf_fcdns_fc4type, tvb, offset, 32,
                                   fc4type_to_str (tvb, offset, str));
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gept (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_item (req_tree, hf_fcdns_req_ptype, tvb, offset+3,
                                 1, 0);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gezm (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            dissect_fcdns_zone_mbr (tvb, req_tree, offset);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gezn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int strlen;

    if (isreq) {
        if (req_tree) {
            strlen = tvb_get_guint8 (tvb, offset);
            proto_tree_add_text (req_tree, tvb, offset, 1, "Name Length: %d",
                                 strlen);
            proto_tree_add_string (req_tree, hf_fcdns_zonenm, tvb, offset+3,
                                   strlen, tvb_get_ptr (tvb, offset+3, strlen));
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geipp (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_item (req_tree, hf_fcdns_portip, tvb, offset, 4, 0);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geff (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    gchar str[256];

    if (isreq) {
        if (req_tree) {
            proto_tree_add_string (req_tree, hf_fcdns_req_fc4feature, tvb, offset,
                                   128, fc4ftrs_to_str (tvb, offset, str));
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_rjt (tvbuff_t *tvb, proto_tree *req_tree)
{
    int offset = 0;

    if (req_tree) {
        proto_tree_add_item (req_tree, hf_fcdns_reason, tvb, offset+13, 1, 0);
        proto_tree_add_item (req_tree, hf_fcdns_rjtdetail, tvb, offset+14, 1,
                             0);
        proto_tree_add_item (req_tree, hf_fcdns_vendor, tvb, offset+15, 1, 0);
    }
}

static void
dissect_fcdns (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti = NULL;
    proto_tree *fcdns_tree = NULL;
    int offset = 0;
    int opcode,
        failed_opcode = 0;
    int isreq = 1;
    fc_ct_preamble cthdr;
    conversation_t *conversation;
    fcdns_conv_data_t *cdata;
    fcdns_conv_key_t ckey, *req_key;

    tvb_memcpy (tvb, (guint8 *)&cthdr, offset, FCCT_PRMBL_SIZE);
    cthdr.revision = tvb_get_guint8 (tvb, offset);
    cthdr.in_id = tvb_get_ntoh24 (tvb, offset+1);
    cthdr.opcode = ntohs (cthdr.opcode);
    opcode = cthdr.opcode;
    cthdr.maxres_size = ntohs (cthdr.maxres_size);

    /* Determine the type of server the request/response is for */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        if (cthdr.gstype == FCCT_GSTYPE_DIRSVC)
            col_set_str (pinfo->cinfo, COL_PROTOCOL, "dNS");
        else
            col_set_str (pinfo->cinfo, COL_PROTOCOL, "Unzoned NS");
    }

    if (tree) {
        if (cthdr.gstype == FCCT_GSTYPE_DIRSVC) {
            ti = proto_tree_add_protocol_format (tree, proto_fcdns, tvb, 0,
                                                 tvb_reported_length (tvb),
                                                 "dNS");
            fcdns_tree = proto_item_add_subtree (ti, ett_fcdns);
        }
        else {
            ti = proto_tree_add_protocol_format (tree, proto_fcdns, tvb, 0,
                                                 tvb_reported_length (tvb),
                                                 "Unzoned NS");
            fcdns_tree = proto_item_add_subtree (ti, ett_fcdns);
        }
    }

    if ((opcode != FCCT_MSG_ACC) && (opcode != FCCT_MSG_RJT)) {
        conversation = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                          pinfo->ptype, pinfo->oxid,
                                          pinfo->rxid, NO_PORT2);
        if (!conversation) {
            conversation = conversation_new (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                             pinfo->ptype, pinfo->oxid,
                                             pinfo->rxid, NO_PORT2);
        }
    
        ckey.conv_idx = conversation->index;
        
        cdata = (fcdns_conv_data_t *)g_hash_table_lookup (fcdns_req_hash,
                                                            &ckey);
        if (cdata) {
            /* Since we never free the memory used by an exchange, this maybe a
             * case of another request using the same exchange as a previous
             * req. 
             */
            cdata->opcode = opcode;
        }
        else {
            req_key = se_alloc (sizeof(fcdns_conv_key_t));
            req_key->conv_idx = conversation->index;
            
            cdata = se_alloc (sizeof(fcdns_conv_data_t));
            cdata->opcode = opcode;
            
            g_hash_table_insert (fcdns_req_hash, req_key, cdata);
        }
        if (check_col (pinfo->cinfo, COL_INFO)) {
            col_set_str (pinfo->cinfo, COL_INFO, val_to_str (opcode, fc_dns_opcode_val,
                                                          "0x%x"));
        }
    }
    else {
        /* Opcode is ACC or RJT */
        conversation = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                          pinfo->ptype, pinfo->oxid,
                                          pinfo->rxid, NO_PORT2);
        isreq = 0;
        if (!conversation) {
            if (tree && (opcode == FCCT_MSG_ACC)) {
                if (check_col (pinfo->cinfo, COL_INFO)) {
                    col_set_str (pinfo->cinfo, COL_INFO,
                                 val_to_str (opcode, fc_dns_opcode_val,
                                             "0x%x"));
                }
                /* No record of what this accept is for. Can't decode */
                proto_tree_add_text (fcdns_tree, tvb, 0, tvb_length (tvb),
                                     "No record of Exchg. Unable to decode MSG_ACC/RJT");
                return;
            }
        }
        else {
            ckey.conv_idx = conversation->index;

            cdata = (fcdns_conv_data_t *)g_hash_table_lookup (fcdns_req_hash, &ckey);

            if (cdata != NULL) {
                if (opcode == FCCT_MSG_ACC) {
                    opcode = cdata->opcode;
                }
                else
                    failed_opcode = cdata->opcode;
            }
            
            if (check_col (pinfo->cinfo, COL_INFO)) {
                if (opcode != FCCT_MSG_RJT) {
                    col_add_fstr (pinfo->cinfo, COL_INFO, "ACC (%s)",
                                  val_to_str (opcode, fc_dns_opcode_val,
                                              "0x%x"));
                }
                else {
                    col_add_fstr (pinfo->cinfo, COL_INFO, "RJT (%s)",
                                  val_to_str (failed_opcode,
                                              fc_dns_opcode_val,
                                              "0x%x"));
                }
            }
                
            if (tree) {
                if ((cdata == NULL) && (opcode != FCCT_MSG_RJT)) {
                    /* No record of what this accept is for. Can't decode */
                    proto_tree_add_text (fcdns_tree, tvb, 0, tvb_length (tvb),
                                         "No record of Exchg. Unable to decode MSG_ACC/RJT");
                    return;
                }
            }
        }
    }

     if (tree) {
        proto_tree_add_item (fcdns_tree, hf_fcdns_opcode, tvb, offset+8, 2, 0);
        proto_tree_add_item (fcdns_tree, hf_fcdns_maxres_size, tvb, offset+10,
                             2, 0);
    }
    
    switch (opcode) {
    case FCCT_MSG_RJT:
        dissect_fcdns_rjt (tvb, fcdns_tree);
        break;
    case FCDNS_GA_NXT:
        dissect_fcdns_ganxt (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPN_ID:
        dissect_fcdns_gpnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GNN_ID:
        dissect_fcdns_gnnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GCS_ID:
        dissect_fcdns_gcsid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFT_ID:
        dissect_fcdns_gftid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GSPN_ID:
        dissect_fcdns_gspnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPT_ID:
        dissect_fcdns_gptid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFPN_ID:
        dissect_fcdns_gfpnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFD_ID:
        dissect_fcdns_gfdid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFF_ID:
        dissect_fcdns_gffid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_PN:
        dissect_fcdns_gidpn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GIPP_PN:
        dissect_fcdns_gipppn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_NN:
        dissect_fcdns_gidnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPN_NN:
        dissect_fcdns_gpnnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GIP_NN:
        dissect_fcdns_gipnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GSNN_NN:
        dissect_fcdns_gsnnnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_FT:
        dissect_fcdns_gidft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPN_FT:
        dissect_fcdns_gpnft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GNN_FT:
        dissect_fcdns_gnnft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_PT:
        dissect_fcdns_gidpt (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_IPP:
        dissect_fcdns_gidipp (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_FF:
        dissect_fcdns_gidff (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RPN_ID:
        dissect_fcdns_rpnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RNN_ID:
        dissect_fcdns_rnnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RCS_ID:
        dissect_fcdns_rcsid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RPT_ID:
        dissect_fcdns_rptid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RFT_ID:
        dissect_fcdns_rftid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RSPN_ID:
        dissect_fcdns_rspnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RIPP_ID:
        dissect_fcdns_rippid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RFD_ID:
        dissect_fcdns_rfdid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RFF_ID:
        dissect_fcdns_rffid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RIP_NN:
        dissect_fcdns_ripnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RSNN_NN:
        dissect_fcdns_rsnnnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_DA_ID:
        dissect_fcdns_daid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_ID:
        dissect_fcdns_geid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_PN:
        dissect_fcdns_gepn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_NN:
        dissect_fcdns_genn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_IP:
        dissect_fcdns_geip (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_FT:
        dissect_fcdns_geft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_PT:
        dissect_fcdns_gept (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_ZM:
        dissect_fcdns_gezm (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_ZN:
        dissect_fcdns_gezn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_IPP:
        dissect_fcdns_geipp (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_FF:
        dissect_fcdns_geff (tvb, fcdns_tree, isreq);
        break;
    default:
        break;
    }
}

/* Register the protocol with Ethereal */

/* this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_fcdns (void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_fcdns_gssubtype,
          {"GS_Subtype", "fcdns.gssubtype", FT_UINT8, BASE_HEX,
           VALS (fc_dns_subtype_val), 0x0, "", HFILL}},
        {&hf_fcdns_opcode,
         {"Opcode", "fcdns.opcode", FT_UINT16, BASE_HEX, VALS (fc_dns_opcode_val),
          0x0, "", HFILL}},
        { &hf_fcdns_req_portid,
          {"Port Identifier", "fcdns.req.portid", FT_STRING, BASE_HEX, NULL, 0x0,
           "", HFILL}},
        { &hf_fcdns_rply_pname,
          {"Port Name", "fcdns.rply.pname", FT_STRING, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_fcdns_rply_nname,
          {"Node Name", "fcdns.rply.nname", FT_STRING, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_fcdns_rply_cos,
          {"Class of Service Supported", "fcdns.rply.cos", FT_STRING, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_fcdns_rply_gft,
          {"FC-4 Types Supported", "fcdns.rply.fc4type", FT_STRING, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_fcdns_rply_snamelen,
          {"Symbolic Node Name Length", "fcdns.rply.snamelen", FT_UINT8, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_fcdns_rply_sname,
          {"Symbolic Node Name", "fcdns.rply.sname", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_rply_ptype,
          {"Port Type", "fcdns.rply.porttype", FT_UINT8, BASE_HEX,
           VALS (fc_dns_port_type_val), 0x0, "", HFILL}},
        { &hf_fcdns_rply_fpname,
          {"Fabric Port Name", "fcdns.rply.fpname", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_fc4type,
          {"FC-4 Type", "fcdns.req.fc4type", FT_STRING, BASE_HEX, NULL, 0x0,
           "", HFILL}},
        { &hf_fcdns_rply_fc4feat,
          {"FC-4 Features", "fcdns.rply.fc4features", FT_STRING, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_fcdns_req_pname,
          {"Port Name", "fcdns.req.portname", FT_STRING, BASE_HEX, NULL, 0x0,
           "", HFILL}},
        { &hf_fcdns_rply_portid,
          {"Port Identifier", "fcdns.rply.portid", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_req_nname,
          {"Node Name", "fcdns.req.nname", FT_STRING, BASE_HEX, NULL, 0x0,
           "", HFILL}},
        { &hf_fcdns_req_domainscope,
          {"Domain ID Scope", "fcdns.req.domainid", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_req_areascope,
          {"Area ID Scope", "fcdns.req.areaid", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_req_fc4type,
          {"FC-4 Type", "fcdns.req.fc4type", FT_UINT8, BASE_HEX,
           VALS (fc_fc4_val), 0x0, "", HFILL}},
        { &hf_fcdns_req_ptype,
          {"Port Type", "fcdns.req.porttype", FT_UINT8, BASE_HEX,
           VALS (fc_dns_port_type_val), 0x0, "", HFILL}},
        { &hf_fcdns_req_ip,
          {"IP Address", "fcdns.req.ip", FT_IPv6, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_fcdns_req_fc4feature,
          {"FC-4 Feature Bits", "fcdns.req.fc4feature", FT_STRING,
           BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_fcdns_req_cos,
          {"Class of Service Supported", "fcdns.req.class", FT_STRING,
           BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_fcdns_req_fc4types,
          {"FC-4 TYPEs Supported", "fcdns.req.fc4types", FT_STRING,
           BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_fcdns_rply_fc4type,
          {"FC-4 Descriptor Type", "fcdns.rply.fc4type", FT_UINT8, BASE_HEX,
           VALS (fc_fc4_val), 0x0, "", HFILL}},
        { &hf_fcdns_req_snamelen,
          {"Symbolic Name Length", "fcdns.req.snamelen", FT_UINT8, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_fcdns_req_sname,
          {"Symbolic Port Name", "fcdns.req.sname", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_rply_spnamelen,
          {"Symbolic Port Name Length", "fcdns.rply.spnamelen", FT_UINT8,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        {&hf_fcdns_rply_spname,
         {"Symbolic Port Name", "fcdns.rply.spname", FT_STRING, BASE_HEX, NULL,
          0x0, "", HFILL}},
        { &hf_fcdns_rply_ipa,
          {"Initial Process Associator", "fcdns.rply.ipa", FT_BYTES, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_fcdns_rply_ipnode,
          {"Node IP Address", "fcdns.rply.ipnode", FT_IPv6, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_rply_ipport,
          {"Port IP Address", "fcdns.rply.ipport", FT_IPv6, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_rply_fc4desclen,
          {"FC-4 Descriptor Length", "fcdns.rply.fc4desclen", FT_UINT8,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_fcdns_rply_fc4desc,
          {"FC-4 Descriptor", "fcdns.rply.fc4desc", FT_BYTES, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_rply_hrdaddr,
          {"Hard Address", "fcdns.rply.hrdaddr", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_req_fdesclen,
          {"FC-4 Descriptor Length", "fcdns.req.fc4desclen", FT_UINT8, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_fcdns_req_fdesc,
          {"FC-4 Descriptor", "fcdns.req.fc4desc", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_req_spnamelen,
          {"Symbolic Port Name Length", "fcdns.req.spnamelen", FT_UINT8,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_fcdns_req_spname,
          {"Symbolic Port Name", "fcdns.req.spname", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_reason,
          {"Reason Code", "fcdns.rply.reason", FT_UINT8, BASE_HEX,
           VALS (fc_ct_rjt_code_vals), 0x0, "", HFILL}},
        { &hf_fcdns_rjtdetail,
          {"Reason Code Explanantion", "fcdns.rply.reasondet", FT_UINT8,
           BASE_HEX, VALS (fc_dns_rjt_det_code_val), 0x0, "", HFILL}},
        { &hf_fcdns_vendor,
          {"Vendor Unique Reject Code", "fcdns.rply.vendor", FT_UINT8,
           BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_fcdns_zone_mbrtype,
          {"Zone Member Type", "fcdns.zone.mbrtype", FT_UINT8, BASE_HEX,
           VALS (fc_swils_zonembr_type_val), 0x0, "", HFILL}},
        { &hf_fcdns_zone_mbrid,
          {"Member Identifier", "swils.zone.mbrid", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcdns_zonenm,
          {"Zone Name", "fcdns.zonename", FT_STRING, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_fcdns_portip,
          {"Port IP Address", "fcdns.portip", FT_IPv4, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_fcdns_sw2_objfmt,
          {"Name Entry Object Format", "fcdns.entry.objfmt", FT_UINT8, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_fcdns_num_fc4desc,
          {"Number of FC4 Descriptors Registered", "fcdns.entry.numfc4desc",
           FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_fcdns_rply_ownerid,
          {"Owner Id", "fcdns.rply.ownerid", FT_STRING, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_fcdns_maxres_size,
          {"Maximum/Residual Size", "fcdns.maxres_size", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
    };

    static gint *ett[] = {
        &ett_fcdns,
    };
    
    /* Register the protocol name and description */
    proto_fcdns = proto_register_protocol("Fibre Channel Name Server",
                                          "FC-dNS", "fcdns");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_fcdns, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_init_routine (&fcdns_init_protocol);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_fcdns (void)
{
    dissector_handle_t dns_handle;

    dns_handle = create_dissector_handle (dissect_fcdns, proto_fcdns);
    dissector_add("fcct.server", FCCT_GSRVR_DNS, dns_handle);
    dissector_add("fcct.server", FCCT_GSRVR_UNS, dns_handle);

    data_handle = find_dissector ("data");
}
