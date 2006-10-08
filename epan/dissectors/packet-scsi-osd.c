/* packet-scsi-osd.c
 * Ronnie sahlberg 2006
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <string.h>
#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include "packet-fc.h"
#include "packet-scsi.h"
#include "packet-scsi-osd.h"

static int proto_scsi_osd		= -1;
int hf_scsi_osd_opcode			= -1;
static int hf_scsi_osd_control		= -1;
static int hf_scsi_osd_add_cdblen	= -1;
static int hf_scsi_osd_svcaction	= -1;
static int hf_scsi_osd_option		= -1;
static int hf_scsi_osd_option_dpo	= -1;
static int hf_scsi_osd_option_fua	= -1;
static int hf_scsi_osd_getsetattrib	= -1;
static int hf_scsi_osd_timestamps_control	= -1;
static int hf_scsi_osd_formatted_capacity	= -1;
static int hf_scsi_osd_get_attributes_page	= -1;
static int hf_scsi_osd_get_attributes_allocation_length	= -1;
static int hf_scsi_osd_get_attributes_list_length= -1;
static int hf_scsi_osd_get_attributes_list_offset= -1;
static int hf_scsi_osd_retreived_attributes_offset = -1;
static int hf_scsi_osd_set_attributes_page	= -1;
static int hf_scsi_osd_set_attribute_length	= -1;
static int hf_scsi_osd_set_attribute_number	= -1;
static int hf_scsi_osd_set_attributes_offset	= -1;
static int hf_scsi_osd_set_attributes_list_length= -1;
static int hf_scsi_osd_set_attributes_list_offset= -1;
static int hf_scsi_osd_capability_format	= -1;
static int hf_scsi_osd_key_version	= -1;
static int hf_scsi_osd_icva		= -1;
static int hf_scsi_osd_security_method	= -1;
static int hf_scsi_osd_capability_expiration_time= -1;
static int hf_scsi_osd_audit= -1;
static int hf_scsi_osd_capability_discriminator	= -1;
static int hf_scsi_osd_object_created_time= -1;
static int hf_scsi_osd_object_type	= -1;
static int hf_scsi_osd_permission_bitmask= -1;
static int hf_scsi_osd_object_descriptor_type	= -1;
static int hf_scsi_osd_object_descriptor= -1;
static int hf_scsi_osd_ricv		= -1;
static int hf_scsi_osd_request_nonce	= -1;
static int hf_scsi_osd_diicvo		= -1;
static int hf_scsi_osd_doicvo		= -1;
static int hf_scsi_osd_requested_partition_id	= -1;
static int hf_scsi_osd_sortorder	= -1;
static int hf_scsi_osd_partition_id	= -1;
static int hf_scsi_osd_list_identifier	= -1;
static int hf_scsi_osd_allocation_length= -1;
static int hf_scsi_osd_initial_object_id= -1;
static int hf_scsi_osd_additional_length= -1;
static int hf_scsi_osd_continuation_object_id= -1;
static int hf_scsi_osd_list_flags_lstchg= -1;
static int hf_scsi_osd_list_flags_root= -1;
static int hf_scsi_osd_user_object_id= -1;
static int hf_scsi_osd_requested_user_object_id	= -1;
static int hf_scsi_osd_number_of_user_objects	= -1;

static gint ett_osd_option		= -1;
static gint ett_osd_attribute_parameters= -1;
static gint ett_osd_capability		= -1;
static gint ett_osd_security_parameters	= -1;

typedef struct _scsi_osd_extra_data_t {
	guint16 svcaction;
	guint8  gsatype;
	union {
		struct {	/* gsatype: attribute list */
			guint32 get_list_length;
			guint32 get_list_offset;
			guint32 get_list_allocation_length;
			guint32 retreived_list_offset;
			guint32 set_list_length;
			guint32 set_list_offset;
		};
	};
} scsi_osd_extra_data_t;

static const true_false_string option_dpo_tfs = {
	"DPO is SET",
	"Dpo is NOT set"
};
static const true_false_string option_fua_tfs = {
	"FUA is SET",
	"Fua is NOT set"
};

/* OSD2 5.2.4 */
static void
dissect_osd_option(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
	proto_tree *tree=NULL;
	proto_item *it=NULL;
	guint8 option;

	option=tvb_get_guint8(tvb, offset);

	if(parent_tree){
		it=proto_tree_add_item(parent_tree, hf_scsi_osd_option, tvb, offset, 1, 0);
		tree = proto_item_add_subtree(it, ett_osd_option);
	}

	proto_tree_add_item(tree, hf_scsi_osd_option_dpo, tvb, offset, 1, 0);
	if(option&0x10){
		proto_item_append_text(tree, " DPO");
	}

	proto_tree_add_item(tree, hf_scsi_osd_option_fua, tvb, offset, 1, 0);
	if(option&0x08){
		proto_item_append_text(tree, " FUA");
	}
}


static const value_string scsi_osd_getsetattrib_vals[] = {
    {2,		"Get an attributes page and set an attribute value"},
    {3,		"Get and set attributes using a list"},
    {0, NULL},
};
/* OSD2 5.2.2.1 */
static void
dissect_osd_getsetattrib(tvbuff_t *tvb, int offset, proto_tree *tree, scsi_task_data_t *cdata)
{
	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		scsi_osd_extra_data_t *extra_data=cdata->itlq->extra_data;
		extra_data->gsatype=(tvb_get_guint8(tvb, offset)>>4)&0x03;
	}
	proto_tree_add_item(tree, hf_scsi_osd_getsetattrib, tvb, offset, 1, 0);
}


static const value_string scsi_osd_timestamps_control_vals[] = {
    {0x00,	"Timestamps shall be updated"},
    {0x7f,	"Timestamps shall not be updated"},
    {0, NULL},
};
/* OSD2 5.2.8 */
static void
dissect_osd_timestamps_control(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_scsi_osd_timestamps_control, tvb, offset, 1, 0);
}


static void
dissect_osd_formatted_capacity(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_scsi_osd_formatted_capacity, tvb, offset, 8, 0);
}


static void
dissect_osd_attribute_parameters(tvbuff_t *tvb, int offset, proto_tree *parent_tree, scsi_task_data_t *cdata)
{
	guint8 gsatype=0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	scsi_osd_extra_data_t *extra_data=NULL;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 28,
		    "Attribute Parameters");
		tree = proto_item_add_subtree(item, ett_osd_attribute_parameters);
	}
		
	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		extra_data=cdata->itlq->extra_data;
		gsatype=extra_data->gsatype;
	} else {
		return;
	}

	switch(gsatype){
	case 2: /* 5.2.2.2  attribute page */
		proto_tree_add_item(tree, hf_scsi_osd_get_attributes_page, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_get_attributes_allocation_length, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_retreived_attributes_offset, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_set_attributes_page, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_set_attribute_length, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_set_attribute_number, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_set_attributes_offset, tvb, offset, 4, 0);
		offset+=4;
		break;
	case 3: /* 5.2.2.3  attribute list */
		proto_tree_add_item(tree, hf_scsi_osd_get_attributes_list_length, tvb, offset, 4, 0);
		extra_data->get_list_length=tvb_get_ntohl(tvb, offset);
		offset+=4;

		proto_tree_add_item(tree, hf_scsi_osd_get_attributes_list_offset, tvb, offset, 4, 0);
		extra_data->get_list_offset=tvb_get_ntohl(tvb, offset);
		offset+=4;

		proto_tree_add_item(tree, hf_scsi_osd_get_attributes_allocation_length, tvb, offset, 4, 0);
		extra_data->get_list_allocation_length=tvb_get_ntohl(tvb, offset);
		offset+=4;

		proto_tree_add_item(tree, hf_scsi_osd_retreived_attributes_offset, tvb, offset, 4, 0);
		extra_data->retreived_list_offset=tvb_get_ntohl(tvb, offset);
		offset+=4;

		proto_tree_add_item(tree, hf_scsi_osd_set_attributes_list_length, tvb, offset, 4, 0);
		extra_data->set_list_length=tvb_get_ntohl(tvb, offset);
		offset+=4;

		proto_tree_add_item(tree, hf_scsi_osd_set_attributes_list_offset, tvb, offset, 4, 0);
		extra_data->set_list_offset=tvb_get_ntohl(tvb, offset);
		offset+=4;

		/* 4 reserved bytes */
		offset+=4;

		break;
	}
}


static void
dissect_osd_attribute_data_out(tvbuff_t *tvb, int offset _U_, proto_tree *tree, scsi_task_data_t *cdata)
{
	guint8 gsatype=0;
	scsi_osd_extra_data_t *extra_data=NULL;

	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		extra_data=cdata->itlq->extra_data;
		gsatype=extra_data->gsatype;
	} else {
		return;
	}

	switch(gsatype){
	case 2: /* 5.2.2.2  attribute page */
/*qqq*/
		break;
	case 3: /* 5.2.2.3  attribute list */
		if(extra_data->get_list_length){
			proto_tree_add_text(tree, tvb, extra_data->get_list_offset, extra_data->get_list_length, "Get Attributes Data");
		}
		if(extra_data->set_list_length){
			proto_tree_add_text(tree, tvb, extra_data->set_list_offset, extra_data->set_list_length, "Set Attributes Data");
		}
		break;
	}
}


static void
dissect_osd_attribute_data_in(tvbuff_t *tvb, int offset _U_, proto_tree *tree, scsi_task_data_t *cdata)
{
	guint8 gsatype=0;
	scsi_osd_extra_data_t *extra_data=NULL;

	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		extra_data=cdata->itlq->extra_data;
		gsatype=extra_data->gsatype;
	} else {
		return;
	}

	switch(gsatype){
	case 2: /* 5.2.2.2  attribute page */
/*qqq*/
		break;
	case 3: /* 5.2.2.3  attribute list */
		if(extra_data->get_list_allocation_length){
			proto_tree_add_text(tree, tvb, extra_data->retreived_list_offset, extra_data->get_list_allocation_length, "Get Attributes Data");
		}
		break;
	}
}


static const value_string scsi_osd_capability_format_vals[] = {
    {0x00,	"No Capability"},
    {0x01,	"SCSI OSD2 Capabilities"},
    {0, NULL},
};
static const value_string scsi_osd_object_type_vals[] = {
    {0x01,	"ROOT"},
    {0x02,	"PARTITION"},
    {0x40,	"COLLECTION"},
    {0x80,	"USER"},
    {0, NULL},
};
static const value_string scsi_osd_object_descriptor_type_vals[] = {
    {0, "NONE: the object descriptor field shall be ignored"},
    {1, "U/C: a single collection or user object"},
    {2, "PAR: a single partition, including partition zero"},
    {0, NULL},
};

/* 4.9.2.2 */
static void
dissect_osd_capability(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 80,
		    "Capabilitiy");
		tree = proto_item_add_subtree(item, ett_osd_capability);
	}
		
	/* capability format */
	proto_tree_add_item(tree, hf_scsi_osd_capability_format, tvb, offset, 1, 0);
	offset++;

	/* key version and icva */
	proto_tree_add_item(tree, hf_scsi_osd_key_version, tvb, offset, 1, 0);
	proto_tree_add_item(tree, hf_scsi_osd_icva, tvb, offset, 1, 0);
	offset++;

	/* security method */
	proto_tree_add_item(tree, hf_scsi_osd_security_method, tvb, offset, 1, 0);
	offset++;

	/* a reserved byte */
	offset++;

	/* capability expiration time */
	proto_tree_add_item(tree, hf_scsi_osd_capability_expiration_time, tvb, offset, 6, 0);
	offset+=6;

	/* audit */
	proto_tree_add_item(tree, hf_scsi_osd_audit, tvb, offset, 20, 0);
	offset+=20;

	/* capability discriminator */
	proto_tree_add_item(tree, hf_scsi_osd_capability_discriminator, tvb, offset, 12, 0);
	offset+=12;

	/* object created time */
	proto_tree_add_item(tree, hf_scsi_osd_object_created_time, tvb, offset, 6, 0);
	offset+=6;

	/* object type */
	proto_tree_add_item(tree, hf_scsi_osd_object_type, tvb, offset, 1, 0);
	offset++;

	/* permission bitmask */
/*qqq should be broken out into a helper and have the individual bits dissected */
	proto_tree_add_item(tree, hf_scsi_osd_permission_bitmask, tvb, offset, 5, 0);
	offset+=5;

	/* a reserved byte */
	offset++;

	/* object descriptor type */
	proto_tree_add_item(tree, hf_scsi_osd_object_descriptor_type, tvb, offset, 1, 0);
	offset++;

	/* object descriptor */
	proto_tree_add_item(tree, hf_scsi_osd_object_descriptor, tvb, offset, 24, 0);
	offset+=24;
}



/* 5.2.6 */
static void
dissect_osd_security_parameters(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 40,
		    "Security Parameters");
		tree = proto_item_add_subtree(item, ett_osd_security_parameters);
	}
		
	/* request integrity check value */
	proto_tree_add_item(tree, hf_scsi_osd_ricv, tvb, offset, 20, 0);
	offset+=20;

	/* request nonce */
	proto_tree_add_item(tree, hf_scsi_osd_request_nonce, tvb, offset, 12, 0);
	offset+=12;

	/* data in integrity check value offset */
	proto_tree_add_item(tree, hf_scsi_osd_diicvo, tvb, offset, 4, 0);
	offset+=4;

	/* data out integrity check value offset */
	proto_tree_add_item(tree, hf_scsi_osd_doicvo, tvb, offset, 4, 0);
	offset+=4;
}

static void
dissect_osd_format_osd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 23 reserved bytes */
		offset+=23;

		/* formatted capacity */
		dissect_osd_formatted_capacity(tvb, offset, tree);
		offset+=8;

		/* 8 reserved bytes */
		offset+=8;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(tvb, offset, tree, cdata);

		/* no data out for format osd */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(tvb, offset, tree, cdata);

		/* no data in for format osd */
	}
	
}


static void
dissect_osd_requested_partition_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* request partition id */
	proto_tree_add_item(tree, hf_scsi_osd_requested_partition_id, tvb, offset, 8, 0);
	offset+=8;
}

static void
dissect_osd_partition_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* partition id */
	proto_tree_add_item(tree, hf_scsi_osd_partition_id, tvb, offset, 8, 0);
	offset+=8;
}



static void
dissect_osd_create_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* requested partiton id */
		dissect_osd_requested_partition_id(tvb, offset, tree);
		offset+=8;

		/* 28 reserved bytes */
		offset+=28;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(tvb, offset, tree, cdata);

		/* no data out for create partition */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(tvb, offset, tree, cdata);

		/* no data in for create partition */
	}
	
}

static const value_string scsi_osd_sort_order_vals[] = {
    {0x00,	"Ascending numeric value"},
    {0, NULL},
};
static void
dissect_osd_sortorder(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* sort order */
	proto_tree_add_item(tree, hf_scsi_osd_sortorder, tvb, offset, 1, 0);
	offset++;
}

static void
dissect_osd_list_identifier(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* list identifier */
	proto_tree_add_item(tree, hf_scsi_osd_list_identifier, tvb, offset, 4, 0);
	offset+=4;
}

static void
dissect_osd_allocation_length(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* allocation length */
	proto_tree_add_item(tree, hf_scsi_osd_allocation_length, tvb, offset, 8, 0);
	offset+=8;
}

static void
dissect_osd_initial_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* initial object id */
	proto_tree_add_item(tree, hf_scsi_osd_initial_object_id, tvb, offset, 8, 0);
	offset+=8;
}

static void
dissect_osd_additional_length(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* additional length */
	proto_tree_add_item(tree, hf_scsi_osd_additional_length, tvb, offset, 8, 0);
	offset+=8;
}


static void
dissect_osd_continuation_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* continuation object id */
	proto_tree_add_item(tree, hf_scsi_osd_continuation_object_id, tvb, offset, 8, 0);
	offset+=8;
}

static const true_false_string list_lstchg_tfs = {
	"List has CHANGED since the first List command",
	"List has NOT changed since first command"
};
static const true_false_string list_root_tfs = {
	"Objects are from root and are PARTITION IDs",
	"Objects are from a partition and are USER OBJECTs"
};

static void
dissect_osd_user_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* user object id */
	proto_tree_add_item(tree, hf_scsi_osd_user_object_id, tvb, offset, 8, 0);
	offset+=8;
}

static void
dissect_osd_list(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte / sort order */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		dissect_osd_sortorder(tvb, offset, tree);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(tvb, offset, tree);
		offset+=8;

		/* 8 reserved bytes */
		offset+=8;

		/* list identifier */
		dissect_osd_list_identifier(tvb, offset, tree);
		offset+=4;

		/* allocation length */
		dissect_osd_allocation_length(tvb, offset, tree);
		offset+=8;

		/* initial object id */
		dissect_osd_initial_object_id(tvb, offset, tree);
		offset+=8;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(tvb, offset, tree, cdata);

		/* no data out for LIST */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		guint64 additional_length;
		gboolean is_root;

		/* attribute data in */
		dissect_osd_attribute_data_in(tvb, offset, tree, cdata);

		/* dissection of the LIST DATA-IN */
		/* additional length */
		additional_length=tvb_get_ntoh64(tvb, offset);
		dissect_osd_additional_length(tvb, offset, tree);
		offset+=8;

		/* continuation object id */
		dissect_osd_continuation_object_id(tvb, offset, tree);
		offset+=8;

		/* list identifier */
		dissect_osd_list_identifier(tvb, offset, tree);
		offset+=4;

		/* 3 reserved bytes */
		offset+=3;

		/* LSTCHG and ROOT flags */
		proto_tree_add_item(tree, hf_scsi_osd_list_flags_lstchg, tvb, offset, 1, 0);
		proto_tree_add_item(tree, hf_scsi_osd_list_flags_root, tvb, offset, 1, 0);
		is_root=tvb_get_guint8(tvb, offset)&0x01;
		offset++;


		/* list of user object ids or partition ids */
		while(additional_length > (offset-8)){
			if(is_root){
				dissect_osd_partition_id(tvb, offset, tree);
			} else {
				dissect_osd_user_object_id(tvb, offset, tree);
			}
			offset+=8;
		}
	}
	
}

static void
dissect_osd_requested_user_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* request user object id */
	proto_tree_add_item(tree, hf_scsi_osd_requested_user_object_id, tvb, offset, 8, 0);
	offset+=8;
}

static void
dissect_osd_number_of_user_objects(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* number_of_user_objects */
	proto_tree_add_item(tree, hf_scsi_osd_number_of_user_objects, tvb, offset, 2, 0);
	offset+=2;
}

static void
dissect_osd_create(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(tvb, offset, tree);
		offset+=8;

		/* requested user_object id */
		dissect_osd_requested_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 4 reserved bytes */
		offset+=4;

		/* number of user objects */
		dissect_osd_number_of_user_objects(tvb, offset, tree);
		offset+=2;

		/* 14 reserved bytes */
		offset+=14;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(tvb, offset, tree, cdata);

		/* no data out for create */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(tvb, offset, tree, cdata);

		/* no data in for create */
	}
	
}


/* OSD Service Actions */
#define OSD_FORMAT_OSD		0x8801
#define OSD_CREATE		0x8802
#define OSD_LIST		0x8803
#define OSD_CREATE_PARTITION	0x880b
static const value_string scsi_osd_svcaction_vals[] = {
    {OSD_FORMAT_OSD,		"Format OSD"},
    {OSD_CREATE,		"Create"},
    {OSD_LIST,			"List"},
    {OSD_CREATE_PARTITION,	"Create Partition"},
    {0, NULL},
};

/* OSD Service Action dissectors */
typedef struct _scsi_osd_svcaction_t {
	guint16 svcaction;
	scsi_dissector_t dissector;
} scsi_osd_svcaction_t;
static const scsi_osd_svcaction_t scsi_osd_svcaction[] = {
    {OSD_FORMAT_OSD, 		dissect_osd_format_osd},
    {OSD_CREATE,		dissect_osd_create},
    {OSD_LIST,			dissect_osd_list},
    {OSD_CREATE_PARTITION,	dissect_osd_create_partition},
    {0, NULL},
};

static scsi_dissector_t
find_svcaction_dissector(guint16 svcaction)
{
	const scsi_osd_svcaction_t *sa=scsi_osd_svcaction;

	while(sa&&sa->dissector){
		if(sa->svcaction==svcaction){
			return sa->dissector;
		}
		sa++;
	}
	return NULL;
}



static void
dissect_osd_opcode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len, scsi_task_data_t *cdata)
{
	guint16 svcaction=0;
	scsi_dissector_t dissector;

	if(!tree) {
		return;
	}

	/* dissecting the CDB */
	if (isreq && iscdb) {
		proto_tree_add_item (tree, hf_scsi_osd_control, tvb, offset, 1, 0);
		offset++;

		/* 5 reserved bytes */
		offset+=5;

		proto_tree_add_item (tree, hf_scsi_osd_add_cdblen, tvb, offset, 1, 0);
		offset++;

		svcaction=tvb_get_ntohs(tvb, offset);
		if(cdata && cdata->itlq){
			/* We must store the service action for this itlq
			 * so we can indentify what the data contains
			 */
			if((!pinfo->fd->flags.visited) && (!cdata->itlq->extra_data)){
				scsi_osd_extra_data_t *extra_data;

				extra_data=se_alloc(sizeof(scsi_osd_extra_data_t));
				extra_data->svcaction=svcaction;
				extra_data->gsatype=0;
				cdata->itlq->extra_data=extra_data;
			}
		}
		proto_tree_add_item (tree, hf_scsi_osd_svcaction, tvb, offset, 2, 0);
		offset+=2;


		if(check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
				val_to_str(svcaction, scsi_osd_svcaction_vals, "Unknown OSD Serviceaction"));
		}
		dissector=find_svcaction_dissector(svcaction);
		if(dissector){
			(*dissector)(tvb, pinfo, tree, offset, isreq, iscdb, payload_len, cdata);
		}
		return;
	}

	/* If it was not a CDB, try to find the service action and pass it
	 * off to the service action dissector
	 */
	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		scsi_osd_extra_data_t *extra_data=cdata->itlq->extra_data;
		svcaction=extra_data->svcaction;
	}
	if(check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
			val_to_str(svcaction, scsi_osd_svcaction_vals, "Unknown OSD Serviceaction"));
	}
	if(svcaction){
		proto_item *it;
		it=proto_tree_add_uint_format(tree, hf_scsi_osd_svcaction, tvb, 0, 0, svcaction, "Service Action: 0x%04x", svcaction);
		PROTO_ITEM_SET_GENERATED(it);
	}
	dissector=find_svcaction_dissector(svcaction);
	if(dissector){
		(*dissector)(tvb, pinfo, tree, offset, isreq, iscdb, payload_len, cdata);
	}

}


/* OSD Commands */
const value_string scsi_osd_vals[] = {
    {SCSI_SPC2_INQUIRY			, "Inquiry"},
    {SCSI_SPC2_LOGSELECT		, "Log Select"},
    {SCSI_SPC2_LOGSENSE			, "Log Sense"},
    {SCSI_SPC2_MODESELECT10		, "Mode Select(10)"},
    {SCSI_SPC2_MODESENSE10		, "Mode Sense(10)"},
    {SCSI_SPC2_PERSRESVIN		, "Persistent Reserve In"},
    {SCSI_SPC2_PERSRESVOUT		, "Persistent Reserve Out"},
    {SCSI_SPC2_REPORTLUNS		, "Report LUNs"},
    {SCSI_OSD_OPCODE			, "OSD Command" },
    {0, NULL},
};



scsi_cdb_table_t scsi_osd_table[256] = {
/*OSD 0x00*/{NULL},
/*OSD 0x01*/{NULL},
/*OSD 0x02*/{NULL},
/*OSD 0x03*/{NULL},
/*OSD 0x04*/{NULL},
/*OSD 0x05*/{NULL},
/*OSD 0x06*/{NULL},
/*OSD 0x07*/{NULL},
/*OSD 0x08*/{NULL},
/*OSD 0x09*/{NULL},
/*OSD 0x0a*/{NULL},
/*OSD 0x0b*/{NULL},
/*OSD 0x0c*/{NULL},
/*OSD 0x0d*/{NULL},
/*OSD 0x0e*/{NULL},
/*OSD 0x0f*/{NULL},
/*OSD 0x10*/{NULL},
/*OSD 0x11*/{NULL},
/*OSD 0x12*/{dissect_spc3_inquiry},
/*OSD 0x13*/{NULL},
/*OSD 0x14*/{NULL},
/*OSD 0x15*/{NULL},
/*OSD 0x16*/{NULL},
/*OSD 0x17*/{NULL},
/*OSD 0x18*/{NULL},
/*OSD 0x19*/{NULL},
/*OSD 0x1a*/{NULL},
/*OSD 0x1b*/{NULL},
/*OSD 0x1c*/{NULL},
/*OSD 0x1d*/{NULL},
/*OSD 0x1e*/{NULL},
/*OSD 0x1f*/{NULL},
/*OSD 0x20*/{NULL},
/*OSD 0x21*/{NULL},
/*OSD 0x22*/{NULL},
/*OSD 0x23*/{NULL},
/*OSD 0x24*/{NULL},
/*OSD 0x25*/{NULL},
/*OSD 0x26*/{NULL},
/*OSD 0x27*/{NULL},
/*OSD 0x28*/{NULL},
/*OSD 0x29*/{NULL},
/*OSD 0x2a*/{NULL},
/*OSD 0x2b*/{NULL},
/*OSD 0x2c*/{NULL},
/*OSD 0x2d*/{NULL},
/*OSD 0x2e*/{NULL},
/*OSD 0x2f*/{NULL},
/*OSD 0x30*/{NULL},
/*OSD 0x31*/{NULL},
/*OSD 0x32*/{NULL},
/*OSD 0x33*/{NULL},
/*OSD 0x34*/{NULL},
/*OSD 0x35*/{NULL},
/*OSD 0x36*/{NULL},
/*OSD 0x37*/{NULL},
/*OSD 0x38*/{NULL},
/*OSD 0x39*/{NULL},
/*OSD 0x3a*/{NULL},
/*OSD 0x3b*/{NULL},
/*OSD 0x3c*/{NULL},
/*OSD 0x3d*/{NULL},
/*OSD 0x3e*/{NULL},
/*OSD 0x3f*/{NULL},
/*OSD 0x40*/{NULL},
/*OSD 0x41*/{NULL},
/*OSD 0x42*/{NULL},
/*OSD 0x43*/{NULL},
/*OSD 0x44*/{NULL},
/*OSD 0x45*/{NULL},
/*OSD 0x46*/{NULL},
/*OSD 0x47*/{NULL},
/*OSD 0x48*/{NULL},
/*OSD 0x49*/{NULL},
/*OSD 0x4a*/{NULL},
/*OSD 0x4b*/{NULL},
/*OSD 0x4c*/{dissect_spc3_logselect},
/*OSD 0x4d*/{dissect_spc3_logsense},
/*OSD 0x4e*/{NULL},
/*OSD 0x4f*/{NULL},
/*OSD 0x50*/{NULL},
/*OSD 0x51*/{NULL},
/*OSD 0x52*/{NULL},
/*OSD 0x53*/{NULL},
/*OSD 0x54*/{NULL},
/*OSD 0x55*/{dissect_spc3_modeselect10},
/*OSD 0x56*/{NULL},
/*OSD 0x57*/{NULL},
/*OSD 0x58*/{NULL},
/*OSD 0x59*/{NULL},
/*OSD 0x5a*/{dissect_spc3_modesense10},
/*OSD 0x5b*/{NULL},
/*OSD 0x5c*/{NULL},
/*OSD 0x5d*/{NULL},
/*OSD 0x5e*/{dissect_spc3_persistentreservein},
/*OSD 0x5f*/{dissect_spc3_persistentreserveout},
/*OSD 0x60*/{NULL},
/*OSD 0x61*/{NULL},
/*OSD 0x62*/{NULL},
/*OSD 0x63*/{NULL},
/*OSD 0x64*/{NULL},
/*OSD 0x65*/{NULL},
/*OSD 0x66*/{NULL},
/*OSD 0x67*/{NULL},
/*OSD 0x68*/{NULL},
/*OSD 0x69*/{NULL},
/*OSD 0x6a*/{NULL},
/*OSD 0x6b*/{NULL},
/*OSD 0x6c*/{NULL},
/*OSD 0x6d*/{NULL},
/*OSD 0x6e*/{NULL},
/*OSD 0x6f*/{NULL},
/*OSD 0x70*/{NULL},
/*OSD 0x71*/{NULL},
/*OSD 0x72*/{NULL},
/*OSD 0x73*/{NULL},
/*OSD 0x74*/{NULL},
/*OSD 0x75*/{NULL},
/*OSD 0x76*/{NULL},
/*OSD 0x77*/{NULL},
/*OSD 0x78*/{NULL},
/*OSD 0x79*/{NULL},
/*OSD 0x7a*/{NULL},
/*OSD 0x7b*/{NULL},
/*OSD 0x7c*/{NULL},
/*OSD 0x7d*/{NULL},
/*OSD 0x7e*/{NULL},
/*OSD 0x7f*/{dissect_osd_opcode},
/*OSD 0x80*/{NULL},
/*OSD 0x81*/{NULL},
/*OSD 0x82*/{NULL},
/*OSD 0x83*/{NULL},
/*OSD 0x84*/{NULL},
/*OSD 0x85*/{NULL},
/*OSD 0x86*/{NULL},
/*OSD 0x87*/{NULL},
/*OSD 0x88*/{NULL},
/*OSD 0x89*/{NULL},
/*OSD 0x8a*/{NULL},
/*OSD 0x8b*/{NULL},
/*OSD 0x8c*/{NULL},
/*OSD 0x8d*/{NULL},
/*OSD 0x8e*/{NULL},
/*OSD 0x8f*/{NULL},
/*OSD 0x90*/{NULL},
/*OSD 0x91*/{NULL},
/*OSD 0x92*/{NULL},
/*OSD 0x93*/{NULL},
/*OSD 0x94*/{NULL},
/*OSD 0x95*/{NULL},
/*OSD 0x96*/{NULL},
/*OSD 0x97*/{NULL},
/*OSD 0x98*/{NULL},
/*OSD 0x99*/{NULL},
/*OSD 0x9a*/{NULL},
/*OSD 0x9b*/{NULL},
/*OSD 0x9c*/{NULL},
/*OSD 0x9d*/{NULL},
/*OSD 0x9e*/{NULL},
/*OSD 0x9f*/{NULL},
/*OSD 0xa0*/{dissect_spc3_reportluns},
/*OSD 0xa1*/{NULL},
/*OSD 0xa2*/{NULL},
/*OSD 0xa3*/{NULL},
/*OSD 0xa4*/{NULL},
/*OSD 0xa5*/{NULL},
/*OSD 0xa6*/{NULL},
/*OSD 0xa7*/{NULL},
/*OSD 0xa8*/{NULL},
/*OSD 0xa9*/{NULL},
/*OSD 0xaa*/{NULL},
/*OSD 0xab*/{NULL},
/*OSD 0xac*/{NULL},
/*OSD 0xad*/{NULL},
/*OSD 0xae*/{NULL},
/*OSD 0xaf*/{NULL},
/*OSD 0xb0*/{NULL},
/*OSD 0xb1*/{NULL},
/*OSD 0xb2*/{NULL},
/*OSD 0xb3*/{NULL},
/*OSD 0xb4*/{NULL},
/*OSD 0xb5*/{NULL},
/*OSD 0xb6*/{NULL},
/*OSD 0xb7*/{NULL},
/*OSD 0xb8*/{NULL},
/*OSD 0xb9*/{NULL},
/*OSD 0xba*/{NULL},
/*OSD 0xbb*/{NULL},
/*OSD 0xbc*/{NULL},
/*OSD 0xbd*/{NULL},
/*OSD 0xbe*/{NULL},
/*OSD 0xbf*/{NULL},
/*OSD 0xc0*/{NULL},
/*OSD 0xc1*/{NULL},
/*OSD 0xc2*/{NULL},
/*OSD 0xc3*/{NULL},
/*OSD 0xc4*/{NULL},
/*OSD 0xc5*/{NULL},
/*OSD 0xc6*/{NULL},
/*OSD 0xc7*/{NULL},
/*OSD 0xc8*/{NULL},
/*OSD 0xc9*/{NULL},
/*OSD 0xca*/{NULL},
/*OSD 0xcb*/{NULL},
/*OSD 0xcc*/{NULL},
/*OSD 0xcd*/{NULL},
/*OSD 0xce*/{NULL},
/*OSD 0xcf*/{NULL},
/*OSD 0xd0*/{NULL},
/*OSD 0xd1*/{NULL},
/*OSD 0xd2*/{NULL},
/*OSD 0xd3*/{NULL},
/*OSD 0xd4*/{NULL},
/*OSD 0xd5*/{NULL},
/*OSD 0xd6*/{NULL},
/*OSD 0xd7*/{NULL},
/*OSD 0xd8*/{NULL},
/*OSD 0xd9*/{NULL},
/*OSD 0xda*/{NULL},
/*OSD 0xdb*/{NULL},
/*OSD 0xdc*/{NULL},
/*OSD 0xdd*/{NULL},
/*OSD 0xde*/{NULL},
/*OSD 0xdf*/{NULL},
/*OSD 0xe0*/{NULL},
/*OSD 0xe1*/{NULL},
/*OSD 0xe2*/{NULL},
/*OSD 0xe3*/{NULL},
/*OSD 0xe4*/{NULL},
/*OSD 0xe5*/{NULL},
/*OSD 0xe6*/{NULL},
/*OSD 0xe7*/{NULL},
/*OSD 0xe8*/{NULL},
/*OSD 0xe9*/{NULL},
/*OSD 0xea*/{NULL},
/*OSD 0xeb*/{NULL},
/*OSD 0xec*/{NULL},
/*OSD 0xed*/{NULL},
/*OSD 0xee*/{NULL},
/*OSD 0xef*/{NULL},
/*OSD 0xf0*/{NULL},
/*OSD 0xf1*/{NULL},
/*OSD 0xf2*/{NULL},
/*OSD 0xf3*/{NULL},
/*OSD 0xf4*/{NULL},
/*OSD 0xf5*/{NULL},
/*OSD 0xf6*/{NULL},
/*OSD 0xf7*/{NULL},
/*OSD 0xf8*/{NULL},
/*OSD 0xf9*/{NULL},
/*OSD 0xfa*/{NULL},
/*OSD 0xfb*/{NULL},
/*OSD 0xfc*/{NULL},
/*OSD 0xfd*/{NULL},
/*OSD 0xfe*/{NULL},
/*OSD 0xff*/{NULL}
};




void
proto_register_scsi_osd(void)
{
	static hf_register_info hf[] = {
        { &hf_scsi_osd_opcode,
          {"OSD Opcode", "scsi.osd.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_osd_vals), 0x0, "", HFILL}},
        { &hf_scsi_osd_control,
          {"Control", "scsi.osd.cdb.control", FT_UINT8, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_add_cdblen,
          {"Additional CDB Length", "scsi.osd.addcdblen", FT_UINT8, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_svcaction,
          {"Service Action", "scsi.osd.svcaction", FT_UINT16, BASE_HEX,
           VALS(scsi_osd_svcaction_vals), 0x0, "", HFILL}},
        { &hf_scsi_osd_option,
          {"Option", "scsi.osd.option", FT_UINT8, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_option_dpo,
          {"DPO", "scsi.osd.option.dpo", FT_BOOLEAN, 8,
           TFS(&option_dpo_tfs), 0x10, "", HFILL}},
        { &hf_scsi_osd_option_fua,
          {"FUA", "scsi.osd.option.fua", FT_BOOLEAN, 8,
           TFS(&option_fua_tfs), 0x08, "", HFILL}},
        { &hf_scsi_osd_getsetattrib,
          {"GET/SET CDBFMT", "scsi.osd.getset", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_getsetattrib_vals), 0x30, "", HFILL}},
        { &hf_scsi_osd_timestamps_control,
          {"Timestamps Control", "scsi.osd.timestamps_control", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_timestamps_control_vals), 0x0, "", HFILL}},
        { &hf_scsi_osd_formatted_capacity,
          {"Formatted Capacity", "scsi.osd.formatted_capacity", FT_UINT64, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_get_attributes_page,
          {"Get Attributes Page", "scsi.osd.get_attributes_page", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_get_attributes_list_length,
          {"Get Attributes List Length", "scsi.osd.get_attributes_list_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_get_attributes_list_offset,
          {"Get Attributes List Offset", "scsi.osd.get_attributes_list_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_set_attributes_list_length,
          {"Set Attributes List Length", "scsi.osd.set_attributes_list_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_set_attributes_list_offset,
          {"Set Attributes List Offset", "scsi.osd.set_attributes_list_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_get_attributes_allocation_length,
          {"Get Attributes Allocation Length", "scsi.osd.get_attributes_allocation_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_retreived_attributes_offset,
          {"Retreived Attributes Offset", "scsi.osd.retreived_attributes_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_set_attributes_page,
          {"Set Attributes Page", "scsi.osd.set_attributes_page", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_set_attribute_length,
          {"Set Attribute Length", "scsi.osd.set_attribute_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_set_attribute_number,
          {"Set Attribute Number", "scsi.osd.set_attribute_number", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_set_attributes_offset,
          {"Set Attributes Offset", "scsi.osd.set_attributes_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_osd_capability_format,
          {"Capability Format", "scsi.osd.capability_format", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_capability_format_vals), 0x0f, "", HFILL}},
        { &hf_scsi_osd_key_version,
          {"Key Version", "scsi.osd.key_version", FT_UINT8, BASE_HEX,
           NULL, 0xf0, "", HFILL}},
        { &hf_scsi_osd_icva,
          {"Integrity Check Value Algorithm", "scsi.osd.icva", FT_UINT8, BASE_HEX,
           NULL, 0x0f, "", HFILL}},
        { &hf_scsi_osd_security_method,
          {"Security Method", "scsi.osd.security_method", FT_UINT8, BASE_HEX,
           NULL, 0x0f, "", HFILL}},
        { &hf_scsi_osd_capability_expiration_time,
          {"Capability Expiration Time", "scsi.osd.capability_expiration_time", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_audit,
          {"Audit", "scsi.osd.audit", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_capability_discriminator,
          {"Capability Discriminator", "scsi.osd.capability_descriminator", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_object_created_time,
          {"Object Created Time", "scsi.osd.object_created_time", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_object_type,
          {"Object Type", "scsi.osd.object_type", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_object_type_vals), 0, "", HFILL}},
        { &hf_scsi_osd_permission_bitmask,
          {"Permission Bitmask", "scsi.osd.permission_bitmask", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_object_descriptor_type,
          {"Object Descriptor Type", "scsi.osd.object_descriptor_type", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_object_descriptor_type_vals), 0xf0, "", HFILL}},
        { &hf_scsi_osd_object_descriptor,
          {"Object Descriptor", "scsi.osd.object_descriptor", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_ricv,
          {"Request Integrity Check value", "scsi.osd.ricv", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_request_nonce,
          {"Request Nonce", "scsi.osd.request_nonce", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_diicvo,
          {"Data-In Integrity Check Value Offset", "scsi.osd.diicvo", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_doicvo,
          {"Data-Out Integrity Check Value Offset", "scsi.osd.doicvo", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_requested_partition_id,
          {"Requested Partition Id", "scsi.osd.requested_partition_id", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_sortorder,
          {"Sort Order", "scsi.osd.sort_order", FT_UINT8, BASE_DEC,
           VALS(scsi_osd_sort_order_vals), 0x0f, "", HFILL}},
        { &hf_scsi_osd_partition_id,
          {"Partition Id", "scsi.osd.partition_id", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_list_identifier,
          {"List Identifier", "scsi.osd.list_identifier", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_allocation_length,
          {"Allocation Length", "scsi.osd.allocation_length", FT_UINT64, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_initial_object_id,
          {"Initial Object Id", "scsi.osd.initial_object_id", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
	{ &hf_scsi_osd_additional_length,
          {"Additional Length", "scsi.osd.additional_length", FT_UINT64, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_continuation_object_id,
          {"Continuation Object Id", "scsi.osd.continuation_object_id", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_user_object_id,
          {"User Object Id", "scsi.osd.user_object_id", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_osd_list_flags_lstchg,
          {"LSTCHG", "scsi.osd.list.lstchg", FT_BOOLEAN, 8,
           TFS(&list_lstchg_tfs), 0x02, "", HFILL}},
        { &hf_scsi_osd_list_flags_root,
          {"ROOT", "scsi.osd.list.root", FT_BOOLEAN, 8,
           TFS(&list_root_tfs), 0x01, "", HFILL}},
        { &hf_scsi_osd_requested_user_object_id,
          {"Requested User Object Id", "scsi.osd.requested_user_object_id", FT_BYTES, BASE_HEX,
           NULL, 0, "", HFILL}},
	{ &hf_scsi_osd_number_of_user_objects,
          {"Number Of User Objects", "scsi.osd.number_of_user_objects", FT_UINT16, BASE_DEC,
           NULL, 0, "", HFILL}},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_osd_option,
		&ett_osd_attribute_parameters,
		&ett_osd_capability,
		&ett_osd_security_parameters,
	};

	/* Register the protocol name and description */
	proto_scsi_osd = proto_register_protocol("SCSI_OSD", "SCSI_OSD", "scsi_osd");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_scsi_osd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_scsi_osd(void)
{
}

