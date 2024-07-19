/* packet-tnef.c
 * Routines for Transport-Neutral Encapsulation Format (TNEF) packet disassembly
 *
 * Copyright (c) 2007 by Graeme Lunt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include <wiretap/tnef.h>

#include "packet-dcerpc.h"
#include "packet-dcerpc-nspi.h"
#include "packet-ber.h"

#define PNAME  "Transport-Neutral Encapsulation Format"
#define PSNAME "TNEF"
#define PFNAME "tnef"

#define ATP_TRIPLES   (0x0000)
#define ATP_STRING    (0x0001)
#define ATP_TEXT      (0x0002)
#define ATP_DATE      (0x0003)
#define ATP_SHORT     (0x0004)
#define ATP_LONG      (0x0005)
#define ATP_BYTE      (0x0006)
#define ATP_WORD      (0x0007)
#define ATP_DWORD     (0x0008)
#define ATP_MAX       (0x0009)

#define ATT_OWNER                     (0x00060000) /* handled */
#define ATT_SENT_FOR                  (0x00060001) /* handled */
#define ATT_DELEGATE                  (0x00060002)
#define ATT_DATE_START                (0x00030006) /* handled */
#define ATT_DATE_END                  (0x00030007) /* handled */
#define ATT_AID_OWNER                 (0x00040008)
#define ATT_REQUEST_RES               (0x00040009)

#define ATT_FROM                      (0x00008000)
#define ATT_SUBJECT                   (0x00018004)
#define ATT_DATE_SENT                 (0x00038005) /* handled */
#define ATT_DATE_RECD                 (0x00038006) /* handled */
#define ATT_MESSAGE_STATUS            (0x00068007)
#define ATT_MESSAGE_CLASS             (0x00078008) /* handled */
#define ATT_MESSAGE_ID                (0x00018009)
#define ATT_PARENT_ID                 (0x0001800A) /* handled */
#define ATT_CONVERSATION_ID           (0x0001800B) /* handled */
#define ATT_BODY                      (0x0002800C)
#define ATT_PRIORITY                  (0x0004800D) /* handled */
#define ATT_ATTACH_DATA               (0x0006800F)
#define ATT_ATTACH_TITLE              (0x00018010) /* handled */
#define ATT_ATTACH_META_FILE          (0x00068011)
#define ATT_ATTACH_CREATE_DATE        (0x00038012) /* handled */
#define ATT_ATTACH_MODIFY_DATE        (0x00038013) /* handled */
#define ATT_DATE_MODIFIED             (0x00038020) /* handled */

#define ATT_ATTACH_TRANSPORT_FILENAME (0x00069001)
#define ATT_ATTACH_REND_DATA          (0x00069002)
#define ATT_MAPI_PROPS                (0x00069003) /* handled */
#define ATT_RECIP_TABLE               (0x00069004)
#define ATT_ATTACHMENT                (0x00069005)
#define ATT_TNEF_VERSION              (0x00089006) /* handled */
#define ATT_OEM_CODEPAGE              (0x00069007) /* handled */
#define ATT_ORIGINAL_MESSAGE_CLASS    (0x00079008) /* handled */

void proto_register_tnef(void);
void proto_reg_handoff_tnef(void);

static int proto_tnef;

static int hf_tnef_signature;
static int hf_tnef_key;
static int hf_tnef_attribute;
static int hf_tnef_attribute_lvl;
static int hf_tnef_attribute_tag;
static int hf_tnef_attribute_tag_type;
static int hf_tnef_attribute_tag_id;
static int hf_tnef_attribute_length;
static int hf_tnef_attribute_value;
static int hf_tnef_attribute_string;
static int hf_tnef_attribute_date;
static int hf_tnef_attribute_display_name;
static int hf_tnef_attribute_email_address;
static int hf_tnef_attribute_checksum;
static int hf_tnef_mapi_props;
static int hf_tnef_oem_codepage;
static int hf_tnef_version;
static int hf_tnef_message_class;
static int hf_tnef_original_message_class;
static int hf_tnef_priority;
static int hf_tnef_mapi_props_count;

static int hf_tnef_property;
static int hf_tnef_property_tag;
static int hf_tnef_property_tag_type;
static int hf_tnef_property_tag_id;
static int hf_tnef_property_tag_set;
static int hf_tnef_property_tag_kind;
static int hf_tnef_property_tag_name_id;
static int hf_tnef_property_tag_name_length;
static int hf_tnef_property_tag_name_string;
static int hf_tnef_property_padding;
static int hf_tnef_padding;

static int hf_tnef_values_count;
static int hf_tnef_value_length;

static int hf_tnef_attribute_date_year;
static int hf_tnef_attribute_date_month;
static int hf_tnef_attribute_date_day;
static int hf_tnef_attribute_date_hour;
static int hf_tnef_attribute_date_minute;
static int hf_tnef_attribute_date_second;
static int hf_tnef_attribute_date_day_of_week;

static int hf_tnef_PropValue_i;
static int hf_tnef_PropValue_l;
static int hf_tnef_PropValue_b;
static int hf_tnef_PropValue_lpszA;
static int hf_tnef_PropValue_lpszW;
static int hf_tnef_PropValue_lpguid;
static int hf_tnef_PropValue_bin;
static int hf_tnef_PropValue_ft;
static int hf_tnef_PropValue_err;
static int hf_tnef_PropValue_MVi;
static int hf_tnef_PropValue_MVl;
static int hf_tnef_PropValue_MVszA;
static int hf_tnef_PropValue_MVbin;
static int hf_tnef_PropValue_MVguid;
static int hf_tnef_PropValue_MVszW;
static int hf_tnef_PropValue_MVft;
static int hf_tnef_PropValue_null;
static int hf_tnef_PropValue_object;

static int ett_tnef;
static int ett_tnef_attribute;
static int ett_tnef_attribute_tag;
static int ett_tnef_mapi_props;
static int ett_tnef_property;
static int ett_tnef_property_tag;
static int ett_tnef_counted_items;
static int ett_tnef_attribute_date;
static int ett_tnef_attribute_address;

static expert_field ei_tnef_expect_single_item;
static expert_field ei_tnef_incorrect_signature;

static dissector_handle_t tnef_handle;

static const value_string tnef_Lvl_vals[] = {
   {   1, "LVL-MESSAGE" },
   {   2, "LVL-ATTACHMENT" },
   { 0, NULL }
};

static const value_string tnef_Priority_vals[] = {
   {   1, "Low" },
   {   2, "High" },
   {   3, "Normal" },
   { 0, NULL }
};

static const value_string tnef_Types_vals[] = {
  {  ATP_TRIPLES, "Triples" },
  {  ATP_STRING,  "String"},
  {  ATP_TEXT,    "Text" },
  {  ATP_DATE,    "Date"},
  {  ATP_SHORT,   "Short"},
  {  ATP_LONG,    "Long"},
  {  ATP_BYTE,    "Byte"},
  {  ATP_WORD,    "Word"},
  {  ATP_DWORD,   "DWord"},
  {  ATP_MAX,     "Max"},
  { 0, NULL }
};

static const value_string weekday_vals[] = {
  {0, "Sunday"},
  {1, "Monday"},
  {2, "Tuesday"},
  {3, "Wednesday"},
  {4, "Thursday"},
  {5, "Friday"},
  {6, "Saturday"},
  {0, NULL}
};

static const value_string tnef_Attribute_vals[] = {
  {  ATT_OWNER,                     "ATT_OWNER" },
  {  ATT_SENT_FOR,                  "ATT_SENT_FOR" },
  {  ATT_DELEGATE,                  "ATT_DELEGATE" },
  {  ATT_OWNER,                     "ATT_OWNER" },
  {  ATT_DATE_START,                "ATT_DATE_START" },
  {  ATT_DATE_END,                  "ATT_DATE_END" },
  {  ATT_AID_OWNER,                 "ATT_AID_OWNER" },
  {  ATT_REQUEST_RES,               "ATT_REQUEST_RES" },
  {  ATT_FROM,                      "ATT_FROM" },
  {  ATT_SUBJECT,                   "ATT_SUBJECT" },
  {  ATT_DATE_SENT,                 "ATT_DATE_SENT" },
  {  ATT_DATE_RECD,                 "ATT_DATE_RECD" },
  {  ATT_MESSAGE_STATUS,            "ATT_MESSAGE_STATUS" },
  {  ATT_MESSAGE_CLASS,             "ATT_MESSAGE_CLASS" },
  {  ATT_MESSAGE_ID,                "ATT_MESSAGE_ID" },
  {  ATT_PARENT_ID,                 "ATT_PARENT_ID" },
  {  ATT_CONVERSATION_ID,           "ATT_CONVERSATION_ID" },
  {  ATT_BODY,                      "ATT_BODY" },
  {  ATT_PRIORITY,                  "ATT_PRIORITY" },
  {  ATT_ATTACH_DATA,               "ATT_ATTACH_DATA" },
  {  ATT_ATTACH_TITLE,              "ATT_ATTACH_TITLE" },
  {  ATT_ATTACH_META_FILE,          "ATT_ATTACH_META_FILE" },
  {  ATT_ATTACH_CREATE_DATE,        "ATT_ATTACH_CREATE_DATE" },
  {  ATT_ATTACH_MODIFY_DATE,        "ATT_ATTACH_MODIFY_DATE" },
  {  ATT_DATE_MODIFIED,             "ATT_DATE_MODIFIED" },
  {  ATT_ATTACH_TRANSPORT_FILENAME, "ATT_ATTACH_TRANSPORT_FILENAME" },
  {  ATT_ATTACH_REND_DATA,          "ATT_ATTACH_REND_DATA" },
  {  ATT_MAPI_PROPS,                "ATT_MAPI_PROPS" },
  {  ATT_RECIP_TABLE,               "ATT_RECIP_TABLE" },
  {  ATT_ATTACHMENT,                "ATT_ATTACHMENT" },
  {  ATT_TNEF_VERSION,              "ATT_TNEF_VERSION" },
  {  ATT_OEM_CODEPAGE,              "ATT_OEM_CODEPAGE" },
  {  ATT_ORIGINAL_MESSAGE_CLASS,    "ATT_ORIGINAL_MESSAGE_CLASS" },
  { 0, NULL }
};

static int dissect_counted_values(tvbuff_t *tvb, int offset, int hf_id,  packet_info *pinfo, proto_tree *tree, bool single, unsigned encoding)
{
  proto_item *item;
  uint32_t    length, count, i;

  count = tvb_get_letohl(tvb, offset);
  proto_tree_add_item(tree, hf_tnef_values_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  if(count > 1) {
    if(single) {
      item = proto_tree_add_expert_format(tree, pinfo, &ei_tnef_expect_single_item, tvb, offset, 4,
                                          "Expecting a single item but found %d", count);
      tree = proto_item_add_subtree(item, ett_tnef_counted_items);
    }
  }

  offset += 4;

  for(i = 0; i < count; i++) {

    length = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_tnef_value_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_id, tvb, offset, length, encoding);
    offset += length;

    /* XXX: may be padding ? */

  }

  return offset;
}

static int dissect_counted_address(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  uint16_t length;

  length = tvb_get_letohs(tvb, offset);
  proto_tree_add_item(tree, hf_tnef_value_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_tnef_attribute_display_name, tvb, offset, length, ENC_ASCII);
  offset += length;

  length = tvb_get_letohs(tvb, offset);
  proto_tree_add_item(tree, hf_tnef_value_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_tnef_attribute_email_address, tvb, offset, length, ENC_ASCII);
  offset += length;

  return offset;
}


static void dissect_DTR(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  int offset;

  offset = 0;

  proto_tree_add_item(tree, hf_tnef_attribute_date_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset +=2;

  proto_tree_add_item(tree, hf_tnef_attribute_date_month, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset +=2;

  proto_tree_add_item(tree, hf_tnef_attribute_date_day, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset +=2;

  proto_tree_add_item(tree, hf_tnef_attribute_date_hour, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset +=2;

  proto_tree_add_item(tree, hf_tnef_attribute_date_minute, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset +=2;

  proto_tree_add_item(tree, hf_tnef_attribute_date_second, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset +=2;

  proto_tree_add_item(tree, hf_tnef_attribute_date_day_of_week, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  /*offset +=2;*/
}


static void dissect_mapiprops(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned oem_encoding)
{
  proto_item *item, *prop_item;
  proto_tree *prop_tree, *tag_tree;
  uint32_t    /*count,*/ tag, tag_kind, tag_length;
  uint16_t    padding;
  int         offset, start_offset;

  uint8_t     drep[] = {0x10 /* LE */, /* DCE_RPC_DREP_FP_IEEE */ 0 };
  static dcerpc_info di;
  static dcerpc_call_value call_data;

  offset = 0;

  di.conformant_run = 0;
  /* we need di->call_data->flags.NDR64 == 0 */
  di.call_data = &call_data;
  di.dcerpc_procedure_name = "";

  /* first the count */
  proto_tree_add_item(tree, hf_tnef_mapi_props_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  /*count = tvb_get_letohl(tvb, offset);*/

  offset += 4;

  while(tvb_reported_length_remaining(tvb, offset) > 0 ) {

    start_offset = offset;

    /* get the property tag */

    prop_item = proto_tree_add_item(tree, hf_tnef_property, tvb, offset, -1, ENC_NA);
    prop_tree = proto_item_add_subtree(prop_item, ett_tnef_property);

    item = proto_tree_add_item(prop_tree, hf_tnef_property_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    tag_tree = proto_item_add_subtree(item, ett_tnef_property_tag);

    /* add a nice name to the property */
    tag = tvb_get_letohl(tvb, offset);
    proto_item_append_text(prop_item, " %s", val_to_str(tag, nspi_MAPITAGS_vals, "Unknown tag (0x%08lx)"));

    proto_tree_add_item(tag_tree, hf_tnef_property_tag_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tag_tree, hf_tnef_property_tag_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if(tag & 0x80000000) {
      const uint8_t* name_string = NULL;

      /* it is a named property */
      proto_tree_add_item(tag_tree, hf_tnef_property_tag_set, tvb, offset, 16, ENC_LITTLE_ENDIAN);
      offset += 16;

      tag_kind = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(tag_tree, hf_tnef_property_tag_kind, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      offset += 4;

      if(tag_kind == 0) {
        proto_tree_add_item(tag_tree, hf_tnef_property_tag_name_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
      } else {
        tag_length = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(tag_tree, hf_tnef_property_tag_name_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item_ret_string(tag_tree, hf_tnef_property_tag_name_string, tvb, offset, tag_length,
          ENC_UTF_16|ENC_LITTLE_ENDIAN, pinfo->pool, &name_string);
        offset += tag_length;

        if((padding = (4 - tag_length % 4)) != 4) {
          proto_tree_add_item(tag_tree, hf_tnef_property_padding, tvb, offset, padding, ENC_NA);
          offset += padding;
        }
      }
      proto_item_append_text(prop_item, " [Named Property");
      if (name_string)
        proto_item_append_text(prop_item, ": %s", name_string);
      proto_item_append_text(prop_item, "]");
    }

    switch(tag) {
      /* handle any specific tags here */
    default:
      /* otherwise just use the type */
      switch(tag & 0x0000ffff) {
      case PT_I2:
        offset = PIDL_dissect_uint16(tvb, offset, pinfo, prop_tree, &di, drep, hf_tnef_PropValue_i, 0);
        break;
      case PT_LONG:
        offset = PIDL_dissect_uint32(tvb, offset, pinfo, prop_tree, &di, drep, hf_tnef_PropValue_l, 0);
        break;
      case PT_BOOLEAN:
        offset = PIDL_dissect_uint16(tvb, offset, pinfo, prop_tree, &di, drep, hf_tnef_PropValue_b, 0);
        break;
      case PT_STRING8:
        offset = dissect_counted_values(tvb, offset, hf_tnef_PropValue_lpszA, pinfo, prop_tree, true, oem_encoding);
        break;
      case PT_BINARY:
        offset = dissect_counted_values(tvb, offset, hf_tnef_PropValue_bin, pinfo, prop_tree, true, ENC_NA);
        break;
      case PT_UNICODE:
        offset = dissect_counted_values (tvb, offset, hf_tnef_PropValue_lpszW, pinfo, prop_tree, true, ENC_UTF_16|ENC_LITTLE_ENDIAN);
        break;
      case PT_CLSID:
        offset = nspi_dissect_struct_MAPIUID(tvb, offset, pinfo, prop_tree, &di, drep, hf_tnef_PropValue_lpguid, 0);
        break;
      case PT_SYSTIME:
        offset = nspi_dissect_struct_FILETIME(tvb,offset,pinfo,prop_tree,&di,drep,hf_tnef_PropValue_ft,0);
        break;
      case PT_ERROR:
        offset = nspi_dissect_enum_MAPISTATUS(tvb, offset, pinfo, prop_tree, &di, drep, hf_tnef_PropValue_err, 0);
        break;
      case PT_MV_I2:
        offset = nspi_dissect_struct_SShortArray(tvb,offset,pinfo,prop_tree,&di,drep,hf_tnef_PropValue_MVi,0);
        break;
      case PT_MV_LONG:
        offset = nspi_dissect_struct_MV_LONG_STRUCT(tvb,offset,pinfo,prop_tree,&di,drep,hf_tnef_PropValue_MVl,0);
        break;
      case PT_MV_STRING8:
        offset = nspi_dissect_struct_SLPSTRArray(tvb,offset,pinfo,prop_tree,&di,drep,hf_tnef_PropValue_MVszA,0);
        break;
      case PT_MV_BINARY:
        offset = nspi_dissect_struct_SBinaryArray(tvb,offset,pinfo,prop_tree,&di,drep,hf_tnef_PropValue_MVbin,0);
        break;
      case PT_MV_CLSID:
        offset = nspi_dissect_struct_SGuidArray(tvb,offset,pinfo,prop_tree,&di,drep,hf_tnef_PropValue_MVguid,0);
        break;
      case PT_MV_UNICODE:
        offset = nspi_dissect_struct_MV_UNICODE_STRUCT(tvb,offset,pinfo,prop_tree,&di,drep,hf_tnef_PropValue_MVszW,0);
        break;
      case PT_MV_SYSTIME:
        offset = nspi_dissect_struct_SDateTimeArray(tvb,offset,pinfo,prop_tree,&di,drep,hf_tnef_PropValue_MVft,0);
        break;
      case PT_NULL:
        offset = PIDL_dissect_uint32(tvb, offset, pinfo, prop_tree, &di, drep, hf_tnef_PropValue_null, 0);
        break;
      case PT_OBJECT:
        offset = PIDL_dissect_uint32(tvb, offset, pinfo, prop_tree, &di, drep, hf_tnef_PropValue_object, 0);
        break;
      }
    }

    /* we may need to pad to a 4-byte boundary */
    if((padding = (4 - (offset - start_offset) % 4)) != 4) {

      /* we need to pad */
      proto_tree_add_item(prop_tree, hf_tnef_property_padding, tvb, offset, padding, ENC_NA);

      offset += padding;
    }

    proto_item_set_len(prop_item, offset - start_offset);
  }
}


static int dissect_tnef(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *attr_item, *item;
  proto_tree *attr_tree, *tag_tree, *props_tree, *addr_tree, *date_tree;
  uint32_t    tag, length, signature;
  int         offset, start_offset;
  tvbuff_t   *next_tvb;
  uint64_t    oem_code_page;
  unsigned    oem_encoding = ENC_ASCII|ENC_NA;

  if(tree){
    item = proto_tree_add_item(tree, proto_tnef, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_tnef);
  }

  offset = 0;

  /* first the signature */
  signature = tvb_get_letohl(tvb, offset);
  item = proto_tree_add_item(tree, hf_tnef_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* check the signature */
  if(signature != TNEF_SIGNATURE) {

    expert_add_info_format(pinfo, item, &ei_tnef_incorrect_signature,
               " [Incorrect, should be 0x%x. No further dissection possible. Check any Content-Transfer-Encoding has been removed.]", TNEF_SIGNATURE);
    return offset;

  } else {

    proto_item_append_text(item, " [Correct]");

  }

  proto_tree_add_item(tree, hf_tnef_key, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  while(tvb_reported_length_remaining(tvb, offset) > 9 ) { /* there must be at least a level (1), tag (4) and length (4) to be valid */

    start_offset = offset;

    attr_item = proto_tree_add_item(tree, hf_tnef_attribute, tvb, offset, -1, ENC_NA);
    attr_tree = proto_item_add_subtree(attr_item, ett_tnef_attribute);

    proto_tree_add_item(attr_tree, hf_tnef_attribute_lvl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    item = proto_tree_add_item(attr_tree, hf_tnef_attribute_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    tag_tree = proto_item_add_subtree(item, ett_tnef_attribute_tag);

    /* add a nice name to the property */
    tag = tvb_get_letohl(tvb, offset);
    proto_item_append_text(attr_item, " %s", val_to_str(tag, tnef_Attribute_vals, "Unknown tag (0x%08lx)"));

    proto_tree_add_item(tag_tree, hf_tnef_attribute_tag_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tag_tree, hf_tnef_attribute_tag_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    /* remember the type for the value dissection */
    offset += 2;

    length = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(attr_tree, hf_tnef_attribute_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    switch(tag) {
    case ATT_OEM_CODEPAGE:
      proto_tree_add_item_ret_uint64(attr_tree, hf_tnef_oem_codepage, tvb, offset, length, ENC_LITTLE_ENDIAN, &oem_code_page);
      switch (oem_code_page) {

      case 1250:
        oem_encoding = ENC_WINDOWS_1250|ENC_NA;
        break;

      case 1251:
        oem_encoding = ENC_WINDOWS_1251|ENC_NA;
        break;

      case 1252:
        oem_encoding = ENC_WINDOWS_1252|ENC_NA;
        break;

      default:
        oem_encoding = ENC_ASCII|ENC_NA; /* XXX - support more code pages */
        break;
      }
      break;
    case ATT_TNEF_VERSION:
      proto_tree_add_item(attr_tree, hf_tnef_version, tvb, offset, length, ENC_LITTLE_ENDIAN);
      break;
    case ATT_MESSAGE_CLASS:
      proto_tree_add_item(attr_tree, hf_tnef_message_class, tvb, offset, length, ENC_ASCII);
      break;
    case ATT_ORIGINAL_MESSAGE_CLASS:
      proto_tree_add_item(attr_tree, hf_tnef_original_message_class, tvb, offset, length, ENC_ASCII);
      break;
    case ATT_MAPI_PROPS:
      item = proto_tree_add_item(attr_tree, hf_tnef_mapi_props, tvb, offset, length, ENC_NA);
      props_tree = proto_item_add_subtree(item, ett_tnef_mapi_props);

      next_tvb = tvb_new_subset_length(tvb, offset, length);

      dissect_mapiprops(next_tvb, pinfo, props_tree, oem_encoding);

      break;
    case ATT_OWNER:
    case ATT_SENT_FOR:
      addr_tree = proto_item_add_subtree(item, ett_tnef_attribute_address);

      (void)dissect_counted_address(tvb, offset, pinfo, addr_tree);

      break;
    case ATT_PRIORITY:
      proto_tree_add_item(attr_tree, hf_tnef_priority, tvb, offset, length, ENC_LITTLE_ENDIAN);
      break;
    default:
      /* just do it on the type */
      switch((tag >> 16) & 0xffff) {
      case ATP_DATE:
        item = proto_tree_add_item(attr_tree, hf_tnef_attribute_date, tvb, offset, length, ENC_NA);
        date_tree = proto_item_add_subtree(item, ett_tnef_attribute_date);

        next_tvb = tvb_new_subset_length(tvb, offset, length);

        dissect_DTR(next_tvb, pinfo, date_tree);

        break;
      case ATP_STRING:
        {
        const uint8_t* atp;
        proto_tree_add_item_ret_string(attr_tree, hf_tnef_attribute_string, tvb, offset, length, oem_encoding, pinfo->pool, &atp);
        proto_item_append_text(attr_item, " %s", atp);
        }
        break;
      default:
        proto_tree_add_item(attr_tree, hf_tnef_attribute_value, tvb, offset, length, ENC_NA);
        break;
      }
    }

    /* check for overflow */
    if (offset + length > (uint32_t)offset) {
      offset += length;
    }

    proto_tree_add_checksum(attr_tree, tvb, offset, hf_tnef_attribute_checksum, -1, NULL, pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    offset += 2;

    proto_item_set_len(attr_item, offset - start_offset);
  }

  /* there may be some padding */
  if(tvb_reported_length_remaining(tvb, offset)) /* XXX: Not sure if they is really padding or not */
    proto_tree_add_item(tree, hf_tnef_padding, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);

  return tvb_captured_length(tvb);
}

static int dissect_tnef_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  col_set_str(pinfo->cinfo, COL_DEF_SRC, PSNAME " encoded file");

  col_append_str(pinfo->cinfo, COL_INFO, PNAME);

  dissect_tnef(tvb, pinfo, tree, NULL);
  return tvb_captured_length(tvb);
}

/* Register all the bits needed by the filtering engine */

void
proto_register_tnef(void)
{
  static hf_register_info hf[] = {
    { &hf_tnef_signature,
      { "Signature", "tnef.signature", FT_UINT32,  BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_key,
      { "Key", "tnef.key", FT_UINT16,  BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute,
      { "Attribute", "tnef.attribute", FT_NONE,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_lvl,
      { "Type", "tnef.attribute.lvl", FT_UINT8,  BASE_DEC, VALS(tnef_Lvl_vals), 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_tag,
      { "Tag", "tnef.attribute.tag", FT_UINT32,  BASE_HEX, VALS(tnef_Attribute_vals), 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_tag_type,
      { "Type", "tnef.attribute.tag.type", FT_UINT16,  BASE_HEX, VALS(tnef_Types_vals), 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_tag_id,
      { "Tag", "tnef.attribute.tag.id", FT_UINT16,  BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_length,
      { "Length", "tnef.attribute.length", FT_UINT32,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_value,
      { "Value", "tnef.attribute.value", FT_NONE,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_string,
      { "String", "tnef.attribute.string", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_date,
      { "Date", "tnef.attribute.date", FT_NONE,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_display_name,
      { "Display Name", "tnef.attribute.display_name", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_email_address,
      { "Email Address", "tnef.attribute.email_address", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_attribute_date_year,
      { "Year", "tnef.attribute.date.year", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_attribute_date_month,
      { "Month", "tnef.attribute.date.month", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_attribute_date_day,
      { "Day", "tnef.attribute.date.day", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_attribute_date_hour,
      { "Hour", "tnef.attribute.date.hour", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_attribute_date_minute,
      { "Minute", "tnef.attribute.date.minute", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_attribute_date_second,
      { "Second", "tnef.attribute.date.second", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_attribute_date_day_of_week,
      { "Day Of Week", "tnef.attribute.date.day_of_week", FT_UINT16, BASE_DEC, VALS(weekday_vals), 0, NULL, HFILL }},
    { &hf_tnef_attribute_checksum,
      { "Checksum", "tnef.attribute.checksum", FT_UINT16,  BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_mapi_props,
      { "MAPI Properties", "tnef.mapi_props", FT_NONE,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_version,
      { "Version", "tnef.version", FT_UINT32,  BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_oem_codepage,
      { "OEM Codepage", "tnef.oem_codepage", FT_UINT64,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_message_class,
      { "Message Class", "tnef.message_class", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_original_message_class,
      { "Original Message Class", "tnef.message_class.original", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_priority,
      { "Priority", "tnef.priority", FT_UINT16,  BASE_DEC, VALS(tnef_Priority_vals), 0x0,
        NULL, HFILL }},
    { &hf_tnef_mapi_props_count,
      { "Count", "tnef.mapi_props.count", FT_UINT32,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_property,
      { "Property", "tnef.property", FT_NONE,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_property_tag,
      { "Tag", "tnef.property.tag", FT_UINT32,  BASE_HEX, VALS(nspi_MAPITAGS_vals), 0x0,
        NULL, HFILL }},
    { &hf_tnef_property_tag_type,
      { "Type", "tnef.property.tag.type", FT_UINT16,  BASE_HEX, VALS(nspi_property_types_vals), 0x0,
        NULL, HFILL }},
    { &hf_tnef_property_tag_id,
      { "Tag", "tnef.property.tag.id", FT_UINT16,  BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_property_tag_set,
      { "Set", "tnef.attribute.tag.set", FT_GUID,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_property_tag_kind,
      { "Kind", "tnef.attribute.tag.kind", FT_UINT32,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_property_tag_name_id,
      { "Name", "tnef.attribute.tag.name.id", FT_UINT32,  BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_property_tag_name_length,
      { "Length", "tnef.attribute.tag.name.length", FT_UINT32,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_property_tag_name_string,
      { "Name", "tnef.attribute.tag.name.string", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_property_padding,
      { "Padding", "tnef.property.padding", FT_NONE,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_padding,
      { "Padding", "tnef.padding", FT_NONE,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_values_count,
      { "Count", "tnef.values.count", FT_UINT32,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_value_length,
      { "Length", "tnef.value.length", FT_UINT32,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tnef_PropValue_i,
      { "I", "tnef.PropValue.i", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_l,
      { "L", "tnef.PropValue.l", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_b,
      { "B", "tnef.PropValue.b", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_lpszA,
      { "Lpsza", "tnef.PropValue.lpszA", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_lpszW,
      { "Lpszw", "tnef.PropValue.lpszW", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_lpguid,
      { "Lpguid", "tnef.PropValue.lpguid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_bin,
      { "Bin", "tnef.PropValue.bin", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_ft,
      { "Ft", "tnef.PropValue.ft", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_err,
      { "Err", "tnef.PropValue.err", FT_UINT32, BASE_DEC, VALS(nspi_MAPISTATUS_vals), 0, NULL, HFILL }},
    { &hf_tnef_PropValue_MVi,
      { "Mvi", "tnef.PropValue.MVi", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_MVl,
      { "Mvl", "tnef.PropValue.MVl", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_MVszA,
      { "Mvsza", "tnef.PropValue.MVszA", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_MVbin,
      { "Mvbin", "tnef.PropValue.MVbin", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_MVguid,
      { "Mvguid", "tnef.PropValue.MVguid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_MVszW,
      { "Mvszw", "tnef.PropValue.MVszW", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_MVft,
      { "Mvft", "tnef.PropValue.MVft", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_null,
      { "Null", "tnef.PropValue.null", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_tnef_PropValue_object,
      { "Object", "tnef.PropValue.object", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
  };
  static int *ett[] = {
    &ett_tnef,
    &ett_tnef_attribute,
    &ett_tnef_attribute_tag,
    &ett_tnef_mapi_props,
    &ett_tnef_property,
    &ett_tnef_property_tag,
    &ett_tnef_counted_items,
    &ett_tnef_attribute_date,
    &ett_tnef_attribute_address,
  };

  static ei_register_info ei[] = {
    { &ei_tnef_expect_single_item, { "tnef.expect_single_item", PI_MALFORMED, PI_ERROR, "Expected single item", EXPFILL }},
    { &ei_tnef_incorrect_signature, { "tnef.signature.incorrect", PI_MALFORMED, PI_WARN, "Incorrect signature", EXPFILL }},
  };

  expert_module_t* expert_tnef;

  proto_tnef = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_tnef, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_tnef = expert_register_protocol(proto_tnef);
  expert_register_field_array(expert_tnef, ei, array_length(ei));

  /* Allow dissector to find be found by name. */
  tnef_handle = register_dissector(PFNAME, dissect_tnef, proto_tnef);

}

/* The registration hand-off routine */
void
proto_reg_handoff_tnef(void)
{
  dissector_handle_t tnef_file_handle;

  tnef_file_handle = create_dissector_handle(dissect_tnef_file, proto_tnef);

  dissector_add_string("media_type", "application/ms-tnef", tnef_handle);

  /* X.400 file transfer bodypart */
  register_ber_oid_dissector_handle("1.2.840.113556.3.10.1", tnef_handle, proto_tnef, "id-et-tnef");

  dissector_add_uint("wtap_encap", WTAP_ENCAP_TNEF, tnef_file_handle);
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
