MANUAL mapi_dissect_element_EcDoRpc_request
MANUAL mapi_dissect_element_EcDoRpc_request_
MANUAL mapi_dissect_element_EcDoRpc_request__

#
# EcDoRpc request (mapi_request)
#
NOEMIT request
ETT_FIELD ett_mapi_mapi_request
#MANUAL mapi_dissect_struct_request
HF_FIELD hf_mapi_mapi_request_mapi_req "Mapi Req" "mapi.mapi_request.mapi_req" FT_NONE BASE_NONE NULL 0 "" HFILL

#
# EcDoRpc_MAPI_REQ
#
NOEMIT EcDoRpc_MAPI_REQ
ETT_FIELD ett_mapi_EcDoRpc_MAPI_REQ
MANUAL mapi_dissect_struct_EcDoRpc_MAPI_REQ
MANUAL mapi_dissect_EcDoRpc_MAPI_REQ_UNION

# EcDoRpc 0x2 - OpenFolder request
NOEMIT OpenFolder_req
ETT_FIELD ett_mapi_OpenFolder_req
MANUAL mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenFolder

# EcDoRpc 0x7 - GetProps request
NOEMIT GetProps_req
ETT_FIELD ett_mapi_GetProps_req
MANUAL mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_GetProps

# EcDoRpc 0xFE - OpenMsgStore request
NOEMIT OpenMsgStore_req
ETT_FIELD ett_mapi_OpenMsgStore_req
MANUAL mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenMsgStore

#
# Misc. filters
#
HF_FIELD hf_mapi_MAPI_OPNUM "Opnum" "mapi.EcDoRpc_MAPI_REQ.opnum" FT_UINT8 BASE_HEX VALS(mapi_MAPI_OPNUM_vals) 0 NULL HFILL
HF_RENAME hf_mapi_EcDoRpc_MAPI_REQ_opnum hf_mapi_MAPI_OPNUM
HF_FIELD hf_mapi_EcDoRpc_mapi_flags "mapi_flags" "mapi.EcDoRpc.mapi_flags" FT_UINT8 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_folder_id "Folder ID" "mapi.EcDoRpc.folder_id" FT_UINT64 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_unknown2 "Unknown2" "mapi.EcDoRpc.unknown2" FT_UINT8 BASE_DEC NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_unknown3 "Unknown3" "mapi.EcDoRpc.unknown3" FT_UINT32 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_mapi_tag "MAPI tag" "mapi.EcDoRpc.mapi_tag" FT_UINT32 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_codepage "Codepage" "mapi.EcDoRpc.codepage" FT_UINT32 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_padding "Padding" "mapi.EcDoRpc.padding" FT_UINT32 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_row "Row" "mapi.EcDoRpc.row" FT_UINT8 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_str_length "Length" "mapi.EcDoRpc.str_length" FT_UINT16 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_mailbox "Mailbox" "mapi.EcDoRpc.mailbox" FT_STRING BASE_NONE NULL 0 NULL HFILL


CODE START

static int
mapi_dissect_struct_EcDoRpc_MAPI_REQ(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	guint8		opnum;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_mapi_EcDoRpc_MAPI_REQ);
	}

	opnum = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_mapi_MAPI_OPNUM, tvb, offset, 1, ENC_NA);
	offset += 1;

	col_append_fstr(pinfo->cinfo, COL_INFO, " + %s", val_to_str(opnum, mapi_MAPI_OPNUM_vals, "Unknown MAPI operation"));

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_mapi_flags, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_handle_index, tvb, offset, 1, ENC_NA);
	offset += 1;

	switch(opnum) {
		case op_MAPI_Release:
				offset = mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_Release(tvb, offset, pinfo, tree, di, drep);
			break;
		case op_MAPI_OpenFolder:
			offset = mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenFolder(tvb, offset, pinfo, tree, di, drep);
			break;
		case op_MAPI_GetProps:
			offset = mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_GetProps(tvb, offset, pinfo, tree, di, drep);
			break;
		case op_MAPI_OpenMsgStore:
			offset = mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenMsgStore(tvb, offset, pinfo, tree, di, drep);
			break;
		default:
			offset += param - 3;
	}

	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
mapi_dissect_element_EcDoRpc_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = mapi_dissect_element_EcDoRpc_request_(tvb, offset, pinfo, tree, di, drep);

	return offset;
}


static int
mapi_dissect_element_EcDoRpc_request_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32		size;
	int		start_offset = offset;
	guint8		*decrypted_data;
	tvbuff_t	*decrypted_tvb;
	const guint8	*ptr;
	gint		reported_len;
	guint16		pdu_len;
	guint32		i;
	proto_tree	*tr = NULL;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_mapi_EcDoRpc_mapi_request, &size);
	proto_tree_add_uint(tree, hf_mapi_EcDoRpc_subcontext_size, tvb, start_offset, offset - start_offset + size, size);

	reported_len = tvb_reported_length_remaining(tvb, offset);

	if ((guint32) reported_len > size) {
		reported_len = size;
	}
	if (size > (guint32) reported_len) {
		size = reported_len;
	}

	ptr = tvb_get_ptr(tvb, offset, size);

	decrypted_data = (guint8 *)g_malloc(size);
	for (i = 0; i < size; i++) {
		decrypted_data[i] = ptr[i] ^ 0xA5;
	}

	decrypted_tvb = tvb_new_child_real_data(tvb, decrypted_data, size, reported_len);
	tvb_set_free_cb(decrypted_tvb, g_free);

	add_new_data_source(pinfo, decrypted_tvb, "Decrypted MAPI");

	tr = proto_tree_add_subtree(tree, decrypted_tvb, 0, size, ett_mapi_mapi_request, NULL, "Decrypted MAPI PDU");

	pdu_len = tvb_get_letohs(decrypted_tvb, 0);
	proto_tree_add_uint(tr, hf_mapi_pdu_len, decrypted_tvb, 0, 2, pdu_len);
	proto_tree_add_item(tr, hf_mapi_decrypted_data, decrypted_tvb, 2, pdu_len - 2, ENC_NA);

	/* analyze contents */
	offset = mapi_dissect_element_EcDoRpc_request__(decrypted_tvb, 0, pinfo, tr, di, drep);

	/* analyze mapi handles */
	offset = mapi_dissect_element_request_handles_cnf(decrypted_tvb, offset, pinfo, tr, di, drep);

	/* append ptr size (4) */
	return start_offset + offset + 4;
}


/*
 * Analyze mapi_request real contents
 */
static int mapi_dissect_element_EcDoRpc_request__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint16	length;

	length = tvb_get_letohs(tvb, offset);
	offset += 2;

	while (offset < length) {
		offset = mapi_dissect_struct_EcDoRpc_MAPI_REQ(tvb, offset, pinfo, tree, di, drep, hf_mapi_mapi_request_mapi_req, length - offset);
	}

	return offset;
}

/*
static int
mapi_dissect_struct_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_mapi_mapi_request);
	}

	offset = mapi_dissect_struct_EcDoRpc_MAPI_REQ(tvb, offset, pinfo, tree, di, drep, hf_mapi_mapi_request_mapi_req, 0);

	return offset;
}
*/

/*************************/
/* EcDoRpc Function 0x2  */
static int
mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenFolder(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		origin_offset;

	origin_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REQ_UNION_mapi_OpenFolder, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mapi_OpenFolder_req);
	}

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_handle_index, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_folder_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_unknown2, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_item_set_len(item, offset - origin_offset);

	return offset;
}

/*************************/
/* EcDoRpc Function 0x7  */
static int
mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_GetProps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		origin_offset;
	guint16		i;
	/**** Function parameters ****/
	guint16		prop_count;
	guint32		mapitag;

	origin_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REQ_UNION_mapi_GetProps, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mapi_GetProps_req);
	}

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_unknown3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	prop_count = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_mapi_EcDoRpc_prop_count, tvb, offset, 2, prop_count);
	offset += 2;

	for (i = 0; i < prop_count; i++) {
		mapitag = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint_format(tree, hf_mapi_EcDoRpc_mapi_tag, tvb, offset, 4, mapitag, "[%.2d] %s", i, val_to_str(mapitag, mapi_MAPITAGS_vals, "Unknown MAPITAGS"));
		offset += 4;
	}

	proto_item_set_len(item, offset - origin_offset);

	return offset;
}


/*************************/
/* EcDoRpc Function 0xFE */
static int
mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenMsgStore(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		origin_offset;
	/**** Function parameters ****/
	guint16		str_len;

	origin_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REQ_UNION_mapi_OpenMsgStore, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mapi_OpenMsgStore_req);
	}

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_codepage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_padding, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_row, tvb, offset, 1, ENC_NA);
	offset += 1;

	str_len = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_mapi_EcDoRpc_str_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_mailbox, tvb, offset, str_len, ENC_ASCII|ENC_NA);
	offset += str_len;

	proto_item_set_len(item, offset - origin_offset);

	return offset;
}

CODE END
