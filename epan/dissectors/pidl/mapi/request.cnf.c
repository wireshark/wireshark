MANUAL mapi_dissect_element_EcDoRpc_request
MANUAL mapi_dissect_element_EcDoRpc_request_
MANUAL mapi_dissect_element_EcDoRpc_request__

#
# EcDoRpc request (mapi_request)
#
NOEMIT request
ETT_FIELD ett_mapi_mapi_request
MANUAL mapi_dissect_struct_request
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

CODE START

int
mapi_dissect_struct_EcDoRpc_MAPI_REQ(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	int		cur_offset;
	guint8		opnum;
	guint8		mapi_flags;
	guint8		handle_idx;
	
	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_mapi_EcDoRpc_MAPI_REQ);
	}

	cur_offset = offset;
	opnum = tvb_get_guint8(tvb, offset);
	offset += 1;
	proto_tree_add_text(tree, tvb, cur_offset, offset - cur_offset, "opnum: %s", val_to_str(opnum, mapi_MAPI_OPNUM_vals, "Unknown MAPI operation"));

	if (check_col(pinfo->cinfo, COL_INFO)) {
	   	 col_append_fstr(pinfo->cinfo, COL_INFO, " + %s", val_to_str(opnum, mapi_MAPI_OPNUM_vals, "Unknown MAPI operation"));
        }

	cur_offset = offset;
	mapi_flags = tvb_get_guint8(tvb, offset);
	offset += 1;
	proto_tree_add_text(tree, tvb, cur_offset, offset - cur_offset, "mapi_flags: 0x%x", mapi_flags);

	cur_offset = offset;
	handle_idx = tvb_get_guint8(tvb, offset);
	offset += 1;
	proto_tree_add_text(tree, tvb, cur_offset, offset - cur_offset, "handle index: %d", handle_idx);

	switch(opnum) {
		case op_MAPI_Release:
     			offset = mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_Release(tvb, offset, pinfo, tree, drep);
			break;
		case op_MAPI_OpenFolder:
			offset = mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenFolder(tvb, offset, pinfo, tree, drep);
			break;
		case op_MAPI_GetProps:
			offset = mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_GetProps(tvb, offset, pinfo, tree, drep);
			break;
		case op_MAPI_OpenMsgStore:
			offset = mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenMsgStore(tvb, offset, pinfo, tree, drep);
			break;
		default:
			offset += param - 3;
	}

	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
mapi_dissect_element_EcDoRpc_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = mapi_dissect_element_EcDoRpc_request_(tvb, offset, pinfo, tree, drep);

	return offset;
}


static int 
mapi_dissect_element_EcDoRpc_request_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32		size;
	int		start_offset = offset;
	guint8		*decrypted_data;
	tvbuff_t	*decrypted_tvb;
	const guint8	*ptr;
	gint		reported_len;
	guint16		pdu_len;
	guint32		i;
	proto_item	*it = NULL;
	proto_tree	*tr = NULL;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_mapi_EcDoRpc_mapi_request, &size);
	proto_tree_add_text(tree, tvb, start_offset, offset - start_offset + size, "Subcontext size: 0x%x", size);

	reported_len = tvb_reported_length_remaining(tvb, offset);

	if ((guint32) reported_len > size) {
		reported_len = size;
	}
	if (size > (guint32) reported_len) {
		size = reported_len;
	}

	ptr = tvb_get_ptr(tvb, offset, size);

	decrypted_data = g_malloc(size);
	for (i = 0; i < size; i++) {
		decrypted_data[i] = ptr[i] ^ 0xA5;
	}

	decrypted_tvb = tvb_new_child_real_data(tvb, decrypted_data, size, reported_len);
	tvb_set_free_cb(decrypted_tvb, g_free);
	
	add_new_data_source(pinfo, decrypted_tvb, "Decrypted MAPI");

	it = proto_tree_add_text(tree, decrypted_tvb, 0, size, "Decrypted MAPI PDU");
	tr = proto_item_add_subtree(it, ett_mapi_mapi_request);

	pdu_len = tvb_get_letohs(decrypted_tvb, 0);
	proto_tree_add_uint(tr, hf_mapi_pdu_len, decrypted_tvb, 0, 2, pdu_len);
	proto_tree_add_item(tr, hf_mapi_decrypted_data, decrypted_tvb, 2, pdu_len - 2, FALSE);

	/* analyze contents */
	offset = mapi_dissect_element_EcDoRpc_request__(decrypted_tvb, 0, pinfo, tr, drep);

	/* analyze mapi handles */
	offset = mapi_dissect_element_request_handles(decrypted_tvb, offset, pinfo, tr, drep);

	/* append ptr size (4) */
	return start_offset + offset + 4;
}


/* 
 * Analyze mapi_request real contents
 */
static int mapi_dissect_element_EcDoRpc_request__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint16	length;

	length = tvb_get_letohs(tvb, offset);
	offset += 2;

	while (offset < length) {
	      	offset = mapi_dissect_struct_EcDoRpc_MAPI_REQ(tvb, offset, pinfo, tree, drep, hf_mapi_mapi_request_mapi_req, length - offset);
	}

	return offset;
}


int
mapi_dissect_struct_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_mapi_mapi_request);
	}

	offset = mapi_dissect_struct_EcDoRpc_MAPI_REQ(tvb, offset, pinfo, tree, drep, hf_mapi_mapi_request_mapi_req, 0);

	return offset;
}


/*************************/
/* EcDoRpc Function 0x2  */
static int
mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenFolder(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	int		origin_offset;
	/**** Function parameters ****/
	guint8		handle_idx;
	guint64		folder_id;
	guint8		unknown;

	origin_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REQ_UNION_mapi_OpenFolder, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_mapi_OpenFolder_req);
	}

	old_offset = offset;
	handle_idx = tvb_get_guint8(tvb, offset);
	offset += 1;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "handle index: %d", handle_idx);

	old_offset = offset;
	folder_id = tvb_get_letoh64(tvb, offset);
	offset += 8;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "folder ID: 0x%" G_GINT64_MODIFIER "x", folder_id);

	old_offset = offset;
	unknown = tvb_get_guint8(tvb, offset);
	offset += 1;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "unknown: %d", unknown);
	
	proto_item_set_len(item, offset - origin_offset);
	
	return offset;
}

/*************************/
/* EcDoRpc Function 0x7  */
static int
mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_GetProps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	int		origin_offset;
	guint16		i;
	/**** Function parameters ****/
	guint32		unknown;
	guint16		prop_count;
	guint32		mapitag;

	origin_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REQ_UNION_mapi_GetProps, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_mapi_GetProps_req);
	}

	old_offset = offset;
	unknown = tvb_get_letohl(tvb, offset);
	offset += 4;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "unknown: 0x%x", unknown);

	old_offset = offset;
	prop_count = tvb_get_letohs(tvb, offset);
	offset += 2;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "prop_count: %d", prop_count);

	for (i = 0; i < prop_count; i++) {
	    old_offset = offset;
	    mapitag = tvb_get_letohl(tvb, offset);
	    offset += 4;
	    proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "[%.2d] %s", i, val_to_str(mapitag, mapi_MAPITAGS_vals, "Unknown MAPITAGS"));
	}

	proto_item_set_len(item, offset - origin_offset);

	return offset;
}


/*************************/
/* EcDoRpc Function 0xFE */
static int
mapi_dissect_element_EcDoRpc_MAPI_REQ_UNION_OpenMsgStore(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	int		origin_offset;
	/**** Function parameters ****/
	guint32		codepage;
	guint32		padding;
	guint8		row;
	guint16		str_len;
	gchar		*mailbox;

	origin_offset = offset;
	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REQ_UNION_mapi_OpenMsgStore, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_mapi_OpenMsgStore_req);
	}

	codepage = tvb_get_letohl(tvb, offset);
	offset += 4;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "codepage: 0x%x", codepage);

	old_offset = offset;
	padding = tvb_get_letohl(tvb, offset);
	offset += 4;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "padding: 0x%x", padding);

	old_offset = offset;
	row = tvb_get_guint8(tvb, offset);
	offset += 1;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "row: 0x%x", row);

	old_offset = offset;
	str_len = tvb_get_letohs(tvb, offset);
	offset += 2;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "str length: 0x%x", str_len);

	old_offset = offset;
	mailbox = tvb_format_text(tvb, offset, str_len - 1);
	offset += str_len;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "mailbox: %s", mailbox);

	proto_item_set_len(item, offset - origin_offset);

	return offset;
}

CODE END
