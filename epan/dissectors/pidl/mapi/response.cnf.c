MANUAL mapi_dissect_element_EcDoRpc_response
MANUAL mapi_dissect_element_EcDoRpc_response_
MANUAL mapi_dissect_element_EcDoRpc_response__

#
# EcDoRpc response (mapi_response)
#
NOEMIT response
ETT_FIELD ett_mapi_mapi_response
MANUAL mapi_dissect_struct_response
HF_FIELD hf_mapi_mapi_response_mapi_repl "Mapi Repl" "mapi.mapi_response.mapi_repl" FT_NONE BASE_NONE NULL 0 NULL HFILL

#
# EcDoRpc_MAPI_REPL
#
NOEMIT EcDoRpc_MAPI_REPL
ETT_FIELD ett_mapi_EcDoRpc_MAPI_REPL
MANUAL mapi_dissect_struct_EcDoRpc_MAPI_REPL
MANUAL mapi_dissect_EcDoRpc_MAPI_REPL_UNION

# EcDoRpc 0x2 - OpenFolder response
NOEMIT OpenFolder_repl
ETT_FIELD ett_mapi_OpenFolder_repl
MANUAL mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_OpenFolder

# EcDoRpc 0x7 - GetProps response
NOEMIT GetProps_repl
ETT_FIELD ett_mapi_GetProps_repl
MANUAL mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_GetProps

# EcDoRpc 0xFE - OpenMsgStore response
#NOEMIT OpenMsgStore_repl
#ETT_FIELD ett_mapi_OpenMsgStore_repl
#MANUAL mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_OpenMsgStore



CODE START

static int
mapi_dissect_struct_EcDoRpc_MAPI_REPL(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	int		cur_offset;
	guint8		opnum;
	guint8		handle_idx;
	guint32		retval;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_mapi_EcDoRpc_MAPI_REPL);
	}

	cur_offset = offset;
	opnum = tvb_get_guint8(tvb, offset);
	offset += 1;
	proto_tree_add_text(tree, tvb, cur_offset, offset - cur_offset, "opnum: %s", val_to_str(opnum, mapi_MAPI_OPNUM_vals, "Unknown MAPI operation: 0x%02x"));

	col_append_fstr(pinfo->cinfo, COL_INFO, " + %s", val_to_str(opnum, mapi_MAPI_OPNUM_vals, "Unknown MAPI operation: 0x%02x"));

	if (opnum != op_MAPI_Notify) {
		cur_offset = offset;
		handle_idx = tvb_get_guint8(tvb, offset);
		offset += 1;
		proto_tree_add_text(tree, tvb, cur_offset, offset - cur_offset, "handle index: %d", handle_idx);

		cur_offset = offset;
		retval = tvb_get_letohl(tvb, offset);
		offset += 4;
		proto_tree_add_text(tree, tvb, cur_offset, offset - cur_offset, "MAPISTATUS: %s", val_to_str(retval, mapi_MAPISTATUS_vals, "Unknown MAPISTATUS error 0x%08x"));

		if (retval == MAPI_E_SUCCESS) {
			switch(opnum) {
				case op_MAPI_Release:
					offset = mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_Release(tvb, offset, pinfo, tree, di, drep);
					break;
				case op_MAPI_OpenFolder:
					offset = mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_OpenFolder(tvb, offset, pinfo, tree, di, drep);
					break;
				case op_MAPI_GetProps:
					offset = mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_GetProps(tvb, offset, pinfo, tree, di, drep);
					break;
/* 				case op_MAPI_OpenMsgStore: */
/* 					offset = mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_OpenMsgStore(tvb, offset, pinfo, tree, di, drep); */
/* 					break; */
				default:
					offset += param - 6;
			}
		}
	} else {
	       /* we don't decode notifications within the dissector yet */
	       offset += param - 1;
	}

	proto_item_set_len(item, offset - old_offset);

	return offset;
}

static int
mapi_dissect_element_EcDoRpc_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = mapi_dissect_element_EcDoRpc_response_(tvb, offset, pinfo, tree, di, drep);

	return offset;
}


static int
mapi_dissect_element_EcDoRpc_response_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_mapi_EcDoRpc_mapi_response, &size);
	proto_tree_add_text(tree, tvb, start_offset, offset - start_offset + size, "Subcontext size: 0x%x", size);

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

	it = proto_tree_add_text(tree, decrypted_tvb, 0, size, "Decrypted MAPI PDU");
	tr = proto_item_add_subtree(it, ett_mapi_mapi_response);

	pdu_len = tvb_get_letohs(decrypted_tvb, 0);
	proto_tree_add_uint(tr, hf_mapi_pdu_len, decrypted_tvb, 0, 2, pdu_len);
	proto_tree_add_item(tr, hf_mapi_decrypted_data, decrypted_tvb, 2, pdu_len - 2, ENC_NA);

	/* Analyze contents */
	offset = mapi_dissect_element_EcDoRpc_response__(decrypted_tvb, 0, pinfo, tr, drep);
	/* Analyze mapi handles */
	offset = mapi_dissect_element_request_handles(decrypted_tvb, offset, pinfo, tr, drep);

	return start_offset + offset + 4;
}


static int
mapi_dissect_element_EcDoRpc_response__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint16		length;
	tvbuff_t	*subtvb;

	length = tvb_get_letohs(tvb, offset);
	subtvb = tvb_new_subset(tvb, offset, length, length);
	offset += 2;

	while (offset < length) {
	      	offset = mapi_dissect_struct_EcDoRpc_MAPI_REPL(subtvb, offset, pinfo, tree, drep, hf_mapi_mapi_response_mapi_repl, length - offset);
	}

	return offset;
}

/*************************/
/* EcDoRpc Function 0x2  */
static int
mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_OpenFolder(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	int		origin_offset;
	/**** Function parameters ****/
	guint16		unknown;

	origin_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REPL_UNION_mapi_OpenFolder, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mapi_OpenFolder_repl);
	}

	old_offset = offset;
	unknown = tvb_get_letohs(tvb, offset);
	offset += 2;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "unknown: 0x%04x", unknown);

	proto_item_set_len(item, offset - origin_offset);

	return offset;
}

/*************************/
/* EcDoRpc Function 0x7  */
static int
mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_GetProps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	int		origin_offset;
	/**** Function parameters ****/
	guint8		layout;
	guint16		length;

	origin_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REPL_UNION_mapi_GetProps, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mapi_GetProps_repl);
	}

	old_offset = offset;
	layout = tvb_get_guint8(tvb, offset);
	offset += 1;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "layout: %d", layout);

	old_offset = offset;
	length = tvb_reported_length_remaining(tvb, offset);
	offset += length;
	proto_tree_add_text(tree, tvb, old_offset, offset - old_offset, "prop_count: 0x%x", length);

	proto_item_set_len(item, offset - origin_offset);

	return offset;
}

/*************************/
/* EcDoRpc Function 0xFE */
/* static int
mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_OpenMsgStore(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo, proto_tree *parent_tree _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	int		origin_offset;

	origin_offset = offset;
	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REPL_UNION_mapi_OpenMsgStore, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_mapi_OpenMsgStore_repl);
	}

	offset = mapi_dissect_element_OpenMsgStore_repl_PR_OBJECT_TYPE(tvb, offset, pinfo, tree, di, drep);

	proto_item_set_len(item, offset - origin_offset);

	return offset;
	}*/

CODE END
