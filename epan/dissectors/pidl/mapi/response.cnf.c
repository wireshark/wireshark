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

#
# Misc. filters
#
HF_FIELD hf_mapi_MAPI_OPNUM "Opnum" "mapi.EcDoRpc_MAPI_REPL.opnum" FT_UINT8 BASE_HEX VALS(mapi_MAPI_OPNUM_vals) 0 NULL HFILL
HF_RENAME hf_mapi_EcDoRpc_MAPI_REPL_opnum hf_mapi_MAPI_OPNUM
HF_FIELD hf_mapi_EcDoRpc_handle_index "Handle index" "mapi.EcDoRpc.handle_index" FT_UINT8 BASE_DEC NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_subcontext_size "Subcontext size" "mapi.EcDoRpc.subcontext_size" FT_UINT32 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_unknown1 "Unknown1" "mapi.EcDoRpc.unknown1" FT_UINT16 BASE_HEX NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_layout "Layout" "mapi.EcDoRpc.layout" FT_UINT8 BASE_DEC NULL 0 NULL HFILL
HF_FIELD hf_mapi_EcDoRpc_prop_count "Prop count" "mapi.EcDoRpc.prop_count" FT_UINT16 BASE_HEX NULL 0 NULL HFILL


CODE START

static int
mapi_dissect_struct_EcDoRpc_MAPI_REPL(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	guint8		opnum;
	guint32		retval;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mapi_EcDoRpc_MAPI_REPL);
	}

	opnum = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_mapi_MAPI_OPNUM, tvb, offset, 1, ENC_NA);
	offset += 1;

	col_append_fstr(pinfo->cinfo, COL_INFO, " + %s", val_to_str(opnum, mapi_MAPI_OPNUM_vals, "Unknown MAPI operation: 0x%02x"));

	if (opnum != op_MAPI_Notify) {
		proto_tree_add_item(tree, hf_mapi_EcDoRpc_handle_index, tvb, offset, 1, ENC_NA);
		offset += 1;

		retval = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_mapi_MAPISTATUS_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

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
	proto_tree	*tr = NULL;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_mapi_EcDoRpc_mapi_response, &size);
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

	tr = proto_tree_add_subtree(tree, decrypted_tvb, 0, size, ett_mapi_mapi_response, NULL, "Decrypted MAPI PDU");

	pdu_len = tvb_get_letohs(decrypted_tvb, 0);
	proto_tree_add_uint(tr, hf_mapi_pdu_len, decrypted_tvb, 0, 2, pdu_len);
	proto_tree_add_item(tr, hf_mapi_decrypted_data, decrypted_tvb, 2, pdu_len - 2, ENC_NA);

	/* Analyze contents */
	offset = mapi_dissect_element_EcDoRpc_response__(decrypted_tvb, 0, pinfo, tr, di, drep);
	/* Analyze mapi handles */
	offset = mapi_dissect_element_request_handles_cnf(decrypted_tvb, offset, pinfo, tr, di, drep);

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
		offset = mapi_dissect_struct_EcDoRpc_MAPI_REPL(subtvb, offset, pinfo, tree, di, drep, hf_mapi_mapi_response_mapi_repl, length - offset);
	}

	return offset;
}

/*************************/
/* EcDoRpc Function 0x2  */
static int
mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_OpenFolder(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		old_offset;
	int		origin_offset;

	origin_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REPL_UNION_mapi_OpenFolder, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mapi_OpenFolder_repl);
	}

	old_offset = offset;
	proto_tree_add_item(tree, hf_mapi_EcDoRpc_unknown1, tvb, old_offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_item_set_len(item, offset - origin_offset);

	return offset;
}

/*************************/
/* EcDoRpc Function 0x7  */
static int
mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_GetProps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	proto_item	*item = NULL;
	proto_tree	*tree = NULL;
	int		origin_offset;
	/**** Function parameters ****/
	guint16		length;

	origin_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_mapi_EcDoRpc_MAPI_REPL_UNION_mapi_GetProps, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mapi_GetProps_repl);
	}

	proto_tree_add_item(tree, hf_mapi_EcDoRpc_layout, tvb, offset, 1, ENC_NA);
	offset += 1;

	length = tvb_reported_length_remaining(tvb, offset);
	proto_tree_add_uint(tree, hf_mapi_EcDoRpc_prop_count, tvb, offset, 0, length);
	offset += length;

	proto_item_set_len(item, offset - origin_offset);

	return offset;
}

/*************************/
/* EcDoRpc Function 0xFE */
/* static int
mapi_dissect_element_EcDoRpc_MAPI_REPL_UNION_OpenMsgStore(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
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
