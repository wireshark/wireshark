/* packet-smb-common.c
 * Common routines for smb packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include "packet-smb-common.h"

#include "packet-dns.h"

/*
 * Share type values - used in LANMAN and in SRVSVC.
 *
 * XXX - should we dissect share type values, at least in SRVSVC, as
 * a subtree with bitfields, as the 0x80000000 bit appears to be a
 * hidden bit, with some number of bits at the bottom being the share
 * type?
 *
 * Does LANMAN use that bit?
 */
const value_string share_type_vals[] = {
	{0, "Directory tree"},
	{1, "Printer queue"},
	{2, "Communications device"},
	{3, "IPC"},
	{0x80000000, "Hidden Directory tree"},
	{0x80000001, "Hidden Printer queue"},
	{0x80000002, "Hidden Communications device"},
	{0x80000003, "Hidden IPC"},
	{0, NULL}
};

int display_ms_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, char **data)
{
	char *str;
	gint  len;

	/* display a string from the tree and return the new offset */

	str = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
	proto_tree_add_string(tree, hf_index, tvb, offset, len, str);

	/* Return a copy of the string if requested */

	if (data)
		*data = str;

	return 	offset+len;
}


int display_unicode_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, char **data)
{
	char    *str, *p;
	int      len;
	int      charoffset;
	guint16  character;

	/* display a unicode string from the tree and return new offset */

	/*
	 * Get the length of the string.
	 * XXX - is it a bug or a feature that this will throw an exception
	 * if we don't find the '\0'?  I think it's a feature.
	 */
	len = 0;
	while (tvb_get_letohs(tvb, offset + len) != '\0')
		len += 2;
	len += 2;	/* count the '\0' too */

	/*
	 * Allocate a buffer for the string; "len" is the length in
	 * bytes, not the length in characters.
	 */
	str = (char *)wmem_alloc(wmem_packet_scope(), len/2);

	/*
	 * XXX - this assumes the string is just ISO 8859-1; we need
	 * to better handle multiple character sets in Wireshark,
	 * including Unicode/ISO 10646, and multiple encodings of
	 * that character set (UCS-2, UTF-8, etc.).
	 */
	charoffset = offset;
	p = str;
	while ((character = tvb_get_letohs(tvb, charoffset)) != '\0') {
		*p++ = (char) character;
		charoffset += 2;
	}
	*p = '\0';

	proto_tree_add_string(tree, hf_index, tvb, offset, len, str);

	if (data)
		*data = str;

	return 	offset+len;
}

/* Max string length for displaying Unicode strings.  */
#define	MAX_UNICODE_STR_LEN	256

int dissect_ms_compressed_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index,
				 const char **data)
{
	int           compr_len;
	gint         str_len;
	const gchar  *str = NULL;

	/* The name data MUST start at offset 0 of the tvb */
	compr_len = get_dns_name(tvb, offset, MAX_UNICODE_STR_LEN+3+1, 0, &str, &str_len);
	proto_tree_add_string(tree, hf_index, tvb, offset, compr_len, format_text(wmem_packet_scope(), str, str_len));

	if (data)
		*data = str;

	return offset + compr_len;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
