/* packet-media.c
 * Routines for displaying an undissected media type (default case),
 * based on the generic "data" dissector.
 *
 * (C) Olivier Biot, 2004
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <wsutil/str_util.h>

#include "packet-media-type.h"

void proto_register_media(void);

static int proto_media;
static int hf_media_type;
static int ett_media;
static heur_dissector_list_t heur_subdissector_list;

static int
dissect_media(tvbuff_t *tvb, packet_info *pinfo , proto_tree *tree, void* data)
{
    int bytes;
    proto_item *ti;
    proto_tree *media_tree = 0;
    media_content_info_t *content_info = (media_content_info_t *)data;
    heur_dtbl_entry_t *hdtbl_entry;

    if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &hdtbl_entry, data)) {
        return tvb_reported_length(tvb);
    }

    /* Add media type to the INFO column if it is visible */
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", (pinfo->match_string) ? pinfo->match_string : "");

    if (tree) {
        if ( (bytes = tvb_reported_length(tvb)) > 0 )
        {
            ti = proto_tree_add_item(tree, proto_media, tvb, 0, -1, ENC_NA);
            media_tree = proto_item_add_subtree(ti, ett_media);

            if (content_info != NULL && content_info->media_str != NULL) {
                /* The media type has parameters */

                proto_tree_add_bytes_format_value(media_tree, hf_media_type, tvb, 0, bytes,
                    NULL, "%s; %s (%d byte%s)",
                    pinfo->match_string, content_info->media_str,
                    bytes, plurality(bytes, "", "s"));
            } else {
                /* The media type has no parameters */
                proto_tree_add_bytes_format_value(media_tree, hf_media_type, tvb, 0, bytes,
                    NULL, "%s (%d byte%s)",
                    pinfo->match_string ? pinfo->match_string : "",
                    bytes, plurality(bytes, "", "s"));
            }
        }
    }

    return tvb_reported_length(tvb);
}

void
proto_register_media(void)
{
    static hf_register_info hf[] = {
      { &hf_media_type,
        { "Media type", "media.type",
          FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},
    };
    static int *ett[] = {
        &ett_media
    };

    proto_media = proto_register_protocol (
        "Media Type",   /* name */
        "Media",        /* short name */
        "media"         /* abbrev */
        );
    register_dissector("media", dissect_media, proto_media);
    heur_subdissector_list = register_heur_dissector_list_with_description("media", "Media type", proto_media);
    proto_register_field_array(proto_media, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*
     * "Media" is used to dissect something whose normal dissector
     * is disabled, so it cannot itself be disabled.
     */
    proto_set_cant_toggle(proto_media);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
