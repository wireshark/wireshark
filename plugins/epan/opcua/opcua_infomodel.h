/* opcua_infomodel.h
 * Custom datatypes from an information model (UANodeSet XML file)
 * Author: Leon Schmidt <leon.schmidt@codewerk.de>
 * Copyright (C) 2022 Codewerk GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPCUA_INFOMODEL_H
#define OPCUA_INFOMODEL_H

#include <epan/packet.h>
#include <epan/prefs.h>

#include "opcua_simpletypes.h"

/**
 * @brief Register the preferences, fields and expert infos of the information model.
 *
 * @param proto  The protocol the fields belong to.
 * @param module The preference module of @p proto.
 */
void opcua_infomodel_register(int proto, module_t *module);

/**
 * @brief (Re)load the information model after a preference change and (re)register the fields of its
 * custom datatypes.
 */
void opcua_infomodel_apply(void);

/**
 * @brief Dissect the body of an ExtensionObject of a custom datatype from the information model.
 *
 * @param tree   The ExtensionObject subtree.
 * @param tvb    The packet buffer.
 * @param pinfo  The packet info.
 * @param offset Offset of the body in @p tvb (after the length field).
 * @param length Length of the body.
 * @param typeId The ExtensionObject type ID.
 * @return true if the body was dissected, false if the type is not in the information model.
 */
bool opcua_infomodel_dissect(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int length,
                             const ExtensionObjectTypeId *typeId);

#endif /* OPCUA_INFOMODEL_H */

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
