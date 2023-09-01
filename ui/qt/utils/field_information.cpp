/* field_information.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>

#include <ui/qt/utils/field_information.h>

FieldInformation::FieldInformation(field_info *fi, QObject * parent)
:QObject(parent)
{
    fi_ = fi;
    parent_fi_ = NULL;
}

FieldInformation::FieldInformation(const ProtoNode *node, QObject * parent)
:QObject(parent)
{
    fi_ = NULL;
    if (node && node->isValid()) {
        fi_ = node->protoNode()->finfo;
    }
    parent_fi_ = NULL;
}

bool FieldInformation::isValid() const
{
    bool ret = false;

    if (fi_ && fi_->hfinfo)
    {
        if (fi_->hfinfo->blurb != NULL && fi_->hfinfo->blurb[0] != '\0') {
            ret = true;
        } else {
            ret = QString((fi_->hfinfo->name)).length() > 0;
        }
    }

    return ret;
}

bool FieldInformation::isLink() const
{
    if (fi_ && fi_->hfinfo) {
        if ((fi_->hfinfo->type == FT_FRAMENUM) ||
                (FI_GET_FLAG(fi_, FI_URL) && FT_IS_STRING(fi_->hfinfo->type))) {
            return true;
        }
    }
    return false;
}

void FieldInformation::setParentField(field_info * par_fi)
{
    parent_fi_ = par_fi;
}

int FieldInformation::treeType()
{
    if (fi_) {
        Q_ASSERT(fi_->tree_type >= -1 && fi_->tree_type < num_tree_types);
        return fi_->tree_type;
    }
    return -1;
}

field_info * FieldInformation::fieldInfo() const
{
    return fi_;
}

FieldInformation::HeaderInfo FieldInformation::headerInfo() const
{
    HeaderInfo header;

    if (fi_ && fi_->hfinfo)
    {
        header.name = fi_->hfinfo->name;
        header.description = fi_->hfinfo->blurb;
        header.abbreviation = fi_->hfinfo->abbrev;
        header.isValid = true;
        header.type = fi_->hfinfo->type;
        header.parent = fi_->hfinfo->parent;
        header.id = fi_->hfinfo->id;
    }
    else
    {
        header.name = "";
        header.description = "";
        header.abbreviation = "";
        header.isValid = false;
        header.type = FT_NONE;
        header.parent = 0;
        header.id = 0;
    }

    return header;
}

FieldInformation * FieldInformation::parentField() const
{
    return new FieldInformation(parent_fi_, parent());
}

bool FieldInformation::tvbContains(FieldInformation *child)
{
    if (fi_ && child && fi_->ds_tvb == child->fieldInfo()->ds_tvb)
        return true;

    return false;
}

unsigned FieldInformation::flag(unsigned mask)
{
    if (fi_) {
        return FI_GET_FLAG(fi_, mask);
    }
    return 0;
}

const QString FieldInformation::moduleName()
{
    QString module_name;
    if (isValid()) {
        if (headerInfo().parent == -1) {
            module_name = fi_->hfinfo->abbrev;
        } else {
            module_name = proto_registrar_get_abbrev(headerInfo().parent);
        }
    }
    return module_name;
}

QString FieldInformation::toString()
{
    QByteArray display_label;

    display_label.resize(80); // Arbitrary.
    int label_len = proto_item_fill_display_label(fi_, display_label.data(), static_cast<int>(display_label.size())-1);
    display_label.resize(label_len);

    if (display_label.isEmpty()) {
        return "[no value for field]";
    }
    return QString(display_label);
}

QString FieldInformation::url()
{
    QString url;
    if (flag(FI_URL) && headerInfo().isValid && FT_IS_STRING(fi_->hfinfo->type)) {
        url = toString();
    }
    return url;
}

FieldInformation::Position FieldInformation::position() const
{
    Position pos = {-1, -1};
    if (fi_ && fi_->ds_tvb)
    {
        int len = (int) tvb_captured_length(fi_->ds_tvb);

        pos.start = fi_->start;
        pos.length = fi_->length;

        if (pos.start < 0 || pos.length < 0 || pos.start >= len)
        {
            if (fi_->appendix_start >= 0 && fi_->appendix_length > 0 && fi_->appendix_start < len)
            {
                pos.start = fi_->appendix_start;
                pos.length = fi_->appendix_length;
            }
        }
    }

    return pos;
}

FieldInformation::Position FieldInformation::appendix() const
{
    Position pos = {-1, -1};
    if (fi_ && fi_->ds_tvb)
    {
        pos.start = fi_->appendix_start;
        pos.length = fi_->appendix_length;
    }

    return pos;
}

const QByteArray FieldInformation::printableData()
{
    QByteArray data;

    if (fi_ && fi_->ds_tvb)
    {
        FieldInformation::Position pos = position();
        int rem_length = tvb_captured_length_remaining(fi_->ds_tvb, pos.start);

        int length = pos.length;
        if (length > rem_length)
            length = rem_length;
        uint8_t * dataSet = (uint8_t *)tvb_memdup(wmem_file_scope(), fi_->ds_tvb, pos.start, length);
        data = QByteArray::fromRawData((char *)dataSet, length);
    }

    return data;
}
