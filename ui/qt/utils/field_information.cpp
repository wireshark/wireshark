/* field_information.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <stdint.h>

#include <ui/qt/utils/field_information.h>

FieldInformation::FieldInformation(field_info * fi, QObject * parent)
:QObject(parent)
{
    fi_ = fi;
    parent_fi_ = 0;
}

bool FieldInformation::isValid()
{
    bool ret = false;

    if ( fi_ )
    {
        if (fi_->hfinfo->blurb != 0 && fi_->hfinfo->blurb[0] != '\0') {
            ret = true;
        } else {
            ret = ((QString().fromUtf8(fi_->hfinfo->name)).length() > 0 );
        }
    }

    return ret;
}

void FieldInformation::setParentField(field_info * par_fi)
{
    parent_fi_ = par_fi;
}

field_info * FieldInformation::fieldInfo() const
{
    return fi_;
}

FieldInformation::HeaderInfo FieldInformation::headerInfo() const
{
    HeaderInfo header;
    header.isValid = false;

    if ( fi_ && fi_->hfinfo )
    {
        header.isValid = true;
        header.name = QString().fromUtf8(fi_->hfinfo->name);
        header.description = QString().fromUtf8(fi_->hfinfo->blurb);
        header.abbreviation = QString().fromUtf8(fi_->hfinfo->abbrev);
    }

    return header;
}

FieldInformation * FieldInformation::parentField() const
{
    return new FieldInformation(parent_fi_);
}

bool FieldInformation::tvbContains(FieldInformation *child)
{
    if ( fi_ && child && fi_->ds_tvb == child->fieldInfo()->ds_tvb )
        return true;

    return false;
}

FieldInformation::Position FieldInformation::position() const
{
    Position pos = {-1, -1};
    if ( fi_ && fi_->ds_tvb )
    {
        int len = (int) tvb_captured_length(fi_->ds_tvb);

        pos.start = fi_->start;
        pos.length = fi_->length;

        if (pos.start < 0 || pos.length < 0 || pos.start >= len)
        {
            if ( fi_->appendix_start >= 0 && fi_->appendix_length > 0 && fi_->appendix_start < len )
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
    if ( fi_ && fi_->ds_tvb )
    {
        pos.start = fi_->appendix_start;
        pos.length = fi_->appendix_length;
    }

    return pos;
}

QByteArray FieldInformation::printableData()
{
    QByteArray data;

    if ( fi_ && fi_->ds_tvb )
    {
        FieldInformation::Position pos = position();
        int rem_length = tvb_captured_length_remaining(fi_->ds_tvb, pos.start);

        int length = pos.length;
        if ( length > rem_length )
            length = rem_length;
        uint8_t * dataSet = (uint8_t *)tvb_memdup(wmem_file_scope(), fi_->ds_tvb, pos.start, length );
        data = QByteArray::fromRawData((char *)dataSet, length);
    }

    return data;
}
/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
