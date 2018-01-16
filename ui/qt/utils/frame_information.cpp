/* frame_information.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <epan/epan_dissect.h>
#include "epan/epan.h"
#include "epan/column.h"
#include "epan/ftypes/ftypes.h"

#include "wiretap/wtap.h"

#include "cfile.h"
#include "file.h"
#include <ui/qt/capture_file.h>

#include "frame_tvbuff.h"

#include <stdint.h>

#include <ui/qt/utils/frame_information.h>

FrameInformation::FrameInformation(CaptureFile * capfile, frame_data * fi, QObject * parent)
:QObject(parent),
 fi_(fi),
 cap_file_(capfile),
 packet_data_(0)
{
    loadFrameTree();
}

void FrameInformation::loadFrameTree()
{
    if ( ! fi_ || ! cap_file_ || !cap_file_->capFile())
        return;

    if (!cf_read_record(cap_file_->capFile(), fi_))
        return;

    struct wtap_pkthdr phdr_ = cap_file_->capFile()->phdr;
    packet_data_ = (guint8 *) g_memdup(ws_buffer_start_ptr(&(cap_file_->capFile()->buf)), fi_->cap_len);

    /* proto tree, visible. We need a proto tree if there's custom columns */
    epan_dissect_init(&edt_, cap_file_->capFile()->epan, TRUE, TRUE);
    col_custom_prime_edt(&edt_, &(cap_file_->capFile()->cinfo));

    epan_dissect_run(&edt_, cap_file_->capFile()->cd_t, &phdr_,
                     frame_tvbuff_new(&cap_file_->capFile()->provider, fi_, packet_data_),
                     fi_, &(cap_file_->capFile()->cinfo));
    epan_dissect_fill_in_columns(&edt_, TRUE, TRUE);
}

FrameInformation::~FrameInformation()
{
    epan_dissect_cleanup(&edt_);
    delete(packet_data_);
}

bool FrameInformation::isValid()
{
    bool ret = false;

    if ( fi_ && cap_file_ && edt_.tvb )
    {
        ret = true;
    }

    return ret;
}

frame_data * FrameInformation::frameData() const
{
    return fi_;
}

int FrameInformation::frameNum() const
{
    if ( ! fi_ )
        return -1;
    return fi_->num;
}

const QByteArray FrameInformation::printableData()
{
    QByteArray data;

    if ( fi_ )
    {
        int rem_length = tvb_captured_length(edt_.tvb);

        uint8_t * dataSet = (uint8_t *)tvb_memdup(wmem_file_scope(), edt_.tvb, 0, rem_length );
        data = QByteArray::fromRawData((char *)dataSet, rem_length);
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
