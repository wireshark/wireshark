/* frame_information.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

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
 edt_(Q_NULLPTR)
{
    wtap_rec_init(&rec_);
    ws_buffer_init(&buf_, 1514);
    loadFrameTree();
}

void FrameInformation::loadFrameTree()
{
    if (! fi_ || ! cap_file_ || !cap_file_->capFile())
        return;

    if (!cf_read_record(cap_file_->capFile(), fi_, &rec_, &buf_))
        return;

    edt_ = g_new0(epan_dissect_t, 1);

    /* proto tree, visible. We need a proto tree if there's custom columns */
    epan_dissect_init(edt_, cap_file_->capFile()->epan, true, true);
    col_custom_prime_edt(edt_, &(cap_file_->capFile()->cinfo));

    epan_dissect_run(edt_, cap_file_->capFile()->cd_t, &rec_,
                     frame_tvbuff_new_buffer(&cap_file_->capFile()->provider, fi_, &buf_),
                     fi_, &(cap_file_->capFile()->cinfo));
    epan_dissect_fill_in_columns(edt_, true, true);
}

FrameInformation::~FrameInformation()
{
    if (edt_) {
        epan_dissect_cleanup(edt_);
        g_free(edt_);
    }
    wtap_rec_cleanup(&rec_);
    ws_buffer_free(&buf_);
}

bool FrameInformation::isValid()
{
    bool ret = false;

    if (fi_ && cap_file_ && edt_ && edt_->tvb)
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
    if (! fi_)
        return -1;
    return fi_->num;
}

const QByteArray FrameInformation::printableData()
{
    if (!fi_ || !edt_)
        return QByteArray();


    int length = tvb_captured_length(edt_->tvb);
    const char *data = (const char *)tvb_get_ptr(edt_->tvb, 0, length);
    return QByteArray(data, length);
}
