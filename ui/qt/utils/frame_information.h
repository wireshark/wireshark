/* frame_information.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FRAME_INFORMATION_H_
#define FRAME_INFORMATION_H_

#include <config.h>

#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include "epan/epan.h"
#include "epan/column.h"
#include "epan/ftypes/ftypes.h"

#include <ui/qt/capture_file.h>

#include "data_printer.h"

#include <QObject>

class FrameInformation : public QObject, public IDataPrintable
{
    Q_OBJECT
    Q_INTERFACES(IDataPrintable)

public:

    explicit FrameInformation(CaptureFile * cfile, frame_data * fi, QObject * parent = Q_NULLPTR);
    virtual ~FrameInformation();

    bool isValid();

    frame_data * frameData() const;
    int frameNum() const;

    const QByteArray printableData();

private:

    frame_data * fi_;
    CaptureFile * cap_file_;
    epan_dissect_t * edt_;
    wtap_rec rec_; /* Record metadata */
    Buffer buf_;   /* Record data */

    void loadFrameTree();

};


#endif // FRAME_INFORMATION_H_

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
