/* frame_information.h
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

    QByteArray printableData();

private:

    frame_data * fi_;
    CaptureFile * cap_file_;
    guint8 *packet_data_;
    epan_dissect_t edt_;

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
