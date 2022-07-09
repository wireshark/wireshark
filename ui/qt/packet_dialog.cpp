/* packet_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_dialog.h"
#include <ui_packet_dialog.h>

#include "file.h"

#include "epan/column.h"
#include "epan/ftypes/ftypes.h"
#include "epan/prefs.h"
#include "ui/preference_utils.h"

#include "frame_tvbuff.h"

#include <wsutil/utf8_entities.h>

#include "byte_view_tab.h"
#include "proto_tree.h"
#include "main_application.h"

#include <ui/qt/utils/field_information.h>
#include <QTreeWidgetItemIterator>

// To do:
// - Copy over experimental packet editing code.
// - Fix ElidedText width.

PacketDialog::PacketDialog(QWidget &parent, CaptureFile &cf, frame_data *fdata) :
    WiresharkDialog(parent, cf),
    ui(new Ui::PacketDialog),
    proto_tree_(NULL),
    byte_view_tab_(NULL)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 4 / 5);
    ui->hintLabel->setSmallText();

    wtap_rec_init(&rec_);
    ws_buffer_init(&buf_, 1514);

    edt_.session = NULL;
    edt_.tvb = NULL;
    edt_.tree = NULL;

    memset(&edt_.pi, 0x0, sizeof(edt_.pi));

    setWindowSubtitle(tr("Packet %1").arg(fdata->num));

    if (!cf_read_record(cap_file_.capFile(), fdata, &rec_, &buf_)) {
        reject();
        return;
    }

    /* proto tree, visible. We need a proto tree if there are custom columns */
    epan_dissect_init(&edt_, cap_file_.capFile()->epan, TRUE, TRUE);
    col_custom_prime_edt(&edt_, &(cap_file_.capFile()->cinfo));

    epan_dissect_run(&edt_, cap_file_.capFile()->cd_t, &rec_,
                     frame_tvbuff_new_buffer(&cap_file_.capFile()->provider, fdata, &buf_),
                     fdata, &(cap_file_.capFile()->cinfo));
    epan_dissect_fill_in_columns(&edt_, TRUE, TRUE);

    proto_tree_ = new ProtoTree(ui->packetSplitter, &edt_);
    // Do not call proto_tree_->setCaptureFile, ProtoTree only needs the
    // dissection context.
    proto_tree_->setRootNode(edt_.tree);

    byte_view_tab_ = new ByteViewTab(ui->packetSplitter, &edt_);
    byte_view_tab_->setCaptureFile(cap_file_.capFile());
    byte_view_tab_->selectedFrameChanged(QList<int>() << 0);

    ui->packetSplitter->setStretchFactor(1, 0);

    QStringList col_parts;
    for (int i = 0; i < cap_file_.capFile()->cinfo.num_cols; ++i) {
        // ElidedLabel doesn't support rich text / HTML
        col_parts << QString("%1: %2")
                     .arg(get_column_title(i))
                     .arg(get_column_text(&cap_file_.capFile()->cinfo, i));
    }
    col_info_ = col_parts.join(" " UTF8_MIDDLE_DOT " ");

    ui->hintLabel->setText(col_info_);

    /* Handle preference value correctly */
    Qt::CheckState state = Qt::Checked;
    if (!prefs.gui_packet_details_show_byteview) {
        state = Qt::Unchecked;
        byte_view_tab_->setVisible(false);
    }
    ui->chkShowByteView->setCheckState(state);

    connect(mainApp, SIGNAL(zoomMonospaceFont(QFont)),
            proto_tree_, SLOT(setMonospaceFont(QFont)));

    connect(byte_view_tab_, SIGNAL(fieldSelected(FieldInformation *)),
            proto_tree_, SLOT(selectedFieldChanged(FieldInformation *)));
    connect(proto_tree_, SIGNAL(fieldSelected(FieldInformation *)),
            byte_view_tab_, SLOT(selectedFieldChanged(FieldInformation *)));

    connect(byte_view_tab_, SIGNAL(fieldHighlight(FieldInformation *)),
            this, SLOT(setHintText(FieldInformation *)));

    connect(proto_tree_, SIGNAL(showProtocolPreferences(QString)),
            this, SIGNAL(showProtocolPreferences(QString)));
    connect(proto_tree_, SIGNAL(editProtocolPreference(preference*,pref_module*)),
            this, SIGNAL(editProtocolPreference(preference*,pref_module*)));

    connect(ui->chkShowByteView, &QCheckBox::stateChanged, this, &PacketDialog::viewVisibilityStateChanged);
}

PacketDialog::~PacketDialog()
{
    delete ui;
    epan_dissect_cleanup(&edt_);
    wtap_rec_cleanup(&rec_);
    ws_buffer_free(&buf_);
}

void PacketDialog::captureFileClosing()
{
    QString closed_title = tr("[%1 closed] " UTF8_MIDDLE_DOT " %2")
            .arg(cap_file_.fileName())
            .arg(col_info_);
    ui->hintLabel->setText(closed_title);
    WiresharkDialog::captureFileClosing();
}

void PacketDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_NEW_PACKET_DIALOG);
}

void PacketDialog::setHintText(FieldInformation * finfo)
{
    QString hint;

     if (finfo)
     {
         FieldInformation::Position pos = finfo->position();
         QString field_str;

         if (pos.length < 2) {
             hint = QString(tr("Byte %1")).arg(pos.start);
         } else {
             hint = QString(tr("Bytes %1-%2")).arg(pos.start).arg(pos.start + pos.length - 1);
         }
         hint += QString(": %1 (%2)")
                 .arg(finfo->headerInfo().name)
                 .arg(finfo->headerInfo().abbreviation);
     }
     ui->hintLabel->setText(hint);
}

void PacketDialog::viewVisibilityStateChanged(int state)
{
    byte_view_tab_->setVisible(state == Qt::Checked);

    prefs.gui_packet_details_show_byteview = (state == Qt::Checked ? TRUE : FALSE);
    prefs_main_write();
}
