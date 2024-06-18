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
#include "epan/prefs-int.h"
#include "ui/preference_utils.h"

#include "frame_tvbuff.h"

#include <wsutil/utf8_entities.h>

#include "byte_view_tab.h"
#include "proto_tree.h"
#include "main_application.h"

#include <ui/qt/utils/field_information.h>
#include <QTreeWidgetItemIterator>

Q_DECLARE_METATYPE(splitter_layout_e)

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
    ui->prefsLayout->insertSpacing(1, 20);
    ui->prefsLayout->addStretch();

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
    epan_dissect_init(&edt_, cap_file_.capFile()->epan, true, true);
    col_custom_prime_edt(&edt_, &(cap_file_.capFile()->cinfo));

    epan_dissect_run(&edt_, cap_file_.capFile()->cd_t, &rec_,
                     frame_tvbuff_new_buffer(&cap_file_.capFile()->provider, fdata, &buf_),
                     fdata, &(cap_file_.capFile()->cinfo));
    epan_dissect_fill_in_columns(&edt_, true, true);

    proto_tree_ = new ProtoTree(ui->packetSplitter, &edt_);
    // Do not call proto_tree_->setCaptureFile, ProtoTree only needs the
    // dissection context.
    proto_tree_->setRootNode(edt_.tree);

    byte_view_tab_ = new ByteViewTab(ui->packetSplitter, &edt_);
    byte_view_tab_->setCaptureFile(cap_file_.capFile());
    byte_view_tab_->selectedFrameChanged(QList<int>() << 0);

    // We have to load the splitter state after adding the proto tree
    // and byte view.
    loadSplitterState(ui->packetSplitter);

    module_t *gui_module = prefs_find_module("gui");
    if (gui_module != nullptr) {
        pref_packet_dialog_layout_ = prefs_find_preference(gui_module, "packet_dialog_layout");
        if (pref_packet_dialog_layout_ != nullptr) {
            for (const enum_val_t *ev = prefs_get_enumvals(pref_packet_dialog_layout_); ev && ev->description; ev++) {
                ui->layoutComboBox->addItem(ev->description, QVariant(ev->value));
            }
        }
    }
    ui->layoutComboBox->setCurrentIndex(ui->layoutComboBox->findData(QVariant(prefs.gui_packet_dialog_layout)));
    Qt::Orientation pref_orientation = Qt::Vertical;
    switch(prefs.gui_packet_dialog_layout) {
    case(layout_vertical):
        pref_orientation = Qt::Vertical;
        break;
    case(layout_horizontal):
        pref_orientation = Qt::Horizontal;
        break;
    }

    if (ui->packetSplitter->orientation() != pref_orientation) {
        ui->packetSplitter->setOrientation(pref_orientation);
        // If the orientation is different than the restore one,
        // reset the sizes to 50-50.
        QList<int> sizes = ui->packetSplitter->sizes();
        int totalsize = sizes.at(0) + sizes.at(1);
        sizes[0] = totalsize / 2;
        sizes[1] = totalsize / 2;
        ui->packetSplitter->setSizes(sizes);
    }

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
    ui->layoutComboBox->setEnabled(state);

    connect(mainApp, SIGNAL(zoomMonospaceFont(QFont)),
            proto_tree_, SLOT(setMonospaceFont(QFont)));

    connect(byte_view_tab_, SIGNAL(fieldSelected(FieldInformation *)),
            proto_tree_, SLOT(selectedFieldChanged(FieldInformation *)));
    connect(proto_tree_, SIGNAL(fieldSelected(FieldInformation *)),
            byte_view_tab_, SLOT(selectedFieldChanged(FieldInformation *)));

    connect(byte_view_tab_, SIGNAL(fieldHighlight(FieldInformation *)),
            this, SLOT(setHintText(FieldInformation *)));
    connect(byte_view_tab_, &ByteViewTab::fieldSelected,
            this, &PacketDialog::setHintTextSelected);
    connect(proto_tree_, &ProtoTree::fieldSelected,
            this, &PacketDialog::setHintTextSelected);

    connect(proto_tree_, SIGNAL(showProtocolPreferences(QString)),
            this, SIGNAL(showProtocolPreferences(QString)));
    connect(proto_tree_, SIGNAL(editProtocolPreference(preference*,pref_module*)),
            this, SIGNAL(editProtocolPreference(preference*,pref_module*)));

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    connect(ui->layoutComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &PacketDialog::layoutChanged);
#else
    connect(ui->layoutComboBox, &QComboBox::currentIndexChanged, this, &PacketDialog::layoutChanged, Qt::AutoConnection);
#endif
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
    byte_view_tab_->captureFileClosing();
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
     else {
         hint = col_info_;
     }
     ui->hintLabel->setText(hint);
}

void PacketDialog::setHintTextSelected(FieldInformation* finfo)
{
    QString hint;

    if (finfo)
    {
        FieldInformation::HeaderInfo hInfo = finfo->headerInfo();

        if (hInfo.isValid)
        {
            if (hInfo.description.length() > 0) {
                hint.append(hInfo.description);
            }
            else {
                hint.append(hInfo.name);
            }
        }

        if (!hint.isEmpty()) {
            int finfo_length;
            if (hInfo.isValid)
                hint.append(" (" + hInfo.abbreviation + ")");

            finfo_length = finfo->position().length + finfo->appendix().length;
            if (finfo_length > 0) {
                int finfo_bits = FI_GET_BITS_SIZE(finfo->fieldInfo());
                if (finfo_bits % 8 == 0) {
                    hint.append(", " + tr("%Ln byte(s)", "", finfo_length));
                } else {
                    hint.append(", " + tr("%Ln bit(s)", "", finfo_bits));
                }
            }
        }
    }
    else {
        hint = col_info_;
    }
    ui->hintLabel->setText(hint);
}

void PacketDialog::viewVisibilityStateChanged(int state)
{
    byte_view_tab_->setVisible(state == Qt::Checked);
    ui->layoutComboBox->setEnabled(state == Qt::Checked);

    prefs.gui_packet_details_show_byteview = (state == Qt::Checked ? true : false);
    prefs_main_write();
}

void PacketDialog::layoutChanged(int index _U_)
{
    splitter_layout_e layout = ui->layoutComboBox->currentData().value<splitter_layout_e>();
    switch(layout) {
    case(layout_vertical):
        ui->packetSplitter->setOrientation(Qt::Vertical);
        break;
    case(layout_horizontal):
        ui->packetSplitter->setOrientation(Qt::Horizontal);
        break;
    }
    prefs_set_enum_value(pref_packet_dialog_layout_, layout, pref_current);
}
