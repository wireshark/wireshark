/* byte_view_tab.cpp
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

#include "byte_view_tab.h"

#include <QApplication>
#include <QClipboard>
#include <QMimeData>
#include <QTabBar>

#include "cfile.h"
#include "epan/epan_dissect.h"
#include "epan/tvbuff-int.h"

#include <wireshark_application.h>

#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/widgets/byte_view_text.h>

#define tvb_data_property "tvb_data_property"

// To do:
// - We might want to add a callback to free_data_sources in so that we
//   don't have to blindly call clear().

ByteViewTab::ByteViewTab(QWidget *parent) :
    QTabWidget(parent),
    cap_file_(0)
{
    setAccessibleName(tr("Packet bytes"));
    setTabPosition(QTabWidget::South);
    setDocumentMode(true);

    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(connectToMainWindow()));
}

void ByteViewTab::connectToMainWindow()
{
    connect(this, SIGNAL(fieldSelected(FieldInformation *)),
            wsApp->mainWindow(), SIGNAL(fieldSelected(FieldInformation *)));
    connect(this, SIGNAL(fieldHighlight(FieldInformation *)),
            wsApp->mainWindow(), SIGNAL(fieldHighlight(FieldInformation *)));

    /* Connect change of packet selection */
    connect(wsApp->mainWindow(), SIGNAL(frameSelected(int)), this, SLOT(selectedFrameChanged(int)));
    connect(wsApp->mainWindow(), SIGNAL(setCaptureFile(capture_file*)), this, SLOT(setCaptureFile(capture_file*)));
    connect(wsApp->mainWindow(), SIGNAL(fieldSelected(FieldInformation *)), this, SLOT(selectedFieldChanged(FieldInformation *)));

    connect(wsApp->mainWindow(), SIGNAL(captureActive(int)), this, SLOT(captureActive(int)));
}

void ByteViewTab::captureActive(int cap)
{
    if ( cap == 0 )
    {
        QList<ByteViewText *> allBVTs = findChildren<ByteViewText *>();
        if ( allBVTs.count() > 0 )
        {
            ByteViewText * bvt = allBVTs.at(0);
            tvbuff_t * stored = VariantPointer<tvbuff_t>::asPtr(bvt->property(tvb_data_property));

            if ( ! stored )
                selectedFrameChanged(-1);
        }
    }
}

void ByteViewTab::addTab(const char *name, tvbuff_t *tvb) {
    if (count() == 1) { // Remove empty placeholder.
        ByteViewText *cur_text = qobject_cast<ByteViewText *>(currentWidget());
        if (cur_text && cur_text->isEmpty()) delete currentWidget();
    }

    packet_char_enc encoding = PACKET_CHAR_ENC_CHAR_ASCII;
    if ( cap_file_ && cap_file_->current_frame )
        encoding = (packet_char_enc)cap_file_->current_frame->flags.encoding;

    QByteArray data;
    if ( tvb )
        data = QByteArray((const char *) tvb_memdup(wmem_file_scope(), tvb, 0, -1), tvb_captured_length(tvb));

    ByteViewText * byte_view_text = new ByteViewText(data, encoding, this);
    byte_view_text->setAccessibleName(name);
    byte_view_text->setMonospaceFont(wsApp->monospaceFont(true));

    if ( tvb )
    {
        byte_view_text->setProperty(tvb_data_property, VariantPointer<tvbuff_t>::asQVariant(tvb));

        connect(wsApp, SIGNAL(zoomMonospaceFont(QFont)), byte_view_text, SLOT(setMonospaceFont(QFont)));

        connect(byte_view_text, SIGNAL(byteHovered(int)), this, SLOT(byteViewTextHovered(int)));
        connect(byte_view_text, SIGNAL(byteSelected(int)), this, SLOT(byteViewTextMarked(int)));
    }

    int idx = QTabWidget::addTab(byte_view_text, name);
    byte_view_text->setProperty("tab_index", QVariant::fromValue(idx));

    QTabWidget::setTabToolTip(idx, name);
}

void ByteViewTab::byteViewTextHovered(int idx)
{
    if ( idx >= 0 && cap_file_ && cap_file_->edt )
    {
        tvbuff_t * tvb = VariantPointer<tvbuff_t>::asPtr(sender()->property(tvb_data_property));
        proto_tree * tree = cap_file_->edt->tree;

        if ( tvb && tree )
        {
            field_info * fi = proto_find_field_from_offset(tree, idx, tvb);
            if ( fi )
            {
                FieldInformation finfo(fi, this);
                highlightedFieldChanged(&finfo);
                emit fieldHighlight(&finfo);
                return;
            }
        }
    }

    emit fieldHighlight((FieldInformation *)0);
}

void ByteViewTab::byteViewTextMarked(int idx)
{
    if ( idx >= 0 && cap_file_ && cap_file_->edt )
    {
        tvbuff_t * tvb = VariantPointer<tvbuff_t>::asPtr(sender()->property(tvb_data_property));
        proto_tree * tree = cap_file_->edt->tree;

        if ( tvb && tree )
        {
            field_info * fi = proto_find_field_from_offset(tree, idx, tvb);
            if ( fi )
            {
                FieldInformation finfo(fi, this);
                emit fieldSelected(&finfo);
                return;
            }
        }
    }

    emit fieldSelected((FieldInformation *)0);
}

ByteViewText * ByteViewTab::findByteViewTextForTvb(tvbuff_t * search_tvb, int * idx)
{

    ByteViewText * item = 0;
    if ( ! search_tvb )
        return item;

    bool found = false;

    QList<ByteViewText *> allBVTs = findChildren<ByteViewText *>();
    unsigned int length = search_tvb->length;
    for (int i = 0; i < allBVTs.size() && ! found; ++i)
    {
        ByteViewText * bvt = allBVTs.at(i);
        tvbuff_t * stored = VariantPointer<tvbuff_t>::asPtr(bvt->property(tvb_data_property));
        if ( stored == search_tvb )
        {
            found = true;
        }
        else if ( stored )
        {
            if ( stored->length >= length && tvb_memeql(search_tvb, 0, tvb_get_ptr(stored, 0, length), length ) == 0 )
            {
                /* In packetDialog we do not match, because we came from different data sources.
                 * Assuming the capture files match, this should be a sufficient enough difference */
                found = true;
            }
        }

        if ( found )
        {
            int wdgIdx = bvt->property("tab_index").toInt();
            if ( idx )
            {
                *idx = wdgIdx;
            }
            item = (ByteViewText *)widget(wdgIdx);
        }
    }

    return item;
}

void ByteViewTab::tabInserted(int tab_index) {
    setTabsVisible();
    QTabWidget::tabInserted(tab_index);
}

void ByteViewTab::tabRemoved(int tab_index) {
    setTabsVisible();
    QTabWidget::tabRemoved(tab_index);
}

void ByteViewTab::setTabsVisible() {
    if (count() > 1)
        tabBar()->show();
    else
        tabBar()->hide();
}

void ByteViewTab::selectedFrameChanged(int frameNum)
{
    clear();
    qDeleteAll(findChildren<ByteViewText *>());

    if ( frameNum >= 0 )
    {
        if ( ! cap_file_ || ! cap_file_->edt )
            return;

        /* This code relies on a dissection, which had happened somewhere else. It also does not
         * really check, if the dissection happened for the correct frame. In the future we might
         * rewrite this for directly calling the dissection engine here. */
        GSList *src_le;
        for (src_le = cap_file_->edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
            struct data_source *source;
            char* source_name;
            source = (struct data_source *)src_le->data;
            source_name = get_data_source_name(source);
            addTab(source_name, get_data_source_tvb(source));
            wmem_free(NULL, source_name);
        }
    }
    else
        addTab("PlaceHolder", 0);

    setCurrentIndex(0);
}

void ByteViewTab::selectedFieldChanged(FieldInformation *selected)
{
    ByteViewText * byte_view_text = 0;

    if (selected) {
        if (selected->parent() == this) {
            // We only want inbound signals.
            return;
        }
        const field_info *fi = selected->fieldInfo();

        int idx = 0;
        if ( fi )
            byte_view_text = findByteViewTextForTvb(fi->ds_tvb, &idx);

        if (byte_view_text)
        {
            int f_start = -1, f_length = -1;

            if (cap_file_->search_in_progress && (cap_file_->hex || (cap_file_->string && cap_file_->packet_data))) {
                // In the hex view, only highlight the target bytes or string. The entire
                // field can then be displayed by clicking on any of the bytes in the field.
                f_start = cap_file_->search_pos - cap_file_->search_len + 1;
                f_length = (int) cap_file_->search_len;
            } else {
                f_start = selected->position().start;
                f_length = selected->position().length;
            }

            setCurrentIndex(idx);

            byte_view_text->markField(f_start, f_length);
            byte_view_text->markProtocol(selected->parentField()->position().start, selected->parentField()->position().length);
            byte_view_text->markAppendix(selected->appendix().start, selected->appendix().length);
        }
    }
}

void ByteViewTab::highlightedFieldChanged(FieldInformation *highlighted)
{
    ByteViewText * byte_view_text = qobject_cast<ByteViewText *>(currentWidget());
    if (!highlighted || !byte_view_text) {
        return;
    }

    int f_start = -1, f_length = -1;

    if (cap_file_->search_in_progress && (cap_file_->hex || (cap_file_->string && cap_file_->packet_data))) {
        // In the hex view, only highlight the target bytes or string. The entire
        // field can then be displayed by clicking on any of the bytes in the field.
        f_start = cap_file_->search_pos - cap_file_->search_len + 1;
        f_length = (int) cap_file_->search_len;
    } else {
        f_start = highlighted->position().start;
        f_length = highlighted->position().length;
    }

    byte_view_text->markField(f_start, f_length, false);
    byte_view_text->markProtocol(-1, -1);
    byte_view_text->markAppendix(-1, -1);
}

void ByteViewTab::setCaptureFile(capture_file *cf)
{
    selectedFrameChanged(-1);

    cap_file_ = cf;
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
