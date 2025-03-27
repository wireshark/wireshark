/* byte_view_tab.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "byte_view_tab.h"

#include <QApplication>
#include <QClipboard>
#include <QMimeData>
#include <QTabBar>

#include "cfile.h"

#include <wsutil/application_flavor.h>

#include <main_application.h>

#include <ui/qt/main_window.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/widgets/byte_view_text.h>
#include <ui/qt/widgets/json_data_source_view.h>

// To do:
// - We might want to add a callback to free_data_sources in so that we
//   don't have to blindly call clear().

ByteViewTab::ByteViewTab(QWidget *parent, epan_dissect_t *edt_fixed) :
    QTabWidget(parent),
    cap_file_(0),
    is_fixed_packet_(edt_fixed != NULL),
    edt_(edt_fixed),
    disable_hover_(false)
{
    if (application_flavor_is_wireshark()) {
        setAccessibleName(tr("Packet bytes"));
    } else {
        setAccessibleName(tr("Event data"));
    }
    setTabPosition(QTabWidget::South);
    setDocumentMode(true);

    // Shrink down to a small but nonzero size in the main splitter.
    int one_em = fontMetrics().height();
    setMinimumSize(one_em, one_em);

    if (!edt_fixed) {
        connect(mainApp, &MainApplication::appInitialized, this, &ByteViewTab::connectToMainWindow);
    }
}

// Connects the byte view with the main window, acting on changes to the packet
// list selection. It MUST NOT be used with the packet dialog as that is
// independent of the selection in the packet list.
void ByteViewTab::connectToMainWindow()
{
    connect(this, &ByteViewTab::fieldSelected, mainApp->mainWindow(), &MainWindow::fieldSelected);
    connect(this, &ByteViewTab::fieldHighlight, mainApp->mainWindow(), &MainWindow::fieldHighlight);

    /* Connect change of packet selection */
    connect(mainApp->mainWindow(), &MainWindow::framesSelected, this, &ByteViewTab::ByteViewTab::selectedFrameChanged);
    connect(mainApp->mainWindow(), &MainWindow::setCaptureFile, this, &ByteViewTab::setCaptureFile);
    connect(mainApp->mainWindow(), &MainWindow::fieldSelected, this, &ByteViewTab::selectedFieldChanged);

    connect(mainApp->mainWindow(), &MainWindow::captureActive, this, &ByteViewTab::captureActive);
}

void ByteViewTab::captureActive(int cap)
{
    if (cap == 0)
    {
        QList<ByteViewText *> allBVTs = findChildren<ByteViewText *>();
        if (allBVTs.count() > 0)
        {
            ByteViewText * bvt = allBVTs.at(0);
            tvbuff_t * stored = bvt->tvb();

            if (! stored)
                selectedFrameChanged(QList<int>());
        }
    }
}

void ByteViewTab::addTab(const char *name, const struct data_source *source)
{

    if (count() == 1) { // Remove empty placeholder.
        BaseDataSourceView *cur_view = qobject_cast<BaseDataSourceView *>(currentWidget());
        if (cur_view && cur_view->isEmpty()) delete currentWidget();
    }

    BaseDataSourceView *data_source_view;
    tvbuff_t *tvb = get_data_source_tvb(source);
    QByteArray data;

    if (tvb) {
        int data_len = (int) tvb_captured_length(tvb);
        if (data_len > 0) {
            // Note: this does not copy the data and will be invalidated
            // when the tvbuff's real data becomes invalid (which is not
            // necessarily when the tvb itself becomes invalid.)
            data = QByteArray::fromRawData((const char *) tvb_get_ptr(tvb, 0, data_len), data_len);
        }
    }

    switch (get_data_source_media_type(source)) {
    case DS_MEDIA_TYPE_APPLICATION_JSON:
    {
        proto_node *root_node = nullptr;
        if (cap_file_ && cap_file_->edt && cap_file_->edt->tree) {
            root_node = cap_file_->edt->tree;
        }

        data_source_view = new JsonDataSourceView(data, root_node, this);
    }
        break;
    default:
    {
        packet_char_enc encoding = PACKET_CHAR_ENC_CHAR_ASCII;
        if (cap_file_ && cap_file_->current_frame) {
            encoding = (packet_char_enc)cap_file_->current_frame->encoding;
        }

        data_source_view = new ByteViewText(data, encoding, this);
    }
    }

    data_source_view->setAccessibleName(name);
    data_source_view->setMonospaceFont(mainApp->monospaceFont(true));

    if (tvb)
    {
        // There are some secondary data source tvbuffs whose data is not freed
        // when the epan_dissect_t is freed, but at some other point expected
        // to outlive the packet, generally when the capture file is closed.
        // If this is a PacketDialog, it can break that assumption.
        // To get around this, we deep copy their data when the file is closed.
        //
        // XXX: We could add a function to the tvbuff API and only do this if
        // there is no free_cb (a free_cb implies the data is freed at the
        // same time as the tvb, i.e. when leaving the packet.)
        if (is_fixed_packet_ && count() > 0) {
            connect(this, &ByteViewTab::detachData, data_source_view, &BaseDataSourceView::detachData);
        }
        // See above - this tvb is (expected to be) scoped to the packet, but
        // the real data is not necessarily so. If this is a PacketDialog
        // and such a secondary data source, then we MUST NOT use any tvb
        // function that accesses the real data after the capture file closes.
        // That includes via the ds_tvb item of a field_info in the tree.
        // proto_find_field_from_offset() is OK. See #14363.
        //
        // XXX: It sounds appealing to clone the secondary data source tvbs
        // and set them to be freed when the byte_view_text is freed, perhaps
        // even doing so only when the capture file is closing. However, while
        // relatively simple for the few number of secondary data sources, it
        // would be a pain to change the pointers for every field_info.
        data_source_view->setTvb(tvb);

        connect(mainApp, &MainApplication::zoomMonospaceFont, data_source_view, &BaseDataSourceView::setMonospaceFont);
        connect(data_source_view, &ByteViewText::byteSelected, this, &ByteViewTab::byteViewTextMarked);

        if (ByteViewText *byte_view_text = qobject_cast<ByteViewText *>(data_source_view)) {
            connect(byte_view_text, &ByteViewText::byteHovered, this, &ByteViewTab::byteViewTextHovered);
            connect(byte_view_text, &ByteViewText::byteViewSettingsChanged, this, &ByteViewTab::byteViewSettingsChanged);
            connect(this, &ByteViewTab::byteViewSettingsChanged, byte_view_text, &ByteViewText::updateByteViewSettings);
            connect(this, &ByteViewTab::byteViewUnmarkField, byte_view_text, &ByteViewText::unmarkField);
        }
    }

    int idx = QTabWidget::addTab(data_source_view, name);
    data_source_view->setTabIndex(idx);

    QTabWidget::setTabToolTip(idx, name);
}

void ByteViewTab::byteViewTextHovered(int idx)
{
    if (idx >= 0 && edt_)
    {
        BaseDataSourceView *source = qobject_cast<BaseDataSourceView *>(sender());
        tvbuff_t * tvb = source ? source->tvb() : nullptr;
        proto_tree * tree = edt_->tree;

        if (tvb && tree)
        {
            field_info * fi = proto_find_field_from_offset(tree, idx, tvb);
            if (fi)
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
    if (idx >= 0 && edt_)
    {
        BaseDataSourceView *source = qobject_cast<BaseDataSourceView *>(sender());
        tvbuff_t * tvb = source ? source->tvb() : nullptr;
        proto_tree * tree = edt_->tree;

        if (tvb && tree)
        {
            field_info * fi = proto_find_field_from_offset(tree, idx, tvb);
            if (fi)
            {
                FieldInformation finfo(fi, this);
                emit fieldSelected(&finfo);
                return;
            }
        }
    }

    emit fieldSelected((FieldInformation *)0);
}

BaseDataSourceView *ByteViewTab::findDataSourceViewForTvb(tvbuff_t * search_tvb, int * idx)
{
    if (! search_tvb) {
        return nullptr;
    }

    BaseDataSourceView *item = nullptr;

    QList<BaseDataSourceView *> all_sources = findChildren<BaseDataSourceView *>();
    for (int i = 0; i < all_sources.size() && !item; ++i)
    {
        BaseDataSourceView * dsv = all_sources.at(i);
        tvbuff_t * stored = dsv->tvb();
        if (stored == search_tvb)
        {
            int wdgIdx = dsv->tabIndex();
            if (idx)
            {
                *idx = wdgIdx;
            }
            item = qobject_cast<BaseDataSourceView *>(widget(wdgIdx));
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

void ByteViewTab::selectedFrameChanged(QList<int> frames)
{
    clear();
    qDeleteAll(findChildren<BaseDataSourceView *>());

    if (!is_fixed_packet_) {
        /* If this is not a fixed packet (not the packet dialog), it must be the
         * byte view associated with the packet list. */
        if (cap_file_ && cap_file_->edt) {
            /* Assumes that this function is called as a result of selecting a
             * packet in the packet list (PacketList::selectionChanged). That
             * invokes "cf_select_packet" which will update "cap_file_->edt". */
            edt_ = cap_file_->edt;
        } else {
            /* capture file is closing or packet is deselected. */
            edt_ = NULL;
        }
    }

    /* only show the bytes for single selections */
    if (frames.count() == 1)
    {
        if (! cap_file_ || ! cap_file_->edt)
            return;

        /* This code relies on a dissection, which had happened somewhere else. It also does not
         * really check, if the dissection happened for the correct frame. In the future we might
         * rewrite this for directly calling the dissection engine here. */
        GSList *src_le;
        for (src_le = edt_->pi.data_src; src_le != NULL; src_le = src_le->next) {
            struct data_source *source;
            char* source_name;
            source = (struct data_source *)src_le->data;
            source_name = get_data_source_name(source);
            addTab(source_name, source);
            wmem_free(NULL, source_name);
        }
    }
    else
        addTab("PlaceHolder", 0);

    setCurrentIndex(0);
}

void ByteViewTab::selectedFieldChanged(FieldInformation *selected)
{
    // We need to handle both selection and deselection.
    BaseDataSourceView * data_source_view = qobject_cast<BaseDataSourceView *>(currentWidget());
    int f_start = -1, f_length = -1;
    int p_start = -1, p_length = -1;
    int fa_start = -1, fa_length = -1;

    if (selected) {
        if (selected->parent() == this) {
            // We only want inbound signals.
            return;
        }
        const field_info *fi = selected->fieldInfo();

        int idx = 0;
        if (fi) {
            data_source_view = findDataSourceViewForTvb(fi->ds_tvb, &idx);
        }

        if (cap_file_->search_in_progress && (cap_file_->hex || (cap_file_->string && cap_file_->packet_data))) {
            // In the hex view, only highlight the target bytes or string. The entire
            // field can then be displayed by clicking on any of the bytes in the field.
            f_start = (int)cap_file_->search_pos;
            f_length = (int) cap_file_->search_len;
        } else {
            f_start = selected->position().start;
            f_length = selected->position().length;
        }

        setCurrentIndex(idx);

        FieldInformation *parentField = selected->parentField();

        p_start = parentField->position().start;
        p_length = parentField->position().length;
        fa_start = selected->appendix().start;
        fa_length = selected->appendix().length;

        delete parentField;
    }

    if (data_source_view)
    {
        data_source_view->markField(f_start, f_length);
        data_source_view->markProtocol(p_start, p_length);
        data_source_view->markAppendix(fa_start, fa_length);
    } else {
        emit byteViewUnmarkField();
    }
}
void ByteViewTab::highlightedFieldChanged(FieldInformation *highlighted)
{
    BaseDataSourceView * data_source_view = qobject_cast<BaseDataSourceView *>(currentWidget());
    if (!highlighted || !data_source_view) {
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

    data_source_view->markField(f_start, f_length, false);
    data_source_view->markProtocol(-1, -1);
    data_source_view->markAppendix(-1, -1);
}

void ByteViewTab::setCaptureFile(capture_file *cf)
{
    selectedFrameChanged(QList<int>());

    cap_file_ = cf;
}

void ByteViewTab::captureFileClosing()
{
    emit detachData();
}
