/* data_source_tab.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "data_source_tab.h"

#include <QApplication>
#include <QClipboard>
#include <QMimeData>
#include <QTabBar>

#include "cfile.h"

#include <app/application_flavor.h>

#include <main_application.h>

#include <ui/qt/main_window.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/widgets/hex_data_source_view.h>
#include <ui/qt/widgets/json_data_source_view.h>

#if QT_VERSION >= QT_VERSION_CHECK(6, 3, 0) && QT_VERSION < QT_VERSION_CHECK(6, 10, 1)
// Short-circuit minimumTabSizeHint and tabSizeHint if the TabBar is not visible
// to workaround https://bugreports.qt.io/browse/QTBUG-141187
// The real fix is in Qt 6.10.1 and later.
class DataSourceTabBar : public QTabBar
{
    Q_OBJECT

public:
    explicit DataSourceTabBar(QWidget *parent = nullptr);

protected:
    virtual QSize minimumTabSizeHint(int) const override;
    virtual QSize tabSizeHint(int) const override;
};

DataSourceTabBar::DataSourceTabBar(QWidget *parent) :
    QTabBar(parent) {}

QSize DataSourceTabBar::minimumTabSizeHint(int index) const
{
    if (!isVisible()) {
        return QSize();
    }
    return QTabBar::minimumTabSizeHint(index);
}

QSize DataSourceTabBar::tabSizeHint(int index) const
{
    if (!isVisible()) {
        return QSize();
    }
    return QTabBar::tabSizeHint(index);
}
#endif

DataSourceTab::DataSourceTab(QWidget *parent, epan_dissect_t *edt_fixed) :
    QTabWidget(parent),
    cap_file_(0),
    is_fixed_packet_(edt_fixed != NULL),
    edt_(edt_fixed),
    disable_hover_(false)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 3, 0) && QT_VERSION < QT_VERSION_CHECK(6, 10, 1)
    setTabBar(new DataSourceTabBar(this));
#endif
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
        connect(mainApp, &MainApplication::appInitialized, this, &DataSourceTab::connectToMainWindow);
    }
}

// Connects the byte view with the main window, acting on changes to the packet
// list selection. It MUST NOT be used with the packet dialog as that is
// independent of the selection in the packet list.
void DataSourceTab::connectToMainWindow()
{
    connect(this, &DataSourceTab::fieldSelected, mainApp->mainWindow(), &MainWindow::fieldSelected);
    connect(this, &DataSourceTab::fieldHighlight, mainApp->mainWindow(), &MainWindow::fieldHighlight);

    /* Connect change of packet selection */
    connect(mainApp->mainWindow(), &MainWindow::framesSelected, this, &DataSourceTab::DataSourceTab::selectedFrameChanged);
    connect(mainApp->mainWindow(), &MainWindow::setCaptureFile, this, &DataSourceTab::setCaptureFile);
    connect(mainApp->mainWindow(), &MainWindow::fieldSelected, this, &DataSourceTab::selectedFieldChanged);

    connect(mainApp->mainWindow(), &MainWindow::captureActive, this, &DataSourceTab::captureActive);
}

void DataSourceTab::captureActive(int cap)
{
    if (cap == 0)
    {
        QList<HexDataSourceView *> allBVTs = findChildren<HexDataSourceView *>();
        if (allBVTs.count() > 0)
        {
            HexDataSourceView * bvt = allBVTs.at(0);
            tvbuff_t * stored = bvt->tvb();

            if (! stored)
                selectedFrameChanged(QList<int>());
        }
    }
}

void DataSourceTab::addTab(const char *name, const struct data_source *source)
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

        data_source_view = new HexDataSourceView(data, encoding, this);
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
            connect(this, &DataSourceTab::detachData, data_source_view, &BaseDataSourceView::detachData);
        }
        // See above - this tvb is (expected to be) scoped to the packet, but
        // the real data is not necessarily so. If this is a PacketDialog
        // and such a secondary data source, then we MUST NOT use any tvb
        // function that accesses the real data after the capture file closes.
        // That includes via the ds_tvb item of a field_info in the tree.
        // proto_find_field_from_offset() is OK. See #14363.
        //
        // XXX: It sounds appealing to clone the secondary data source tvbs
        // and set them to be freed when the hex_data_source_view is freed, perhaps
        // even doing so only when the capture file is closing. However, while
        // relatively simple for the few number of secondary data sources, it
        // would be a pain to change the pointers for every field_info.
        data_source_view->setTvb(tvb);

        connect(mainApp, &MainApplication::zoomMonospaceFont, data_source_view, &BaseDataSourceView::setMonospaceFont);
        connect(data_source_view, &HexDataSourceView::byteSelected, this, &DataSourceTab::byteViewTextMarked);

        if (HexDataSourceView *hex_data_source_view = qobject_cast<HexDataSourceView *>(data_source_view)) {
            connect(hex_data_source_view, &HexDataSourceView::byteHovered, this, &DataSourceTab::byteViewTextHovered);
            connect(hex_data_source_view, &HexDataSourceView::byteViewSettingsChanged, this, &DataSourceTab::byteViewSettingsChanged);
            connect(this, &DataSourceTab::byteViewSettingsChanged, hex_data_source_view, &HexDataSourceView::updateByteViewSettings);
            connect(this, &DataSourceTab::byteViewUnmarkField, hex_data_source_view, &HexDataSourceView::unmarkField);
        }
    }

    int idx = QTabWidget::addTab(data_source_view, name);
    data_source_view->setTabIndex(idx);

    QTabWidget::setTabToolTip(idx, name);
}

void DataSourceTab::byteViewTextHovered(int idx)
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

void DataSourceTab::byteViewTextMarked(int idx)
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

BaseDataSourceView *DataSourceTab::findDataSourceViewForTvb(tvbuff_t * search_tvb, int * idx)
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

void DataSourceTab::tabInserted(int tab_index) {
    setTabsVisible();
    QTabWidget::tabInserted(tab_index);
}

void DataSourceTab::tabRemoved(int tab_index) {
    setTabsVisible();
    QTabWidget::tabRemoved(tab_index);
}

void DataSourceTab::setTabsVisible() {
    if (count() > 1)
        tabBar()->show();
    else
        tabBar()->hide();
}

void DataSourceTab::selectedFrameChanged(QList<int> frames)
{
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

    /* We don't need to call clear() on Linux because Qt will remove the child
     * widgets when they're deleted, but need to on MacOS and maybe Windows.
     * We want to hide the QTabWidget so that the QTabBar doesn't calculate
     * the sizeHint for each tab remaining every time a tab is removed, instead
     * deferring until later. */
    /* !isHidden and isVisible are different; during startup this widget might
     * not be visible because its parent is not (i.e., the Welcome Screen is
     * being shown instead), but whether it's hidden or not is set by the layout
     * regardless. */
    bool save_hidden = isHidden();
    setVisible(false);
#if QT_VERSION < QT_VERSION_CHECK(6, 8, 2)
    /* Pick up this performance improvement from Qt 6.8.2:
     * https://github.com/qt/qtbase/commit/8717c1752f9b72ac7c028b722f0a068e84e64eca
     * https://github.com/qt/qtbase/commit/828ece4743a0d44f7f37f1a980dec076783a8abe
     */
    int c = count();
    while (c)
        removeTab(--c);
#else
    clear();
#endif
    qDeleteAll(findChildren<BaseDataSourceView *>(QString(), Qt::FindDirectChildrenOnly));
    setVisible(!save_hidden);

    /* only show the bytes for single selections */
    if (frames.count() == 1)
    {
        if (! cap_file_ || ! cap_file_->edt)
            return;

        /* Unfortunately in Qt 6.3 and later adding a tab still causes a
         * relayout thanks to the following commit:
         * https://github.com/qt/qtbase/commit/02164b292f002b051f34a88871145415fad94f32
         * Filed: https://bugreports.qt.io/browse/QTBUG-141187
         */
        setVisible(false);
        /* This code relies on a dissection, which had happened somewhere else. It also does not
         * really check, if the dissection happened for the correct frame. In the future we might
         * rewrite this for directly calling the dissection engine here. */
        GSList *src_le;
        for (src_le = edt_->pi.data_src; src_le != NULL; src_le = src_le->next) {
            struct data_source *source;
            char* source_description;
            source = (struct data_source *)src_le->data;
            source_description = get_data_source_description(source);
            addTab(source_description, source);
            wmem_free(NULL, source_description);
        }
        setVisible(!save_hidden);
    }
    else
        addTab("PlaceHolder", 0);

    setCurrentIndex(0);
}

void DataSourceTab::selectedFieldChanged(FieldInformation *selected)
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
        data_source_view->saveSelected(f_start);
    } else {
        emit byteViewUnmarkField();
    }
}
void DataSourceTab::highlightedFieldChanged(FieldInformation *highlighted)
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

void DataSourceTab::setCaptureFile(capture_file *cf)
{
    selectedFrameChanged(QList<int>());

    cap_file_ = cf;
}

void DataSourceTab::captureFileClosing()
{
    emit detachData();
}

#if QT_VERSION >= QT_VERSION_CHECK(6, 3, 0) && QT_VERSION < QT_VERSION_CHECK(6, 10, 1)
#include "data_source_tab.moc"
#endif
