/* proto_tree.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>

#include <ui/qt/proto_tree.h>
#include <ui/qt/models/proto_tree_model.h>

#include <epan/ftypes/ftypes.h>
#include <epan/prefs.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <cfile.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/utils/wireshark_mime_data.h>
#include <ui/qt/widgets/drag_label.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include <ui/qt/show_packet_bytes_dialog.h>
#include <ui/qt/filter_action.h>
#include <ui/all_files_wildcard.h>
#include <ui/alert_box.h>
#include <ui/urls.h>
#include "main_application.h"

#include <QApplication>
#include <QContextMenuEvent>
#include <QDesktopServices>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QScrollBar>
#include <QStack>
#include <QUrl>
#include <QClipboard>
#include <QWindow>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>

// To do:
// - Fix "apply as filter" behavior.

ProtoTree::ProtoTree(QWidget *parent, epan_dissect_t *edt_fixed) :
    QTreeView(parent),
    proto_tree_model_(new ProtoTreeModel(this)),
    column_resize_timer_(0),
    cap_file_(NULL),
    edt_(edt_fixed)
{
    setAccessibleName(tr("Packet details"));
    // Leave the uniformRowHeights property as-is (false) since items might
    // have multiple lines (e.g. packet comments). If this slows things down
    // too much we should add a custom delegate which handles SizeHintRole
    // similar to PacketListModel::data.
    setHeaderHidden(true);

#if !defined(Q_OS_WIN)
    setStyleSheet(QString(
        "QTreeView:item:hover {"
        "  background-color: %1;"
        "  color: palette(text);"
        "}").arg(ColorUtils::hoverBackground().name(QColor::HexArgb)));
#endif

    // Shrink down to a small but nonzero size in the main splitter.
    int one_em = fontMetrics().height();
    setMinimumSize(one_em, one_em);

    setModel(proto_tree_model_);

    connect(this, SIGNAL(expanded(QModelIndex)), this, SLOT(syncExpanded(QModelIndex)));
    connect(this, SIGNAL(collapsed(QModelIndex)), this, SLOT(syncCollapsed(QModelIndex)));
    connect(this, SIGNAL(clicked(QModelIndex)),
            this, SLOT(itemClicked(QModelIndex)));
    connect(this, SIGNAL(doubleClicked(QModelIndex)),
            this, SLOT(itemDoubleClicked(QModelIndex)));

    connect(&proto_prefs_menu_, SIGNAL(showProtocolPreferences(QString)),
            this, SIGNAL(showProtocolPreferences(QString)));
    connect(&proto_prefs_menu_, SIGNAL(editProtocolPreference(preference*,pref_module*)),
            this, SIGNAL(editProtocolPreference(preference*,pref_module*)));

    // resizeColumnToContents checks 1000 items by default. The user might
    // have scrolled to an area with a different width at this point.
    connect(verticalScrollBar(), SIGNAL(sliderReleased()),
            this, SLOT(updateContentWidth()));

    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(connectToMainWindow()));

    viewport()->installEventFilter(this);
}

void ProtoTree::clear() {
    proto_tree_model_->setRootNode(NULL);
    updateContentWidth();
}

void ProtoTree::connectToMainWindow()
{
    if (mainApp->mainWindow())
    {
        connect(mainApp->mainWindow(), SIGNAL(fieldSelected(FieldInformation *)),
                this, SLOT(selectedFieldChanged(FieldInformation *)));
        connect(mainApp->mainWindow(), SIGNAL(framesSelected(QList<int>)),
                this, SLOT(selectedFrameChanged(QList<int>)));
    }
}

void ProtoTree::ctxCopyVisibleItems()
{
    bool selected_tree = false;

    QAction * send = qobject_cast<QAction *>(sender());
    if (send && send->property("selected_tree").isValid())
        selected_tree = true;

    QString clip;
    if (selected_tree && selectionModel()->hasSelection())
        clip = toString(selectionModel()->selectedIndexes().first());
    else
        clip = toString();

    if (clip.length() > 0)
        mainApp->clipboard()->setText(clip);
}

void ProtoTree::ctxCopyAsFilter()
{
    QModelIndex idx = selectionModel()->selectedIndexes().first();
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(idx).protoNode());
    if (finfo.isValid())
    {
        epan_dissect_t *edt = cap_file_ ? cap_file_->edt : edt_;
        char *field_filter = proto_construct_match_selected_string(finfo.fieldInfo(), edt);
        QString filter(field_filter);
        wmem_free(Q_NULLPTR, field_filter);

        if (filter.length() > 0)
            mainApp->clipboard()->setText(filter);
    }
}

void ProtoTree::ctxCopySelectedInfo()
{
    int val = -1;
    QString clip;
    QAction * send = qobject_cast<QAction *>(sender());
    if (send && send->property("field_type").isValid())
        val = send->property("field_type").toInt();

    QModelIndex idx = selectionModel()->selectedIndexes().first();
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(idx).protoNode());
    if (! finfo.isValid())
        return;

    switch (val)
    {
    case ProtoTree::Name:
        clip.append(finfo.headerInfo().abbreviation);
        break;

    case ProtoTree::Description:
        clip = idx.data(Qt::DisplayRole).toString();
        break;

    case ProtoTree::Value:
        {
            epan_dissect_t *edt = cap_file_ ? cap_file_->edt : edt_;
            gchar* field_str = get_node_field_value(finfo.fieldInfo(), edt);
            clip.append(field_str);
            g_free(field_str);
        }
        break;
    default:
        break;
    }

    if (clip.length() > 0)
        mainApp->clipboard()->setText(clip);
}

void ProtoTree::ctxOpenUrlWiki()
{
    QUrl url;
    bool is_field_reference = false;
    QAction * send = qobject_cast<QAction *>(sender());
    if (send && send->property("field_reference").isValid())
        is_field_reference = send->property("field_reference").toBool();
    QModelIndex idx = selectionModel()->selectedIndexes().first();
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(idx).protoNode());

    int field_id = finfo.headerInfo().id;
    if (!proto_registrar_is_protocol(field_id) && (field_id != hf_text_only)) {
        field_id = proto_registrar_get_parent(field_id);
    }
    const QString proto_abbrev = proto_registrar_get_abbrev(field_id);

    if (! is_field_reference)
    {
        int ret = QMessageBox::question(this, mainApp->windowTitleString(tr("Wiki Page for %1").arg(proto_abbrev)),
                                        tr("<p>The Wireshark Wiki is maintained by the community.</p>"
                                        "<p>The page you are about to load might be wonderful, "
                                        "incomplete, wrong, or nonexistent.</p>"
                                        "<p>Proceed to the wiki?</p>"),
                                        QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);

        if (ret != QMessageBox::Yes) return;

        url = QString(WS_WIKI_URL("%1")).arg(proto_abbrev);
    }
    else
    {
        if (field_id != hf_text_only) {
            url = QString(WS_DOCS_URL "dfref/%1/%2")
                .arg(proto_abbrev[0])
                .arg(proto_abbrev);
        } else {
            QMessageBox::information(this, tr("Not a field or protocol"),
                tr("No field reference available for text labels."),
                QMessageBox::Ok);
        }
    }

    QDesktopServices::openUrl(url);
}

void ProtoTree::contextMenuEvent(QContextMenuEvent *event)
{
    QModelIndex index = indexAt(event->pos());
    if (! index.isValid())
        return;

    // We're in a PacketDialog
    bool buildForDialog = false;
    if (! window()->findChild<QAction *>("actionViewExpandSubtrees"))
        buildForDialog = true;

    QMenu * ctx_menu = new QMenu(this);
    ctx_menu->setAttribute(Qt::WA_DeleteOnClose);
    ctx_menu->setProperty("toolTipsVisible", QVariant::fromValue(true));

    QMenu *main_menu_item, *submenu;
    QAction *action;

    bool have_subtree = false;
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode());
    field_info * fi = finfo.fieldInfo();
    bool is_selected = false;
    epan_dissect_t *edt = cap_file_ ? cap_file_->edt : edt_;

    if (cap_file_ && cap_file_->finfo_selected == fi)
        is_selected = true;
    else if (! window()->findChild<QAction *>("actionViewExpandSubtrees"))
        is_selected = true;

    if (is_selected)
    {
        if (fi && fi->tree_type != -1) {
            have_subtree = true;
        }
    }

    action = ctx_menu->addAction(tr("Expand Subtrees"), this, SLOT(expandSubtrees()));
    action->setEnabled(have_subtree);
    action = ctx_menu->addAction(tr("Collapse Subtrees"), this, SLOT(collapseSubtrees()));
    action->setEnabled(have_subtree);
    ctx_menu->addAction(tr("Expand All"), this, SLOT(expandAll()));
    ctx_menu->addAction(tr("Collapse All"), this, SLOT(collapseAll()));
    ctx_menu->addSeparator();

    if (! buildForDialog)
    {
        action = window()->findChild<QAction *>("actionAnalyzeCreateAColumn");
        ctx_menu->addAction(action);
        ctx_menu->addSeparator();
    }

    char * selectedfilter = proto_construct_match_selected_string(finfo.fieldInfo(), edt);
    bool can_match_selected = proto_can_match_selected(finfo.fieldInfo(), edt);
    ctx_menu->addMenu(FilterAction::createFilterMenu(FilterAction::ActionApply, selectedfilter, can_match_selected, ctx_menu));
    ctx_menu->addMenu(FilterAction::createFilterMenu(FilterAction::ActionPrepare, selectedfilter, can_match_selected, ctx_menu));
    if (selectedfilter)
        wmem_free(Q_NULLPTR, selectedfilter);

    if (! buildForDialog)
    {
        QMenu *main_conv_menu = window()->findChild<QMenu *>("menuConversationFilter");
        conv_menu_.setTitle(main_conv_menu->title());
        conv_menu_.clear();
        foreach (QAction *action, main_conv_menu->actions()) {
            conv_menu_.addAction(action);
        }

        ctx_menu->addMenu(&conv_menu_);

        colorize_menu_.setTitle(tr("Colorize with Filter"));
        ctx_menu->addMenu(&colorize_menu_);

        main_menu_item = window()->findChild<QMenu *>("menuFollow");
        submenu = new QMenu(main_menu_item->title(), ctx_menu);
        ctx_menu->addMenu(submenu);
        submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowTCPStream"));
        submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowUDPStream"));
        submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowDCCPStream"));
        submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowTLSStream"));
        submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowHTTPStream"));
        submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowHTTP2Stream"));
        submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowQUICStream"));
        submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowSIPCall"));
        ctx_menu->addSeparator();
    }

    submenu = ctx_menu->addMenu(tr("Copy"));
    submenu->addAction(tr("All Visible Items"), this, SLOT(ctxCopyVisibleItems()));
    action = submenu->addAction(tr("All Visible Selected Tree Items"), this, SLOT(ctxCopyVisibleItems()));
    action->setProperty("selected_tree", QVariant::fromValue(true));
    action = submenu->addAction(tr("Description"), this, SLOT(ctxCopySelectedInfo()));
    action->setProperty("field_type", ProtoTree::Description);
    action = submenu->addAction(tr("Field Name"), this, SLOT(ctxCopySelectedInfo()));
    action->setProperty("field_type", ProtoTree::Name);
    action = submenu->addAction(tr("Value"), this, SLOT(ctxCopySelectedInfo()));
    action->setProperty("field_type", ProtoTree::Value);
    submenu->addSeparator();
    submenu->addAction(tr("As Filter"), this, SLOT(ctxCopyAsFilter()));
    submenu->addSeparator();
    QActionGroup * copyEntries = DataPrinter::copyActions(this, &finfo);
    submenu->addActions(copyEntries->actions());
    ctx_menu->addSeparator();

    if (! buildForDialog)
    {
        action = window()->findChild<QAction *>("actionAnalyzeShowPacketBytes");
        ctx_menu->addAction(action);
        action = window()->findChild<QAction *>("actionFileExportPacketBytes");
        ctx_menu->addAction(action);

        ctx_menu->addSeparator();
    }

    int field_id = finfo.headerInfo().id;
    action = ctx_menu->addAction(tr("Wiki Protocol Page"), this, SLOT(ctxOpenUrlWiki()));
    action->setProperty("toolTip", QString(WS_WIKI_URL("Protocols/%1")).arg(proto_registrar_get_abbrev(field_id)));

    action = ctx_menu->addAction(tr("Filter Field Reference"), this, SLOT(ctxOpenUrlWiki()));
    action->setProperty("field_reference", QVariant::fromValue(true));
    if (field_id != hf_text_only) {
        action->setEnabled(true);
        const QString proto_abbrev = proto_registrar_get_abbrev(field_id);
        action->setProperty("toolTip", QString(WS_DOCS_URL "dfref/%1/%2")
                .arg(proto_abbrev[0])
                .arg(proto_abbrev));
    }
    else {
        action->setEnabled(false);
        action->setProperty("toolTip", tr("No field reference available for text labels."));
    }
    ctx_menu->addMenu(&proto_prefs_menu_);
    ctx_menu->addSeparator();

    if (! buildForDialog)
    {
        QAction *decode_as_ = window()->findChild<QAction *>("actionAnalyzeDecodeAs");
        ctx_menu->addAction(decode_as_);
        decode_as_->setProperty("create_new", QVariant::fromValue(true));

        ctx_menu->addAction(window()->findChild<QAction *>("actionGoGoToLinkedPacket"));
        ctx_menu->addAction(window()->findChild<QAction *>("actionContextShowLinkedPacketInNewWindow"));
    }

    // The "text only" header field will not give preferences for the selected protocol.
    // Use parent in this case.
    proto_node *node = proto_tree_model_->protoNodeFromIndex(index).protoNode();
    while (node && node->finfo && node->finfo->hfinfo && node->finfo->hfinfo->id == hf_text_only)
        node = node->parent;

    FieldInformation pref_finfo(node);
    proto_prefs_menu_.setModule(pref_finfo.moduleName());

    ctx_menu->popup(event->globalPos());
}

void ProtoTree::timerEvent(QTimerEvent *event)
{
    if (event->timerId() == column_resize_timer_) {
        killTimer(column_resize_timer_);
        column_resize_timer_ = 0;
        resizeColumnToContents(0);
    } else {
        QTreeView::timerEvent(event);
    }
}

// resizeColumnToContents checks 1000 items by default. The user might
// have scrolled to an area with a different width at this point.
void ProtoTree::keyReleaseEvent(QKeyEvent *event)
{
    if (event->isAutoRepeat()) return;

    switch(event->key()) {
        case Qt::Key_Up:
        case Qt::Key_Down:
        case Qt::Key_PageUp:
        case Qt::Key_PageDown:
        case Qt::Key_Home:
        case Qt::Key_End:
            updateContentWidth();
            break;
        default:
            break;
    }
}

void ProtoTree::updateContentWidth()
{
    if (column_resize_timer_ == 0) {
        column_resize_timer_ = startTimer(0);
    }
}

void ProtoTree::setMonospaceFont(const QFont &mono_font)
{
    setFont(mono_font);
    update();
}

void ProtoTree::foreachTreeNode(proto_node *node, gpointer proto_tree_ptr)
{
    ProtoTree *tree_view = static_cast<ProtoTree *>(proto_tree_ptr);
    ProtoTreeModel *model = qobject_cast<ProtoTreeModel *>(tree_view->model());
    if (!tree_view || !model) {
        return;
    }

    // Expanded state
    if (tree_expanded(node->finfo->tree_type)) {
        ProtoNode expand_node = ProtoNode(node);
        tree_view->expand(model->indexFromProtoNode(expand_node));
    }

    // Related frames
    if (node->finfo->hfinfo->type == FT_FRAMENUM) {
        ft_framenum_type_t framenum_type = (ft_framenum_type_t)GPOINTER_TO_INT(node->finfo->hfinfo->strings);
        tree_view->emitRelatedFrame(node->finfo->value.value.uinteger, framenum_type);
    }

    proto_tree_children_foreach(node, foreachTreeNode, proto_tree_ptr);
}

// setRootNode sets the new contents for the protocol tree and subsequently
// restores the previously expanded state.
void ProtoTree::setRootNode(proto_node *root_node) {
    // We track item expansion using proto.c:tree_is_expanded.
    // Replace any existing (possibly invalidated) proto tree by the new tree.
    // The expanded state will be reset as well and will be re-expanded below.
    proto_tree_model_->setRootNode(root_node);

    disconnect(this, SIGNAL(expanded(QModelIndex)), this, SLOT(syncExpanded(QModelIndex)));
    proto_tree_children_foreach(root_node, foreachTreeNode, this);
    connect(this, SIGNAL(expanded(QModelIndex)), this, SLOT(syncExpanded(QModelIndex)));

    updateContentWidth();
}

void ProtoTree::emitRelatedFrame(int related_frame, ft_framenum_type_t framenum_type)
{
    emit relatedFrame(related_frame, framenum_type);
}

void ProtoTree::autoScrollTo(const QModelIndex &index)
{
    selectionModel()->setCurrentIndex(index, QItemSelectionModel::ClearAndSelect);
    if (!index.isValid()) {
        return;
    }

    // ensure item is visible (expanding its parents as needed).
    scrollTo(index);
}

// XXX We select the first match, which might not be the desired item.
void ProtoTree::goToHfid(int hfid)
{
    QModelIndex index = proto_tree_model_->findFirstHfid(hfid);
    autoScrollTo(index);
}

void ProtoTree::selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    QTreeView::selectionChanged(selected, deselected);
    if (selected.isEmpty()) {
        emit fieldSelected(0);
        return;
    }

    QModelIndex index = selected.indexes().first();
    saveSelectedField(index);

    // Find and highlight the protocol bytes. select above won't call
    // selectionChanged if the current and selected indexes are the same
    // so we do this here.
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode(), this);
    if (finfo.isValid()) {
        QModelIndex parent = index;
        while (parent.isValid() && parent.parent().isValid()) {
            parent = parent.parent();
        }
        if (parent.isValid()) {
            FieldInformation parent_finfo(proto_tree_model_->protoNodeFromIndex(parent).protoNode());
            finfo.setParentField(parent_finfo.fieldInfo());
        }
        emit fieldSelected(&finfo);
    }
}

void ProtoTree::syncExpanded(const QModelIndex &index) {
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode());
    if (!finfo.isValid()) return;

    /*
     * Nodes with "finfo->tree_type" of -1 have no ett_ value, and
     * are thus presumably leaf nodes and cannot be expanded.
     */
    if (finfo.treeType() != -1) {
        tree_expanded_set(finfo.treeType(), TRUE);
    }
}

void ProtoTree::syncCollapsed(const QModelIndex &index) {
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode());
    if (!finfo.isValid()) return;

    /*
     * Nodes with "finfo->tree_type" of -1 have no ett_ value, and
     * are thus presumably leaf nodes and cannot be collapsed.
     */
    if (finfo.treeType() != -1) {
        tree_expanded_set(finfo.treeType(), FALSE);
    }
}

void ProtoTree::expandSubtrees()
{
    if (!selectionModel()->hasSelection()) return;

    QStack<QModelIndex> index_stack;
    index_stack.push(selectionModel()->selectedIndexes().first());

    while (!index_stack.isEmpty()) {
        QModelIndex index = index_stack.pop();
        expand(index);
        int row_count = proto_tree_model_->rowCount(index);
        for (int row = row_count - 1; row >= 0; row--) {
            QModelIndex child = proto_tree_model_->index(row, 0, index);
            if (proto_tree_model_->hasChildren(child)) {
                index_stack.push(child);
            }
        }
    }

    updateContentWidth();
}

void ProtoTree::collapseSubtrees()
{
    if (!selectionModel()->hasSelection()) return;

    QStack<QModelIndex> index_stack;
    index_stack.push(selectionModel()->selectedIndexes().first());

    while (!index_stack.isEmpty()) {
        QModelIndex index = index_stack.pop();
        collapse(index);
        int row_count = proto_tree_model_->rowCount(index);
        for (int row = row_count - 1; row >= 0; row--) {
            QModelIndex child = proto_tree_model_->index(row, 0, index);
            if (proto_tree_model_->hasChildren(child)) {
                index_stack.push(child);
            }
        }
    }

    updateContentWidth();
}

void ProtoTree::expandAll()
{
    for (int i = 0; i < num_tree_types; i++) {
        tree_expanded_set(i, TRUE);
    }
    QTreeView::expandAll();
    updateContentWidth();
}

void ProtoTree::collapseAll()
{
    for (int i = 0; i < num_tree_types; i++) {
        tree_expanded_set(i, FALSE);
    }
    QTreeView::collapseAll();
    updateContentWidth();
}

void ProtoTree::itemClicked(const QModelIndex &index)
{
    if (selectionModel()->selectedIndexes().isEmpty()) {
        emit fieldSelected(0);
    } else if (index == selectionModel()->selectedIndexes().first()) {
        FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode());

        if (finfo.isValid()) {
            emit fieldSelected(&finfo);
        }
    }
}

void ProtoTree::itemDoubleClicked(const QModelIndex &index)
{
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode());
    if (!finfo.isValid()) return;

    if (finfo.headerInfo().type == FT_FRAMENUM) {
        if (QApplication::queryKeyboardModifiers() & Qt::ShiftModifier) {
            emit openPacketInNewWindow(true);
        } else {
            mainApp->gotoFrame(finfo.fieldInfo()->value.value.uinteger);
        }
    } else {
        QString url = finfo.url();
        if (!url.isEmpty()) {
            QApplication::clipboard()->setText(url);
            QString push_msg = tr("Copied ") + url;
            mainApp->pushStatus(MainApplication::TemporaryStatus, push_msg);
        }
    }
}

void ProtoTree::selectedFrameChanged(QList<int> frames)
{
    if (frames.count() == 1 && cap_file_ && cap_file_->edt && cap_file_->edt->tree) {
        setRootNode(cap_file_->edt->tree);
    } else {
        // Clear the proto tree contents as they have become invalid.
        proto_tree_model_->setRootNode(NULL);
    }
}

// Select a field and bring it into view. Intended to be called by external
// components (such as the byte view).
void ProtoTree::selectedFieldChanged(FieldInformation *finfo)
{
    if (finfo && finfo->parent() == this) {
        // We only want inbound signals.
        return;
    }

    QModelIndex index = proto_tree_model_->findFieldInformation(finfo);
    setUpdatesEnabled(false);
    // The new finfo might match the current index. Clear our selection
    // so that we force a fresh item selection, so that fieldSelected
    // will in turn be emitted.
    selectionModel()->clearSelection();
    autoScrollTo(index);
    setUpdatesEnabled(true);
}

// Remember the currently focussed field based on:
// - current hf_id (obviously)
// - parent items (to avoid selecting a text item in a different tree)
// - the row of each item
void ProtoTree::saveSelectedField(QModelIndex &index)
{
    selected_hfid_path_.clear();
    QModelIndex save_index = index;
    while (save_index.isValid()) {
        FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(save_index).protoNode());
        if (!finfo.isValid()) break;
        selected_hfid_path_.prepend(QPair<int,int>(save_index.row(), finfo.headerInfo().id));
        save_index = save_index.parent();
    }
}

// Try to focus a tree item which was previously also visible
void ProtoTree::restoreSelectedField()
{
    if (selected_hfid_path_.isEmpty()) return;

    QModelIndex cur_index = QModelIndex();
    QPair<int,int> path_entry;
    foreach (path_entry, selected_hfid_path_) {
        int row = path_entry.first;
        int hf_id = path_entry.second;
        cur_index = proto_tree_model_->index(row, 0, cur_index);
        FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(cur_index).protoNode());
        if (!finfo.isValid() || finfo.headerInfo().id != hf_id) {
            // Did not find the selected hfid path in the selected packet
            cur_index = QModelIndex();
            emit fieldSelected(0);
            break;
        }
    }

    autoScrollTo(cur_index);
}

QString ProtoTree::traverseTree(const QModelIndex & travTree, int identLevel) const
{
    QString result = "";

    if (travTree.isValid())
    {
        result.append(QString("    ").repeated(identLevel));
        result.append(travTree.data().toString());
        result.append("\n");

        /* if the element is expanded, we traverse one level down */
        if (isExpanded(travTree))
        {
            int children = proto_tree_model_->rowCount(travTree);
            identLevel++;
            for (int child = 0; child < children; child++)
                result += traverseTree(proto_tree_model_->index(child, 0, travTree), identLevel);
        }
    }

    return result;
}

QString ProtoTree::toString(const QModelIndex &start_idx) const
{
    QString tree_string = "";
    if (start_idx.isValid())
        tree_string = traverseTree(start_idx, 0);
    else
    {
        int children = proto_tree_model_->rowCount();
        for (int child = 0; child < children; child++)
            tree_string += traverseTree(proto_tree_model_->index(child, 0, QModelIndex()), 0);
    }

    return tree_string;
}

void ProtoTree::setCaptureFile(capture_file *cf)
{
    // For use by the main view, set the capture file which will later have a
    // dissection (EDT) ready.
    // The packet dialog sets a fixed EDT context and MUST NOT use this.
    Q_ASSERT(edt_ == NULL);
    cap_file_ = cf;
}

bool ProtoTree::eventFilter(QObject * obj, QEvent * event)
{
    if (event->type() != QEvent::MouseButtonPress && event->type() != QEvent::MouseMove)
        return QTreeView::eventFilter(obj, event);

    /* Mouse was over scrollbar, ignoring */
    if (qobject_cast<QScrollBar *>(obj))
        return QTreeView::eventFilter(obj, event);

    if (event->type() == QEvent::MouseButtonPress)
    {
        QMouseEvent * ev = (QMouseEvent *)event;

        if (ev->buttons() & Qt::LeftButton)
            drag_start_position_ = ev->pos();
    }
    else if (event->type() == QEvent::MouseMove)
    {
        QMouseEvent * ev = (QMouseEvent *)event;

        if ((ev->buttons() & Qt::LeftButton) && (ev->pos() - drag_start_position_).manhattanLength()
                 > QApplication::startDragDistance())
        {
            QModelIndex idx = indexAt(drag_start_position_);
            FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(idx).protoNode());
            if (finfo.isValid())
            {
                /* Hack to prevent QItemSelection taking the item which has been dragged over at start
                 * of drag-drop operation. selectionModel()->blockSignals could have done the trick, but
                 * it does not take in a QTreeWidget (maybe View) */
                emit fieldSelected(&finfo);
                selectionModel()->select(idx, QItemSelectionModel::ClearAndSelect);

                epan_dissect_t *edt = cap_file_ ? cap_file_->edt : edt_;
                char *field_filter = proto_construct_match_selected_string(finfo.fieldInfo(), edt);
                QString filter(field_filter);
                wmem_free(NULL, field_filter);

                if (filter.length() > 0)
                {
                    QJsonObject filterData;
                    filterData["filter"] = filter;
                    filterData["name"] = finfo.headerInfo().abbreviation;
                    filterData["description"] = finfo.headerInfo().name;
                    QMimeData * mimeData = new QMimeData();

                    mimeData->setData(WiresharkMimeData::DisplayFilterMimeType, QJsonDocument(filterData).toJson());
                    mimeData->setText(toString(idx));

                    QDrag * drag = new QDrag(this);
                    drag->setMimeData(mimeData);

                    QString lblTxt = QString("%1\n%2").arg(finfo.headerInfo().name, filter);

                    DragLabel * content = new DragLabel(lblTxt, this);

                    qreal dpr = window()->windowHandle()->devicePixelRatio();
                    QPixmap pixmap(content->size() * dpr);
                    pixmap.setDevicePixelRatio(dpr);
                    content->render(&pixmap);
                    drag->setPixmap(pixmap);

                    drag->exec(Qt::CopyAction);

                    return true;
                }
            }
        }
    }

    return QTreeView::eventFilter(obj, event);
}

QModelIndex ProtoTree::moveCursor(QAbstractItemView::CursorAction cursorAction, Qt::KeyboardModifiers modifiers)
{
    if (cursorAction == MoveLeft && selectionModel()->hasSelection()) {
        QModelIndex cur_idx = selectionModel()->selectedIndexes().first();
        QModelIndex parent = cur_idx.parent();
        if (!isExpanded(cur_idx) && parent.isValid() && parent != rootIndex()) {
            return parent;
        }
    }
    return QTreeView::moveCursor(cursorAction, modifiers);
}
