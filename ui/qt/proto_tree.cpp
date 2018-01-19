/* proto_tree.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <stdio.h>

#include "proto_tree.h"
#include <ui/qt/models/proto_tree_model.h>

#include <epan/ftypes/ftypes.h>
#include <epan/prefs.h>

#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/utils/wireshark_mime_data.h>
#include <ui/qt/widgets/drag_label.h>

#include <QApplication>
#include <QContextMenuEvent>
#include <QDesktopServices>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QScrollBar>
#include <QStack>
#include <QUrl>

#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
#include <QWindow>
#endif


// To do:
// - Fix "apply as filter" behavior.

ProtoTree::ProtoTree(QWidget *parent) :
    QTreeView(parent),
    proto_tree_model_(new ProtoTreeModel(this)),
    decode_as_(NULL),
    column_resize_timer_(0),
    cap_file_(NULL)
{
    setAccessibleName(tr("Packet details"));
    // Leave the uniformRowHeights property as-is (false) since items might
    // have multiple lines (e.g. packet comments). If this slows things down
    // too much we should add a custom delegate which handles SizeHintRole
    // similar to PacketListModel::data.
    setHeaderHidden(true);

    setModel(proto_tree_model_);

    connect(this, SIGNAL(expanded(QModelIndex)), this, SLOT(syncExpanded(QModelIndex)));
    connect(this, SIGNAL(collapsed(QModelIndex)), this, SLOT(syncCollapsed(QModelIndex)));
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

    viewport()->installEventFilter(this);
}

void ProtoTree::clear() {
    proto_tree_model_->setRootNode(NULL);
    updateContentWidth();
}

void ProtoTree::closeContextMenu()
{
    ctx_menu_.close();
}

void ProtoTree::contextMenuEvent(QContextMenuEvent *event)
{
    // We're in a PacketDialog
    if (! window()->findChild<QAction *>("actionViewExpandSubtrees"))
        return;

    ctx_menu_.clear();

    QMenu *main_menu_item, *submenu;
    QAction *action;

    ctx_menu_.addAction(window()->findChild<QAction *>("actionViewExpandSubtrees"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionViewCollapseSubtrees"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionViewExpandAll"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionViewCollapseAll"));
    ctx_menu_.addSeparator();

    action = window()->findChild<QAction *>("actionAnalyzeCreateAColumn");
    ctx_menu_.addAction(action);
    ctx_menu_.addSeparator();

    main_menu_item = window()->findChild<QMenu *>("menuApplyAsFilter");
    submenu = new QMenu(main_menu_item->title(), &ctx_menu_);
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFAndSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFOrSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFAndNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFOrNotSelected"));

    main_menu_item = window()->findChild<QMenu *>("menuPrepareAFilter");
    submenu = new QMenu(main_menu_item->title(), &ctx_menu_);
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFAndSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFOrSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFAndNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFOrNotSelected"));

    QMenu *main_conv_menu = window()->findChild<QMenu *>("menuConversationFilter");
    conv_menu_.setTitle(main_conv_menu->title());
    conv_menu_.clear();
    foreach (QAction *action, main_conv_menu->actions()) {
        conv_menu_.addAction(action);
    }

    ctx_menu_.addMenu(&conv_menu_);

    colorize_menu_.setTitle(tr("Colorize with Filter"));
    ctx_menu_.addMenu(&colorize_menu_);

    main_menu_item = window()->findChild<QMenu *>("menuFollow");
    submenu = new QMenu(main_menu_item->title(), &ctx_menu_);
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowTCPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowUDPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowSSLStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowHTTPStream"));
    ctx_menu_.addSeparator();

    main_menu_item = window()->findChild<QMenu *>("menuEditCopy");
    submenu = new QMenu(main_menu_item->title(), &ctx_menu_);
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionCopyAllVisibleItems"));
    submenu->addAction(window()->findChild<QAction *>("actionCopyAllVisibleSelectedTreeItems"));
    submenu->addAction(window()->findChild<QAction *>("actionEditCopyDescription"));
    submenu->addAction(window()->findChild<QAction *>("actionEditCopyFieldName"));
    submenu->addAction(window()->findChild<QAction *>("actionEditCopyValue"));
    submenu->addSeparator();

    submenu->addAction(window()->findChild<QAction *>("actionEditCopyAsFilter"));
    submenu->addSeparator();

    QModelIndex index = indexAt(event->pos());
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode());
    QActionGroup * copyEntries = DataPrinter::copyActions(this, &finfo);
    submenu->addActions(copyEntries->actions());

    action = window()->findChild<QAction *>("actionAnalyzeShowPacketBytes");
    ctx_menu_.addAction(action);
    action = window()->findChild<QAction *>("actionFileExportPacketBytes");
    ctx_menu_.addAction(action);

    ctx_menu_.addSeparator();

    action = window()->findChild<QAction *>("actionContextWikiProtocolPage");
    ctx_menu_.addAction(action);
    action = window()->findChild<QAction *>("actionContextFilterFieldReference");
    ctx_menu_.addAction(action);
    ctx_menu_.addMenu(&proto_prefs_menu_);
    ctx_menu_.addSeparator();
    decode_as_ = window()->findChild<QAction *>("actionAnalyzeDecodeAs");
    ctx_menu_.addAction(decode_as_);

    ctx_menu_.addAction(window()->findChild<QAction *>("actionGoGoToLinkedPacket"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionContextShowLinkedPacketInNewWindow"));

    proto_prefs_menu_.setModule(finfo.moduleName());

    decode_as_->setData(QVariant::fromValue(true));

    ctx_menu_.exec(event->globalPos());
    decode_as_->setData(QVariant());
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
    mono_font_ = mono_font;
    setFont(mono_font_);
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

// We track item expansion using proto.c:tree_is_expanded. QTreeView
// tracks it using QTreeViewPrivate::expandedIndexes. When we're handed
// a new tree, clear expandedIndexes and repopulate it by walking the
// tree and calling QTreeView::expand above.
void ProtoTree::setRootNode(proto_node *root_node) {
    setFont(mono_font_);
    reset(); // clears expandedIndexes.
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
    selectionModel()->select(index, QItemSelectionModel::ClearAndSelect);
    if (!index.isValid() || !prefs.gui_auto_scroll_on_expand) {
        return;
    }

    ScrollHint scroll_hint = PositionAtTop;
    if (prefs.gui_auto_scroll_percentage > 66) {
        scroll_hint = PositionAtBottom;
    } else if (prefs.gui_auto_scroll_percentage >= 33) {
        scroll_hint = PositionAtCenter;
    }
    scrollTo(index, scroll_hint);
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
    if (selected.isEmpty()) return;

    QModelIndex index = selected.indexes().first();

    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode(), this);
    if (!finfo.isValid()) return;

    // Find and highlight the protocol bytes
    QModelIndex parent = index;
    while (parent.isValid() && parent.parent().isValid()) {
        parent = parent.parent();
    }
    if (parent.isValid()) {
        FieldInformation parent_finfo(proto_tree_model_->protoNodeFromIndex(parent).protoNode());
        finfo.setParentField(parent_finfo.fieldInfo());
    }

    if ( finfo.isValid() )
    {
        saveSelectedField(index);
        emit fieldSelected(&finfo);
    }
    // else the GTK+ version pushes an empty string as described below.
    /*
     * Don't show anything if the field name is zero-length;
     * the pseudo-field for text-only items is such
     * a field, and we don't want "Text (text)" showing up
     * on the status line if you've selected such a field.
     *
     * XXX - there are zero-length fields for which we *do*
     * want to show the field name.
     *
     * XXX - perhaps the name and abbrev field should be null
     * pointers rather than null strings for that pseudo-field,
     * but we'd have to add checks for null pointers in some
     * places if we did that.
     *
     * Or perhaps text-only items should have -1 as the field
     * index, with no pseudo-field being used, but that might
     * also require special checks for -1 to be added.
     */
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
    for(int i = 0; i < num_tree_types; i++) {
        tree_expanded_set(i, TRUE);
    }
    QTreeView::expandAll();
    updateContentWidth();
}

void ProtoTree::collapseAll()
{
    for(int i = 0; i < num_tree_types; i++) {
        tree_expanded_set(i, FALSE);
    }
    QTreeView::collapseAll();
    updateContentWidth();
}

void ProtoTree::itemDoubleClicked(const QModelIndex &index) {
    FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode());
    if (!finfo.isValid()) return;

    if (finfo.headerInfo().type == FT_FRAMENUM) {
        if (QApplication::queryKeyboardModifiers() & Qt::ShiftModifier) {
            emit openPacketInNewWindow(true);
        } else {
            emit goToPacket(finfo.fieldInfo()->value.value.uinteger);
        }
    } else {
        QString url = finfo.url();
        if (!url.isEmpty()) {
            QDesktopServices::openUrl(QUrl(url));
        }
    }
}

void ProtoTree::selectedFieldChanged(FieldInformation *finfo)
{
    QModelIndex index = proto_tree_model_->findFieldInformation(finfo);
    if (!index.isValid() || finfo->parent() == this) {
        // We only want valid, inbound signals.
        return;
    }
    autoScrollTo(index);
}

// Remember the currently focussed field based on:
// - current hf_id (obviously)
// - parent items (to avoid selecting a text item in a different tree)
// - the row of each item
void ProtoTree::saveSelectedField(QModelIndex &index)
{
    selected_hfid_path_.clear();
    while (index.isValid()) {
        FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(index).protoNode());
        if (!finfo.isValid()) break;
        selected_hfid_path_.prepend(QPair<int,int>(index.row(), finfo.headerInfo().id));
        index = index.parent();
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
            cur_index = QModelIndex();
            break;
        }
    }

    autoScrollTo(cur_index);
}

const QString ProtoTree::toString(const QModelIndex &start_idx) const
{
    QModelIndex cur_idx = start_idx.isValid() ? start_idx : proto_tree_model_->index(0, 0);
    QModelIndex stop_idx = proto_tree_model_->index(cur_idx.row() + 1, 0, cur_idx.parent());
    QString tree_string;
    int indent_level = 0;

    do {
        tree_string.append(QString("    ").repeated(indent_level));
        tree_string.append(cur_idx.data().toString());
        tree_string.append("\n");
        // Next child
        if (isExpanded(cur_idx)) {
            cur_idx = proto_tree_model_->index(0, 0, cur_idx);
            indent_level++;
            continue;
        }
        // Next sibling
        QModelIndex sibling = proto_tree_model_->index(cur_idx.row() + 1, 0, cur_idx.parent());
        if (sibling.isValid()) {
            cur_idx = sibling;
            continue;
        }
        // Next parent
        cur_idx = proto_tree_model_->index(cur_idx.parent().row() + 1, 0, cur_idx.parent().parent());
        indent_level--;
    } while (cur_idx.isValid() && cur_idx.internalPointer() != stop_idx.internalPointer() && indent_level >= 0);

    return tree_string;
}

void ProtoTree::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
}

bool ProtoTree::eventFilter(QObject * obj, QEvent * event)
{
    if ( cap_file_ && event->type() != QEvent::MouseButtonPress && event->type() != QEvent::MouseMove )
        return QTreeView::eventFilter(obj, event);

    /* Mouse was over scrollbar, ignoring */
    if ( qobject_cast<QScrollBar *>(obj) )
        return QTreeView::eventFilter(obj, event);

    if ( event->type() == QEvent::MouseButtonPress )
    {
        QMouseEvent * ev = (QMouseEvent *)event;

        if ( ev->buttons() & Qt::LeftButton )
            drag_start_position_ = ev->pos();
    }
    else if ( event->type() == QEvent::MouseMove )
    {
        QMouseEvent * ev = (QMouseEvent *)event;

        if ( ( ev->buttons() & Qt::LeftButton ) && (ev->pos() - drag_start_position_).manhattanLength()
                 > QApplication::startDragDistance())
        {
            QModelIndex idx = indexAt(drag_start_position_);
            FieldInformation finfo(proto_tree_model_->protoNodeFromIndex(idx).protoNode());
            if ( finfo.isValid() )
            {
                /* Hack to prevent QItemSelection taking the item which has been dragged over at start
                 * of drag-drop operation. selectionModel()->blockSignals could have done the trick, but
                 * it does not take in a QTreeWidget (maybe View) */
                emit fieldSelected(&finfo);
                selectionModel()->select(idx, QItemSelectionModel::ClearAndSelect);

                QString filter = QString(proto_construct_match_selected_string(finfo.fieldInfo(), cap_file_->edt));

                if ( filter.length() > 0 )
                {
                    DisplayFilterMimeData * dfmd =
                            new DisplayFilterMimeData(QString(finfo.headerInfo().name), QString(finfo.headerInfo().abbreviation), filter);
                    QDrag * drag = new QDrag(this);
                    drag->setMimeData(dfmd);

                    DragLabel * content = new DragLabel(dfmd->labelText(), this);

#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
                    qreal dpr = window()->windowHandle()->devicePixelRatio();
                    QPixmap pixmap(content->size() * dpr);
                    pixmap.setDevicePixelRatio(dpr);
#else
                    QPixmap pixmap(content->size());
#endif
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
