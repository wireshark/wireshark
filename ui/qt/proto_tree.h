/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROTO_TREE_H
#define PROTO_TREE_H

#include <config.h>

#include <epan/proto.h>

#include "cfile.h"

#include "protocol_preferences_menu.h"

#include <ui/qt/utils/field_information.h>
#include <QTreeView>
#include <QMenu>

class ProtoTreeModel;
class ProtoNode;

class ProtoTree : public QTreeView
{
    Q_OBJECT
public:
    explicit ProtoTree(QWidget *parent = 0, epan_dissect_t *edt_fixed = 0);
    QMenu *colorizeMenu() { return &colorize_menu_; }
    void setRootNode(proto_node *root_node);
    void emitRelatedFrame(int related_frame, ft_framenum_type_t framenum_type = FT_FRAMENUM_NONE);
    void autoScrollTo(const QModelIndex &index);
    void goToHfid(int hfid);
    void clear();
    void restoreSelectedField();
    QString toString(const QModelIndex &start_idx = QModelIndex()) const;

protected:

    enum {
        Name = 0,
        Description,
        Value
    };

    virtual void contextMenuEvent(QContextMenuEvent *event);
    virtual void timerEvent(QTimerEvent *event);
    virtual void keyReleaseEvent(QKeyEvent *event);
    virtual bool eventFilter(QObject * obj, QEvent * ev);
    virtual QModelIndex moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers);

    QString traverseTree(const QModelIndex & rootNode, int identLevel = 0) const;

private:
    ProtoTreeModel *proto_tree_model_;
    QMenu conv_menu_;
    QMenu colorize_menu_;
    ProtocolPreferencesMenu proto_prefs_menu_;
    QList<QAction *> copy_actions_;
    int column_resize_timer_;
    QList<QPair<int,int> > selected_hfid_path_; // row, hfinfo

    QPoint drag_start_position_;

    capture_file *cap_file_;
    epan_dissect_t *edt_;

    void saveSelectedField(QModelIndex &index);
    static void foreachTreeNode(proto_node *node, void *proto_tree_ptr);
    void foreachExpand(const QModelIndex &index);

signals:
    void fieldSelected(FieldInformation *);
    void openPacketInNewWindow(bool);
    void goToPacket(int);
    void relatedFrame(int, ft_framenum_type_t);
    void showProtocolPreferences(const QString module_name);
    void editProtocolPreference(struct preference *pref, struct pref_module *module);

public slots:

    /* Set the capture file */
    void setCaptureFile(capture_file *cf);
    void setMonospaceFont(const QFont &mono_font);
    void syncExpanded(const QModelIndex & index);
    void syncCollapsed(const QModelIndex & index);
    void expandSubtrees();
    void collapseSubtrees();
    void expandAll();
    void collapseAll();
    void itemClicked(const QModelIndex & index);
    void itemDoubleClicked(const QModelIndex & index);
    void selectedFieldChanged(FieldInformation *);
    void selectedFrameChanged(QList<int>);

protected slots:
    void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
#if 0
    void ctxShowPacketBytes();
    void ctxExportPacketBytes();
#endif
    void ctxCopyVisibleItems();
    void ctxCopyAsFilter();
    void ctxCopySelectedInfo();
    void ctxOpenUrlWiki();

private slots:
    void updateContentWidth();
    void connectToMainWindow();
};

#endif // PROTO_TREE_H
