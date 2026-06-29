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

#include <epan/cfile.h>

#include <ui/qt/utils/field_information.h>
#include <QTreeView>
#include <QMenu>

class ProtoTreeModel;
class ProtoNode;

/**
 * @brief A tree view for displaying protocol dissection details.
 */
class ProtoTree : public QTreeView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ProtoTree.
     * @param parent The parent widget, defaults to 0.
     * @param edt_fixed Pointer to fixed epan dissection data, defaults to 0.
     */
    explicit ProtoTree(QWidget *parent = 0, epan_dissect_t *edt_fixed = 0);

    /**
     * @brief Retrieves the colorize menu.
     * @return A pointer to the colorize QMenu.
     */
    QMenu *colorizeMenu() { return &colorize_menu_; }

    /**
     * @brief Sets the root protocol node to be displayed.
     * @param root_node Pointer to the root proto_node.
     */
    void setRootNode(proto_node *root_node);

    /**
     * @brief Emits a signal indicating a related frame.
     * @param related_frame The related frame number.
     * @param framenum_type The type of the related frame, defaults to FT_FRAMENUM_NONE.
     */
    void emitRelatedFrame(int related_frame, ft_framenum_type_t framenum_type = FT_FRAMENUM_NONE);

    /**
     * @brief Automatically scrolls to a specific model index.
     * @param index The model index to scroll to.
     */
    void autoScrollTo(const QModelIndex &index);

    /**
     * @brief Navigates to a specific Header Field ID (HFID).
     * @param hfid The Header Field ID to navigate to.
     */
    void goToHfid(int hfid);

    /**
     * @brief Clears the protocol tree.
     */
    void clear();

    /**
     * @brief Restores the previously selected field in the tree.
     */
    void restoreSelectedField();

    /**
     * @brief Converts the tree or a subtree to a string representation.
     * @param start_idx The starting model index, defaults to QModelIndex().
     * @return The string representation of the tree.
     */
    QString toString(const QModelIndex &start_idx = QModelIndex()) const;

protected:

    /**
     * @brief Columns in the protocol tree.
     */
    enum {
        Name = 0,     /**< The name column. */
        Description,  /**< The description column. */
        Value         /**< The value column. */
    };

    /**
     * @brief Handles context menu events.
     * @param event The context menu event.
     */
    virtual void contextMenuEvent(QContextMenuEvent *event) override;

    /**
     * @brief Handles timer events.
     * @param event The timer event.
     */
    virtual void timerEvent(QTimerEvent *event) override;

    /**
     * @brief Handles key release events.
     * @param event The key release event.
     */
    virtual void keyReleaseEvent(QKeyEvent *event) override;

    /**
     * @brief Handles focus in events.
     * @param event The focus event.
     */
    virtual void focusInEvent(QFocusEvent *event) override;

    /**
     * @brief Filters events for watched objects.
     * @param obj The watched object.
     * @param ev The event to filter.
     * @return True if the event was filtered, false otherwise.
     */
    virtual bool eventFilter(QObject * obj, QEvent * ev) override;

    /**
     * @brief Handles cursor movements within the tree.
     * @param cursorAction The cursor action type.
     * @param modifiers The keyboard modifiers.
     * @return The new model index after moving the cursor.
     */
    virtual QModelIndex moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers) override;

    /**
     * @brief Traverses the tree and builds a string representation.
     * @param rootNode The starting root node index.
     * @param identLevel The current indentation level, defaults to 0.
     * @return The string representation of the traversed subtree.
     */
    QString traverseTree(const QModelIndex & rootNode, int identLevel = 0) const;

private:
    /** The underlying model for the protocol tree. */
    ProtoTreeModel *proto_tree_model_;

    /** Menu for conversation-related actions. */
    QMenu conv_menu_;

    /** Menu for colorize-related actions. */
    QMenu colorize_menu_;

    /** List of actions for copying data. */
    QList<QAction *> copy_actions_;

    /** Timer ID for handling column resizes. */
    int column_resize_timer_;

    /** Path to the selected HFID, stored as pairs of row and hfinfo. */
    QList<QPair<int,int> > selected_hfid_path_;

    /** The starting position of a drag operation. */
    QPoint drag_start_position_;

    /** Pointer to the capture file. */
    capture_file *cap_file_;

    /** Pointer to the epan dissection data. */
    epan_dissect_t *edt_;

    /**
     * @brief Saves the currently selected field for later restoration.
     * @param index The model index of the selected field.
     */
    void saveSelectedField(QModelIndex &index);

    /**
     * @brief Helper function to iterate over tree nodes.
     * @param node The current proto_node.
     * @param proto_tree_ptr Pointer to the ProtoTree instance.
     */
    static void foreachTreeNode(proto_node *node, void *proto_tree_ptr);

    /**
     * @brief Helper function to expand all children of a node.
     * @param index The model index to expand.
     */
    void foreachExpand(const QModelIndex &index);

signals:
    /**
     * @brief Signal emitted when a field is selected.
     * @param finfo Pointer to the FieldInformation.
     */
    void fieldSelected(FieldInformation *finfo);

    /**
     * @brief Signal emitted to open the packet in a new window.
     * @param open True to open in a new window.
     */
    void openPacketInNewWindow(bool open);

    /**
     * @brief Signal emitted to jump to a specific packet.
     * @param packet_num The packet number to go to.
     */
    void goToPacket(int packet_num);

    /**
     * @brief Signal emitted to indicate a related frame.
     * @param frame_num The related frame number.
     * @param type The type of the related frame.
     */
    void relatedFrame(int frame_num, ft_framenum_type_t type);

    /**
     * @brief Signal emitted to show preferences for a specific protocol.
     * @param module_name The name of the protocol module.
     */
    void showProtocolPreferences(const QString module_name);

    /**
     * @brief Signal emitted to edit a specific protocol preference.
     * @param pref Pointer to the preference.
     * @param module Pointer to the module.
     */
    void editProtocolPreference(pref_t *pref, module_t *module);

    /**
     * @brief Signal emitted to request packet recolorization.
     */
    void recolorPacketsRequested();

    /**
     * @brief Signal emitted to request redissection of packets.
     */
    void redissectPacketsRequested();

    /**
     * @brief Signal emitted to show a Distribution Dialog for a Named Field.
     * @param abbr_name The name of the Named Field.
     */
    void showDistributionDialog(const QString abbr_name);

public slots:

    /**
     * @brief Set the capture file.
     * @param cf Pointer to the capture file.
     */
    void setCaptureFile(capture_file *cf);

    /**
     * @brief Sets the monospace font used in the tree view.
     * @param mono_font The monospace font.
     */
    void setMonospaceFont(const QFont &mono_font);

    /**
     * @brief Synchronizes the expanded state of a node.
     * @param index The model index that was expanded.
     */
    void syncExpanded(const QModelIndex & index);

    /**
     * @brief Synchronizes the collapsed state of a node.
     * @param index The model index that was collapsed.
     */
    void syncCollapsed(const QModelIndex & index);

    /**
     * @brief Expands all subtrees of the currently selected item.
     */
    void expandSubtrees();

    /**
     * @brief Collapses all subtrees of the currently selected item.
     */
    void collapseSubtrees();

    /**
     * @brief Expands all items in the tree.
     */
    void expandAll();

    /**
     * @brief Collapses all items in the tree.
     */
    void collapseAll();

    /**
     * @brief Slot triggered when an item is clicked.
     * @param index The model index of the clicked item.
     */
    void itemClicked(const QModelIndex & index);

    /**
     * @brief Slot triggered when an item is double-clicked.
     * @param index The model index of the double-clicked item.
     */
    void itemDoubleClicked(const QModelIndex & index);

    /**
     * @brief Slot triggered when the selected field changes.
     * @param finfo Pointer to the new FieldInformation.
     */
    void selectedFieldChanged(FieldInformation *finfo);

    /**
     * @brief Slot triggered when the selected frame changes.
     * @param frames List of selected frame numbers.
     */
    void selectedFrameChanged(QList<int> frames);

protected slots:
    /**
     * @brief Handles changes in the tree view selection.
     * @param selected The newly selected items.
     * @param deselected The newly deselected items.
     */
    void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected) override;

#if 0
    /**
     * @brief Context menu action to show packet bytes.
     */
    void ctxShowPacketBytes();

    /**
     * @brief Context menu action to export packet bytes.
     */
    void ctxExportPacketBytes();
#endif

    /**
     * @brief Context menu action to copy all visible items.
     */
    void ctxCopyVisibleItems();

    /**
     * @brief Context menu action to copy the selected item as a display filter.
     */
    void ctxCopyAsFilter();

    /**
     * @brief Context menu action to copy the selected information.
     */
    void ctxCopySelectedInfo();

    /**
     * @brief Context menu action to open the associated protocol wiki page.
     */
    void ctxOpenUrlWiki();

private slots:
    /**
     * @brief Updates the content width of the tree columns.
     */
    void updateContentWidth();

    /**
     * @brief Connects signals from the tree to the main window.
     */
    void connectToMainWindow();
};

#endif // PROTO_TREE_H
