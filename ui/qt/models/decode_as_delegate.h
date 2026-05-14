/** @file
 *
 * Delegates for editing various field types in a Decode As record.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DECODE_AS_DELEGATE_H
#define DECODE_AS_DELEGATE_H

#include <config.h>

#include <epan/cfile.h>

#include <QStyledItemDelegate>
#include <QSet>
#include <QList>
#include <ui/qt/models/decode_as_model.h>

/**
 * @brief Per-layer protocol data collected from the currently selected packet.
 */
typedef struct _packet_proto_data_t {
    const char *proto_name;     /**< Internal protocol name (e.g. "tcp"). */
    const char *table_ui_name;  /**< Human-readable dissector table name shown in the UI. */
    uint8_t     curr_layer_num; /**< Layer index of this protocol instance within the packet. */
} packet_proto_data_t;


/**
 * @brief Item delegate providing in-place editors for the Decode As table.
 */
class DecodeAsDelegate : public QStyledItemDelegate
{
public:
    /**
     * @brief Construct a DecodeAsDelegate.
     * @param parent The parent QObject.
     * @param cf     The currently open capture file, used to interrogate the
     *               selected packet for its protocol layers. May be NULL.
     */
    DecodeAsDelegate(QObject *parent = 0, capture_file *cf = NULL);

    /**
     * @brief Create an editor widget for the cell at @p index.
     *
     * Returns a QComboBox populated with dissector table selector values
     * (for the selector column) or dissector handle names (for the codec
     * column). Falls back to QStyledItemDelegate for other columns.
     *
     * @param parent  The parent widget for the editor.
     * @param option  Style options for the editor's viewport rect.
     * @param index   The model index of the cell being edited.
     * @return The editor widget; ownership is transferred to the view.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;

    /**
     * @brief Destroy the editor widget created by createEditor().
     *
     * Performs any cleanup required before the editor is deleted,
     * then delegates to QStyledItemDelegate::destroyEditor().
     *
     * @param editor The editor widget to destroy.
     * @param index  The model index the editor was associated with.
     */
    void destroyEditor(QWidget *editor, const QModelIndex &index) const override;

    /**
     * @brief Populate the editor with the current model data.
     *
     * Sets the current selection of the selector or dissector combo box
     * to match the value stored at @p index in the model.
     *
     * @param editor The editor widget returned by createEditor().
     * @param index  The model index whose data should be loaded.
     */
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;

    /**
     * @brief Write the editor's current value back to the model.
     *
     * Reads the selected item from the selector or dissector combo box
     * and stores it into @p model at @p index.
     *
     * @param editor The editor widget whose value should be committed.
     * @param model  The model to update.
     * @param index  The model index to write to.
     */
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const override;

#if 0
    void updateEditorGeometry(QWidget *editor,
            const QStyleOptionViewItem &option, const QModelIndex &index) const;
#endif

private:
    /**
     * @brief Return the DecodeAsItem for the given model index.
     *
     * @param index The model index to look up.
     * @return The DecodeAsItem for @p index, or nullptr if unavailable.
     */
    DecodeAsItem *indexToField(const QModelIndex &index) const;

    /**
     * @brief Collect all protocols eligible for Decode As.
     *
     * @param all_protocols Receives the full set of eligible protocol names.
     * @param current_list  Receives the ordered list of protocols seen in
     *                      the selected packet.
     */
    void collectDAProtocols(QSet<QString> &all_protocols,
                            QList<QString> &current_list) const;

    /**
     * @brief Populate @c packet_proto_list_ from the selected packet.
     */
    void cachePacketProtocols();

    /**
     * @brief Return whether the selector column for @p item uses a combo box.
     *
     * @param item The Decode As row item to check.
     * @return true if a combo box should be used for the selector column.
     */
    bool isSelectorCombo(DecodeAsItem *item) const;


    /**
     * @brief Callback invoked by the dissector framework for each registered
     * protocol that can be added to a Decode As entry.
     *
     * @param table_name Internal dissector table name.
     * @param proto_name Internal protocol name for the dissector.
     * @param value      The selector value (uint or string) for this entry.
     * @param user_data  Pointer to the QComboBox being populated.
     */
    static void decodeAddProtocol(const char *table_name, const char *proto_name,
                                  void *value, void *user_data);

    capture_file *cap_file_;                      /**< The capture file used to query the selected packet. */
    QList<packet_proto_data_t> packet_proto_list_; /**< Cached protocol layers from the selected packet. */
};
#endif // DECODE_AS_DELEGATE_H
