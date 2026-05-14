/** @file
 *
 * Data model for Decode As records.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DECODE_AS_MODEL_H
#define DECODE_AS_MODEL_H

#include <config.h>

#include <QAbstractItemModel>
#include <QList>

#include <epan/cfile.h>

#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/dissectors/packet-dcerpc.h>

/**
 * @brief Represents a single "Decode As" mapping entry in the UI.
 */
class DecodeAsItem
{
public:
    /** @brief Construct a DecodeAsItem from a raw table name and selector.
     *  @param table_name The dissector table name, or NULL for none.
     *  @param selector   The selector value, or NULL for none. */
    DecodeAsItem(const char *table_name = NULL, const void *selector = NULL);

    /** @brief Construct a DecodeAsItem from a decode_as_t entry and selector.
     *  @param entry    The decode_as_t entry describing the table.
     *  @param selector The selector value, or NULL for none. */
    DecodeAsItem(const decode_as_t *entry, const void *selector = NULL);

    /** @brief Destroy the DecodeAsItem. */
    virtual ~DecodeAsItem();

    /** @brief Return the dissector table name.
     *  @return The internal table name string. */
    const char* tableName() const { return tableName_; }

    /** @brief Return the dissector table name for display in the UI.
     *  @return The UI-facing table name string. */
    const char* tableUIName() const { return tableUIName_; }

    /** @brief Return the selector as an unsigned integer.
     *  @return The uint selector value. */
    uint selectorUint() const { return selectorUint_; }

    /** @brief Return the selector as a string.
     *  @return The string selector value. */
    QString selectorString() const { return selectorString_; }

    /** @brief Return the selector as a DCE/RPC bind value.
     *  @return Pointer to the DCE/RPC bind values, or nullptr if not set. */
    decode_dcerpc_bind_values_t* selectorDCERPC() const { return selectorDCERPC_; }

    /** @brief Return the selector as a UUID key.
     *  @return Pointer to the UUID key. */
    const guid_key* selectorUUID() const { return &selectorUUID_; }

    /** @brief Return the name of the default dissector for this entry.
     *  @return The default dissector name string. */
    QString defaultDissector() const { return default_dissector_; }

    /** @brief Return the name of the currently selected dissector.
     *  @return The current dissector name string. */
    QString currentDissector() const { return current_dissector_; }

    /** @brief Return the handle of the currently selected dissector.
     *  @return The dissector handle. */
    dissector_handle_t dissectorHandle() const { return dissector_handle_; }

    /** @brief Set the dissector table from a decode_as_t entry.
     *  @param entry The decode_as_t entry describing the table. */
    void setTable(const decode_as_t *entry);

    /** @brief Set the selector value from a string.
     *  @param value The new selector string. */
    void setSelector(const QString &value);

    /** @brief Set the dissector handle.
     *  @param handle The dissector handle to use. */
    void setDissectorHandle(dissector_handle_t handle);

    /** @brief Set the UUID selector key.
     *  @param key The UUID key to use as the selector. */
    void setUUID(const guid_key& key);

    /**
     * @brief Refresh the default and current dissector name strings from
     * the current dissector handle.
     */
    void updateHandles();

private:
    /** @brief Initialize the item from a raw table name and selector.
     *  @param table_name The dissector table name, or NULL for none.
     *  @param selector   The selector value, or NULL for none. */
    void init(const char *table_name, const void *selector = NULL);

    const char* tableName_;    /**< Internal dissector table name. */
    const char* tableUIName_;  /**< UI-facing dissector table name. */

    // Selector values are stored by value to avoid memory management issues
    // between the transient GUI state and the underlying dissector data.
    uint selectorUint_;              /**< Selector as an unsigned integer. */
    QString selectorString_;         /**< Selector as a string. */

    //for special handling of DCE/RPC
    decode_dcerpc_bind_values_t* selectorDCERPC_;  /**< Selector for DCE/RPC bindings. */
    guid_key                     selectorUUID_;    /**< Selector as a UUID key. */

    QString default_dissector_;        /**< Name of the default dissector. */
    QString current_dissector_;        /**< Name of the currently selected dissector. */
    dissector_handle_t dissector_handle_; /**< Handle of the currently selected dissector. */
};

typedef struct _dissector_info_t {
    QString             proto_name;
    guid_key            dcerpc_uuid;
    dissector_handle_t  dissector_handle;
} dissector_info_t;

Q_DECLARE_METATYPE(dissector_info_t*)

/**
 * @brief Table model backing the Decode As dialog.
 *
 * Manages the list of @c DecodeAsItem entries that map dissector table
 * selectors to user-chosen dissectors, and provides methods to apply,
 * import, and reset those mappings.
 */
class DecodeAsModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    /**
     * @brief Construct a DecodeAsModel.
     *
     * @param parent The parent object.
     * @param cf     The capture file, or NULL if none is open.
     */
    DecodeAsModel(QObject *parent, capture_file *cf = NULL);

    /** @brief Destroy the DecodeAsModel. */
    virtual ~DecodeAsModel();


    /**
     * @brief A pending change to a uint-keyed dissector table entry.
     */
    struct UIntEntry {
        QByteArray table;     /**< The dissector table name. */
        uint32_t    key;      /**< The uint selector key. */
        QByteArray pref_name; /**< The preference name for this entry. */

        /** @brief Construct a UIntEntry.
         *  @param t           The dissector table name.
         *  @param k           The uint selector key.
         *  @param pref_suffix The suffix to append to the table name to form
         *                     the preference name. */
        UIntEntry(const char* t, uint32_t k, const char* pref_suffix) :
            table(t), key(k), pref_name(t) { pref_name.append(pref_suffix); }
    };


    /**
     * @brief Column indices for the Decode As table.
     */
    enum DecodeAsColumn {
        colTable    = 0, /**< The dissector table (aka "Field", e.g. "TCP Port"). */
        colSelector,     /**< The selector value (e.g., port number 80). */
        colType,         /**< The field type (e.g. "Integer, base 16"). */
        colDefault,      /**< The initial protocol chosen by Wireshark. */
        colProtocol,     /**< The current protocol selected by the user. */
        colDecodeAsMax   /**< Sentinel value; not used as a column. */
    };


    /** @brief Return the item flags for the given index.
     *  @param index The model index to query.
     *  @return The item flags. */
    Qt::ItemFlags flags(const QModelIndex &index) const;

    /** @brief Return data for the given index and role.
     *  @param index The model index to query.
     *  @param role  The data role.
     *  @return The data, or an invalid @c QVariant if unsupported. */
    QVariant data(const QModelIndex &index, int role) const;

    /** @brief Return header data for the given section, orientation, and role.
     *  @param section     The section index.
     *  @param orientation The header orientation.
     *  @param role        The data role.
     *  @return The header data, or an invalid @c QVariant if unsupported. */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    /** @brief Return the number of rows in the model.
     *  @param parent Unused; present for API compatibility.
     *  @return The number of decode-as entries. */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /** @brief Return the number of columns in the model.
     *  @param parent Unused; present for API compatibility.
     *  @return The number of columns. */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;


    /** @brief Set data for the given index and role.
     *  @param index The model index to update.
     *  @param value The new value.
     *  @param role  The data role.
     *  @return true if the data was set successfully, false otherwise. */
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

    /**
     * @brief Populate the model from the current decode-as configuration.
     */
    void fillTable();


    /** @brief Set the dissector handle for the entry at the given index.
     *  @param index            The model index of the entry to update.
     *  @param dissector_handle The dissector handle to assign. */
    void setDissectorHandle(const QModelIndex &index, dissector_handle_t dissector_handle);


    /** @brief Insert rows into the model.
     *  @param row    The row before which to insert.
     *  @param count  The number of rows to insert.
     *  @param parent Unused; present for API compatibility.
     *  @return true if the rows were inserted successfully. */
    bool insertRows(int row, int count, const QModelIndex &parent = QModelIndex());

    /** @brief Remove rows from the model.
     *  @param row    The first row to remove.
     *  @param count  The number of rows to remove.
     *  @param parent Unused; present for API compatibility.
     *  @return true if the rows were removed successfully. */
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());

    /**
     * @brief Remove all decode-as entries from the model.
     */
    void clearAll();

    /** @brief Copy a row within the model.
     *  @param dst_row The destination row index.
     *  @param src_row The source row index.
     *  @return true if the row was copied successfully. */
    bool copyRow(int dst_row, int src_row);

    /** @brief Import decode-as entries from a Wireshark profile file.
     *  @param filename The path to the profile file.
     *  @param err      Output pointer for an error message on failure.
     *  @return true if the import succeeded, false otherwise. */
    bool copyFromProfile(QString filename, const char **err);

    /** @brief Return a human-readable string describing a dissector table entry.
     *  @param table_name The dissector table name.
     *  @param value      The selector value.
     *  @return A display string for the entry. */
    static QString entryString(const char *table_name, const void *value);

    /**
     * @brief Apply all pending decode-as changes to the dissector tables.
     */
    void applyChanges();

protected:
    /** @brief Callback to record a changed uint or string dissector table entry.
     *  @param table_name    The dissector table name.
     *  @param selector_type The field type of the selector.
     *  @param key           The selector key.
     *  @param value         The dissector handle value.
     *  @param user_data     Pointer to the @c DecodeAsModel instance. */
    static void buildChangedList(const char *table_name, ftenum_t selector_type,
                          void *key, void *value, void *user_data);

    /** @brief Callback to record a changed DCE/RPC dissector table entry.
     *  @param data      The DCE/RPC bind values.
     *  @param user_data Pointer to the @c DecodeAsModel instance. */
    static void buildDceRpcChangedList(void *data, void *user_data);

    /** @brief Callback to collect entries that differ from their defaults.
     *  @param table_name    The dissector table name.
     *  @param selector_type The field type of the selector.
     *  @param key           The selector key.
     *  @param value         The dissector handle value.
     *  @param user_data     Pointer to the @c DecodeAsModel instance. */
    static void gatherChangedEntries(const char *table_name, ftenum_t selector_type,
                          void *key, void *value, void *user_data);

    /** @brief Callback to parse and apply a single decode-as preference entry.
     *  @param key       The preference key string.
     *  @param value     The preference value string.
     *  @param user_data Pointer to the @c DecodeAsModel instance.
     *  @return The result of the preference set operation. */
    static prefs_set_pref_e readDecodeAsEntry(char *key, const char *value,
                          void *user_data, bool);

private:
    capture_file *cap_file_;                                          /**< The associated capture file. */
    QList<DecodeAsItem *> decode_as_items_;                           /**< The list of decode-as entries. */
    QList<UIntEntry> changed_uint_entries_;                           /**< Pending changes to uint-keyed tables. */
    QList<QPair<const char *, const char *> > changed_string_entries_; /**< Pending changes to string-keyed tables. */
};

#endif // DECODE_AS_MODEL_H
