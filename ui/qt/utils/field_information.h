/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FIELD_INFORMATION_H_
#define FIELD_INFORMATION_H_

#include <config.h>

#include <epan/proto.h>

#include <ui/qt/utils/proto_node.h>
#include "data_printer.h"

#include <QObject>

/**
 * @brief Represents information about a dissected packet field.
 */
class FieldInformation : public QObject, public IDataPrintable
{
    Q_OBJECT
    Q_INTERFACES(IDataPrintable)

public:

    /**
     * @brief Structure holding header field information.
     */
    struct HeaderInfo
    {
        QString name;         /**< The name of the field. */
        QString description;  /**< A description of the field. */
        QString abbreviation; /**< The field's abbreviation (used in display filters). */
        bool isValid;         /**< True if the header information is valid. */
        enum ftenum type;     /**< The field type (e.g., FT_UINT32, FT_STRING). */
        int parent;           /**< The ID of the parent field. */
        int id;               /**< The unique ID of the field. */
    };

    /**
     * @brief Structure representing the position of a field within data.
     */
    struct Position
    {
        int start;  /**< The starting byte offset. */
        int length; /**< The length in bytes. */
    };

    /**
     * @brief Constructs a FieldInformation object from a core field_info struct.
     * @param fi Pointer to the underlying field_info struct.
     * @param parent The parent object.
     */
    explicit FieldInformation(field_info * fi, QObject * parent = Q_NULLPTR);

    /**
     * @brief Constructs a FieldInformation object from a ProtoNode.
     * @param node Pointer to the ProtoNode representing the field.
     * @param parent The parent object.
     */
    explicit FieldInformation(const ProtoNode * node, QObject * parent = Q_NULLPTR);

    /**
     * @brief Checks if the field information is valid.
     * @return True if valid, false otherwise.
     */
    bool isValid() const;

    /**
     * @brief Checks if the field represents a link.
     * @return True if it is a link, false otherwise.
     */
    bool isLink() const ;

    /**
     * @brief Retrieves the underlying field_info struct.
     * @return Pointer to the field_info struct.
     */
    field_info * fieldInfo() const;

    /**
     * @brief Retrieves the header information for the field.
     * @return A HeaderInfo structure containing the data.
     */
    HeaderInfo headerInfo() const;

    /**
     * @brief Retrieves the position of the field within the data source.
     * @return A Position structure with the start and length.
     */
    Position position() const;

    /**
     * @brief Retrieves the position of the field's appendix (if any).
     * @return A Position structure with the start and length of the appendix.
     */
    Position appendix() const;

    /**
     * @brief Sets the parent field for this field.
     * @param fi Pointer to the parent field_info.
     */
    void setParentField(field_info * fi);

    /**
     * @brief Gets the tree type associated with this field.
     * @return The tree type identifier.
     */
    int treeType();

    /**
     * @brief Retrieves the parent FieldInformation object.
     * @return Pointer to the parent FieldInformation, or nullptr if none.
     */
    FieldInformation * parentField() const;

    /**
     * @brief Checks if the TVB associated with this field contains the given field.
     * @param child Pointer to another FieldInformation to check.
     * @return True if this field's TVB contains the specified field, false otherwise.
     */
    bool tvbContains(FieldInformation * child);

    /**
     * @brief Retrieves a specific flag value based on a mask.
     * @param mask The bitmask to apply to the field's flags.
     * @return The flag value.
     */
    unsigned flag(unsigned mask);

    /**
     * @brief Retrieves the name of the module that registered this field.
     * @return The module name as a QString.
     */
    const QString moduleName();

    /**
     * @brief Converts the field information to a string representation.
     * @return The string representation of the field.
     */
    QString toString();

    /**
     * @brief Retrieves a URL related to this field, if available.
     * @return The URL string.
     */
    QString url();

    /**
     * @brief Gets the printable data for the field.
     * @return A QByteArray containing the printable data.
     */
    const QByteArray printableData();

private:

    field_info * fi_;        /**< Pointer to the underlying field_info structure. */
    field_info * parent_fi_; /**< Pointer to the parent field_info structure. */
};


#endif // FIELD_INFORMATION_H_
