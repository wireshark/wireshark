/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_UTILS_WIRESHARK_MIME_DATA_H_
#define UI_QT_UTILS_WIRESHARK_MIME_DATA_H_

#include <QMimeData>

/**
 * @brief Base class for Wireshark specific MIME data.
 */
class WiresharkMimeData: public QMimeData {
public:
    /**
     * @brief Retrieves the label text for the MIME data.
     * @return A QString containing the label text.
     */
    virtual QString labelText() const = 0;

    /**
     * @brief Allows the MIME data to be represented as plain text.
     */
    virtual void allowPlainText();

    /** @brief MIME type string for coloring rules. */
    static const QString ColoringRulesMimeType;

    /** @brief MIME type string for column lists. */
    static const QString ColumnListMimeType;

    /** @brief MIME type string for filter lists. */
    static const QString FilterListMimeType;

    /** @brief MIME type string for display filters. */
    static const QString DisplayFilterMimeType;
};

/**
 * @brief MIME data representation for a toolbar entry.
 */
class ToolbarEntryMimeData: public WiresharkMimeData {
    Q_OBJECT
public:

    /**
     * @brief Constructs a new ToolbarEntryMimeData object.
     * @param element The toolbar element string.
     * @param pos The position of the entry.
     */
    ToolbarEntryMimeData(QString element, int pos);

    /**
     * @brief Retrieves the position of the entry.
     * @return The integer position.
     */
    int position() const;

    /**
     * @brief Retrieves the element string.
     * @return A QString containing the element.
     */
    QString element() const;

    /**
     * @brief Retrieves the filter string associated with the entry.
     * @return A QString containing the filter.
     */
    QString filter() const;

    /**
     * @brief Sets the filter string for the entry.
     * @param text The new filter string's text.
     */
    void setFilter(QString text);

    /**
     * @brief Retrieves the label text for the toolbar entry.
     * @return A QString containing the label text.
     */
    QString labelText() const override;

private:

    /** @brief The toolbar element string. */
    QString element_;

    /** @brief The filter string associated with the entry. */
    QString filter_;

    /** @brief The position of the entry. */
    int pos_;

};

#endif /* UI_QT_UTILS_WIRESHARK_MIME_DATA_H_ */
