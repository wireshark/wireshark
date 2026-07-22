/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef PACKET_FORMAT_GROUP_BOX_H
#define PACKET_FORMAT_GROUP_BOX_H

#include "file.h"

#include <QGroupBox>

/**
 * @brief Base group box for configuring packet export and print formats.
 */
class PacketFormatGroupBox : public QGroupBox
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a PacketFormatGroupBox.
     * @param parent The parent widget.
     */
    explicit PacketFormatGroupBox(QWidget *parent = 0);

    /**
     * @brief Checks if the current format configuration is valid.
     * @return True if the configuration is valid, false otherwise.
     */
    virtual bool isValid() const;

    /**
     * @brief Updates the print arguments with the current format settings.
     * @param print_args The print arguments structure to update.
     */
    virtual void updatePrintArgs(print_args_t& print_args) = 0;

signals:
    /**
     * @brief Signal emitted when the format configuration changes.
     */
    void formatChanged();

};

/**
 * @brief A blank packet format group box that provides default or empty formatting.
 */
class PacketFormatBlankGroupBox : public PacketFormatGroupBox
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a PacketFormatBlankGroupBox.
     * @param parent The parent widget.
     */
    explicit PacketFormatBlankGroupBox(QWidget *parent = 0);

    /**
     * @brief Updates the print arguments with the blank format settings.
     * @param print_args The print arguments structure to update.
     */
    void updatePrintArgs(print_args_t& print_args) override;
};

namespace Ui {
class PacketFormatTextGroupBox;
}

/**
 * @brief Group box for configuring plain text packet formatting options.
 */
class PacketFormatTextGroupBox : public PacketFormatGroupBox
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a PacketFormatTextGroupBox.
     * @param parent The parent widget.
     */
    explicit PacketFormatTextGroupBox(QWidget *parent = 0);

    /**
     * @brief Destroys the PacketFormatTextGroupBox.
     */
    ~PacketFormatTextGroupBox();

    /**
     * @brief Checks if the text format configuration is valid.
     * @return True if the configuration is valid, false otherwise.
     */
    bool isValid() const override;

    /**
     * @brief Updates the print arguments with the text format settings.
     * @param print_args The print arguments structure to update.
     */
    void updatePrintArgs(print_args_t& print_args) override;

    /**
     * @brief Checks if the packet summary option is enabled.
     * @return True if enabled, false otherwise.
     */
    bool summaryEnabled() const;

    /**
     * @brief Checks if the packet details option is enabled.
     * @return True if enabled, false otherwise.
     */
    bool detailsEnabled() const;

    /**
     * @brief Checks if the packet bytes option is enabled.
     * @return True if enabled, false otherwise.
     */
    bool bytesEnabled() const;

    /**
     * @brief Checks if the column headings option is enabled.
     * @return True if enabled, false otherwise.
     */
    bool includeColumnHeadingsEnabled() const;

    /**
     * @brief Checks if the 'all collapsed' detail state is enabled.
     * @return True if enabled, false otherwise.
     */
    bool allCollapsedEnabled() const;

    /**
     * @brief Checks if the 'as displayed' detail state is enabled.
     * @return True if enabled, false otherwise.
     */
    bool asDisplayedEnabled() const;

    /**
     * @brief Checks if the 'all expanded' detail state is enabled.
     * @return True if enabled, false otherwise.
     */
    bool allExpandedEnabled() const;

    /**
     * @brief Retrieves the current hexdump formatting options.
     * @return The hexdump options bitmask.
     */
    uint getHexdumpOptions() const;

private slots:
    /**
     * @brief Handles the toggling of the summary checkbox.
     * @param checked The new checked state.
     */
    void on_summaryCheckBox_toggled(bool checked);

    /**
     * @brief Handles the toggling of the details checkbox.
     * @param checked The new checked state.
     */
    void on_detailsCheckBox_toggled(bool checked);

    /**
     * @brief Handles the toggling of the bytes checkbox.
     * @param checked The new checked state.
     */
    void on_bytesCheckBox_toggled(bool checked);

    /**
     * @brief Handles the toggling of the include column headings checkbox.
     * @param checked The new checked state.
     */
    void on_includeColumnHeadingsCheckBox_toggled(bool checked);

    /**
     * @brief Handles the toggling of the all collapsed radio button.
     * @param checked The new checked state.
     */
    void on_allCollapsedButton_toggled(bool checked);

    /**
     * @brief Handles the toggling of the as displayed radio button.
     * @param checked The new checked state.
     */
    void on_asDisplayedButton_toggled(bool checked);

    /**
     * @brief Handles the toggling of the all expanded radio button.
     * @param checked The new checked state.
     */
    void on_allExpandedButton_toggled(bool checked);

    /**
     * @brief Handles the toggling of the include data sources checkbox.
     * @param checked The new checked state.
     */
    void on_includeDataSourcesCheckBox_toggled(bool checked);

    /**
     * @brief Handles the toggling of the timestamp checkbox.
     * @param checked The new checked state.
     */
    void on_timestampCheckBox_toggled(bool checked);

private:
    Ui::PacketFormatTextGroupBox *pf_ui_; /**< Pointer to the user interface form elements. */
};

namespace Ui {
class PacketFormatJSONGroupBox;
}

/**
 * @brief Group box for configuring JSON packet formatting options.
 */
class PacketFormatJSONGroupBox : public PacketFormatGroupBox
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a PacketFormatJSONGroupBox.
     * @param parent The parent widget.
     */
    explicit PacketFormatJSONGroupBox(QWidget *parent = 0);

    /**
     * @brief Destroys the PacketFormatJSONGroupBox.
     */
    ~PacketFormatJSONGroupBox();

    /**
     * @brief Checks if the JSON format configuration is valid.
     * @return True if the configuration is valid, false otherwise.
     */
    bool isValid() const override;

    /**
     * @brief Updates the print arguments with the JSON format settings.
     * @param print_args The print arguments structure to update.
     */
    void updatePrintArgs(print_args_t& print_args) override;

    /**
     * @brief Checks if duplicate keys are excluded from the JSON output.
     * @return True if duplicate keys are omitted, false otherwise.
     */
    bool noDuplicateKeys();

private:
    /**
     * @brief Checks if JSON values output is enabled.
     * @return True if enabled, false otherwise.
     */
    bool valuesEnabled() const;

    /**
     * @brief Checks if JSON bytes output is enabled.
     * @return True if enabled, false otherwise.
     */
    bool bytesEnabled() const;

    Ui::PacketFormatJSONGroupBox *pf_ui_; /**< Pointer to the user interface form elements. */
};

namespace Ui {
class PacketFormatCSVGroupBox;
}

/**
 * @brief Group box for configuring CSV packet formatting options.
 */
class PacketFormatCSVGroupBox : public PacketFormatGroupBox
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a PacketFormatCSVGroupBox.
     * @param parent The parent widget.
     */
    explicit PacketFormatCSVGroupBox(QWidget *parent = 0);

    /**
     * @brief Destroys the PacketFormatCSVGroupBox.
     */
    ~PacketFormatCSVGroupBox();

    /**
     * @brief Checks if the CSV format configuration is valid.
     * @return True if the configuration is valid, false otherwise.
     */
    bool isValid() const override;

    /**
     * @brief Updates the print arguments with the CSV format settings.
     * @param print_args The print arguments structure to update.
     */
    void updatePrintArgs(print_args_t& print_args) override;

protected slots:
    void utf8Toggled(bool checked);

private:
    /**
     * @brief Checked if UTF-8 CSV output is enabled.
     * @return True if enabled, false otherwise.
     */
    bool UTF8Enabled() const;

    /**
     * @brief Checks if tabs, newlines, and other whitespace should be escaped as in C.
     * @return True if C-style escapes should be used, false otherwise.
     */
    bool escapeWSP() const;

    /**
     * @brief Checks if the file should begin with a Byte Order Mark, for Windows.
     * @return True if a BOM should be printed, false otherwise.
     */
    bool printBOM() const;

    Ui::PacketFormatCSVGroupBox *pf_ui_; /**< Pointer to the user interface form elements. */
};

#endif // PACKET_FORMAT_GROUP_BOX_H
