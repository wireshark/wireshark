/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IMPORT_TEXT_DIALOG_H
#define IMPORT_TEXT_DIALOG_H

#include <config.h>

#include <stdio.h>

#include "ui/text_import.h"

#include <ui/qt/widgets/syntax_line_edit.h>

#include <QDialog>
#include <QPushButton>
#include <QRadioButton>
#include <QButtonGroup>

namespace Ui {
class ImportTextDialog;
}

/**
 * @brief A dialog for importing packets from a text file (hex dump or regex formats).
 */
class ImportTextDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ImportTextDialog.
     * @param parent The parent widget, defaults to 0.
     */
    explicit ImportTextDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the ImportTextDialog.
     */
    ~ImportTextDialog();

    /**
     * @brief Retrieves the generated capture file name resulting from the import.
     * @return A reference to the capture file name string.
     */
    QString &capfileName();

private:
    /**
     * @brief Enables or disables specific header configuration widgets based on the chosen encapsulation.
     * @param encapsulation The wiretap encapsulation type (e.g., WTAP_ENCAP_ETHERNET).
     */
    void enableHeaderWidgets(uint encapsulation = WTAP_ENCAP_ETHERNET);

    /* regex fields */
    /**
     * @brief Enables or disables field configuration widgets used for regex imports.
     * @param enable_direction_input True if direction indicators are supported by the regex.
     * @param enable_time_input True if time input is supported by the regex.
     */
    void enableFieldWidgets(bool enable_direction_input = true, bool enable_time_input = true);

    /**
     * @brief Validates numeric input from a line edit and highlights it accordingly.
     * @param le The line edit to check.
     * @param ok_enable A boolean reference updated to false if validation fails.
     * @param num_str The string value to validate.
     * @param base The numeric base (e.g., 10 or 16).
     * @param max_val The maximum allowed value.
     * @param is_short True if the value should be treated as a 16-bit short.
     * @param val_ptr Pointer to store the successfully converted unsigned integer.
     */
    void check_line_edit(SyntaxLineEdit *le, bool &ok_enable, const QString &num_str, int base, unsigned max_val, bool is_short, unsigned *val_ptr);

    /**
     * @brief Validates an IPv4 address input and highlights the line edit.
     * @param le The line edit to check.
     * @param ok_enable A boolean reference updated to false if validation fails.
     * @param addr_str The IP address string.
     * @param val_ptr Pointer to store the successfully converted IPv4 address.
     */
    void checkAddress(SyntaxLineEdit *le, bool &ok_enable, const QString &addr_str, ws_in4_addr *val_ptr);

    /**
     * @brief Validates an IPv6 address input and highlights the line edit.
     * @param le The line edit to check.
     * @param ok_enable A boolean reference updated to false if validation fails.
     * @param addr_str The IPv6 address string.
     * @param val_ptr Pointer to store the successfully converted IPv6 address.
     */
    void checkIPv6Address(SyntaxLineEdit *le, bool &ok_enable, const QString &addr_str, ws_in6_addr *val_ptr);

    /**
     * @brief Validates the provided date/time format string.
     * @param time_format The format string to validate.
     * @return True if the format is valid, false otherwise.
     */
    bool checkDateTimeFormat(const QString &time_format);

    /**
     * @brief Loads previously saved import settings from the configuration file.
     */
    void loadSettingsFile();

    /**
     * @brief Saves the current import settings to the configuration file.
     */
    void saveSettingsFile();

    /**
     * @brief Applies loaded settings to update the dialog's UI state.
     */
    void applyDialogSettings();

    /**
     * @brief Extracts current dialog UI states and stores them in the settings map.
     */
    void storeDialogSettings();

    /**
     * @brief Evaluates all validity flags and enables/disables the Import button accordingly.
     */
    void updateImportButtonState();

    /** Pointer to the generated UI elements. */
    Ui::ImportTextDialog *ti_ui_;

    /** Map storing import dialog settings for persistence. */
    QVariantMap settings;

    /** Pointer to the Import button in the dialog. */
    QPushButton *import_button_;

    /** Group of radio buttons used to select dummy header types. */
    QButtonGroup *encap_buttons;

    /** Core structure containing data about the text import process. */
    text_import_info_t import_info_;

    /** The name of the resulting capture file. */
    QString capfile_name_;

    /** Flag indicating if the input text file is valid and readable. */
    bool file_ok_;

    /** Flag indicating if the timestamp format string is valid. */
    bool timestamp_format_ok_;

    /* Regex input */

    /** Flag indicating if the provided regular expression is valid. */
    bool regex_ok_;

    /** Flag indicating if the regex contains a named group for direction. */
    bool re_has_dir_;

    /** Flag indicating if the 'in' direction indicator is valid. */
    bool in_indication_ok_;

    /** Flag indicating if the 'out' direction indicator is valid. */
    bool out_indication_ok_;

    /** Flag indicating if the regex contains a named group for time. */
    bool re_has_time_;

    /** Flag indicating if the entered EtherType is valid. */
    bool ether_type_ok_;

    /** Flag indicating if the entered Protocol ID is valid. */
    bool proto_ok_;

    /** Flag indicating if the entered source IP address is valid. */
    bool source_addr_ok_;

    /** Flag indicating if the entered destination IP address is valid. */
    bool dest_addr_ok_;

    /** Flag indicating if the entered source port is valid. */
    bool source_port_ok_;

    /** Flag indicating if the entered destination port is valid. */
    bool dest_port_ok_;

    /** Flag indicating if the SCTP Data tag is valid. */
    bool tag_ok_;

    /** Flag indicating if the SCTP PPI is valid. */
    bool ppi_ok_;

    /** Flag indicating if the payload configuration is valid. */
    bool payload_ok_;

    /** Flag indicating if the maximum frame length value is valid. */
    bool max_len_ok_;

public slots:
    /**
     * @brief Shows the dialog as a modal window, blocking until the user closes it.
     * @return The dialog result (e.g., QDialog::Accepted or QDialog::Rejected).
     */
    int exec();

private slots:
    /**
     * @brief Slot triggered when the browse button for the input text file is clicked.
     */
    void on_textFileBrowseButton_clicked();

    /**
     * @brief Slot triggered when the text in the input file line edit changes.
     * @param arg1 The new file path string.
     */
    void on_textFileLineEdit_textChanged(const QString &arg1);

    /**
     * @brief Slot triggered when the active tab in the mode selector (Hex/Regex) changes.
     * @param index The index of the newly active tab.
     */
    void on_modeTabWidget_currentChanged(int index);

    /**
     * @brief Slot triggered when the text in the timestamp format line edit changes.
     * @param arg1 The new format string.
     */
    void on_timestampFormatLineEdit_textChanged(const QString &arg1);

    /* Hex Dump input */
    /**
     * @brief Slot triggered when the "No Offset" checkbox is toggled.
     * @param checked True if the hex dump contains no offsets.
     */
    void on_noOffsetButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the "Direction Indication" checkbox is toggled.
     * @param checked True if the hex dump contains direction indicators.
     */
    void on_directionIndicationCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the "ASCII Identification" checkbox is toggled.
     * @param checked True if the hex dump contains ASCII text alongside hex.
     */
    void on_asciiIdentificationCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the "Little Endian" checkbox is toggled.
     * @param checked True if the imported values should be treated as little-endian.
     */
    void on_littleEndianCheckBox_toggled(bool checked);

    /* Regex input */
    /**
     * @brief Slot triggered when the text in the regular expression edit box changes.
     */
    void on_regexTextEdit_textChanged();

    /**
     * @brief Slot triggered when the data encoding combo box selection changes.
     * @param index The index of the newly selected encoding.
     */
    void on_dataEncodingComboBox_currentIndexChanged(int index);

    /**
     * @brief Slot triggered when the text defining the "In" direction indicator changes.
     * @param arg1 The new indicator string.
     */
    void on_dirInIndicationLineEdit_textChanged(const QString &arg1);

    /**
     * @brief Slot triggered when the text defining the "Out" direction indicator changes.
     * @param arg1 The new indicator string.
     */
    void on_dirOutIndicationLineEdit_textChanged(const QString &arg1);

    /* Encapsulation input */
    /**
     * @brief Slot triggered when the primary encapsulation combo box selection changes.
     * @param index The index of the new encapsulation type.
     */
    void on_encapComboBox_currentIndexChanged(int index);

    /**
     * @brief Slot triggered when any of the dummy header radio buttons are toggled.
     * @param button The button that was toggled.
     * @param checked True if the button is now checked.
     */
    void encap_buttonsToggled(QAbstractButton *button, bool checked);

    /**
     * @brief Slot triggered when the IP version combo box selection changes.
     * @param index The index corresponding to IPv4 or IPv6.
     */
    void on_ipVersionComboBox_currentIndexChanged(int index);

    /**
     * @brief Slot triggered when the text in the EtherType line edit changes.
     * @param ethertype_str The new EtherType string.
     */
    void on_ethertypeLineEdit_textChanged(const QString &ethertype_str);

    /**
     * @brief Slot triggered when the text in the Protocol line edit changes.
     * @param protocol_str The new protocol string.
     */
    void on_protocolLineEdit_textChanged(const QString &protocol_str);

    /**
     * @brief Slot triggered when the text in the source address line edit changes.
     * @param source_addr_str The new source IP address string.
     */
    void on_sourceAddressLineEdit_textChanged(const QString &source_addr_str);

    /**
     * @brief Slot triggered when the text in the destination address line edit changes.
     * @param destination_addr_str The new destination IP address string.
     */
    void on_destinationAddressLineEdit_textChanged(const QString &destination_addr_str);

    /**
     * @brief Slot triggered when the text in the source port line edit changes.
     * @param source_port_str The new source port string.
     */
    void on_sourcePortLineEdit_textChanged(const QString &source_port_str);

    /**
     * @brief Slot triggered when the text in the destination port line edit changes.
     * @param destination_port_str The new destination port string.
     */
    void on_destinationPortLineEdit_textChanged(const QString &destination_port_str);

    /**
     * @brief Slot triggered when the text in the SCTP Data tag line edit changes.
     * @param tag_str The new tag string.
     */
    void on_tagLineEdit_textChanged(const QString &tag_str);

    /**
     * @brief Slot triggered when the text in the SCTP PPI line edit changes.
     * @param ppi_str The new PPI string.
     */
    void on_ppiLineEdit_textChanged(const QString &ppi_str);

    /* Footer input */
    /**
     * @brief Slot triggered when the text in the maximum frame length line edit changes.
     * @param max_frame_len_str The new length string.
     */
    void on_maxLengthLineEdit_textChanged(const QString &max_frame_len_str);

    /**
     * @brief Slot triggered when help is requested from the dialog's button box.
     */
    void on_buttonBox_helpRequested();
};


#endif // IMPORT_TEXT_DIALOG_H
