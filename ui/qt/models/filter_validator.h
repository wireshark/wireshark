/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_VALIDATOR_H
#define FILTER_VALIDATOR_H

#include <QValidator>
#include <QString>

/**
 * @brief Abstract QValidator for filter expressions, attachable to any QLineEdit.
 *
 * Plain QValidator is insufficient for filter editing: its State is only
 * Invalid/Intermediate/Acceptable and it carries no error text, error location,
 * or deprecation information. FilterValidator extends it with a Detail accessor
 * that the host widget reads immediately after calling validate().
 *
 * The validator is intended to be single-owner: each instance is permanently
 * attached to one widget, so the "validate() then read lastDetail()"
 * stash-and-read pattern is safe and non-reentrant.
 *
 * Subclasses (DisplayFilterValidator, CaptureFilterValidator) implement
 * validate() against their respective compilers and return matching Detail.
 */
class FilterValidator : public QValidator
{
    Q_OBJECT

public:
    /**
     * @brief Diagnostic detail produced by the most recent validate() call.
     */
    struct Detail {
        int     errPos = -1;     /**< Byte offset of the error; -1 if none/unknown. */
        int     errLen = 0;      /**< Span length, for location annotation. */
        QString errMsg;          /**< Short error message; empty if no error. */
        QString deprecatedToken; /**< Non-empty when the input is valid but deprecated. */
    };

    explicit FilterValidator(QObject *parent = nullptr);

    /**
     * @brief Validates @p input and updates the stashed Detail.
     * @param input The text to validate; may be normalised in place.
     * @param pos   In/out cursor position.
     * @return Invalid, Intermediate, or Acceptable.
     */
    QValidator::State validate(QString &input, int &pos) const override = 0;

    /**
     * @brief Returns the Detail produced by the most recent validate() call.
     */
    virtual Detail lastDetail() const = 0;

    /** @brief Short error message from the last validation (Detail::errMsg). */
    QString lastError() const { return lastDetail().errMsg; }

    /**
     * @brief Full, location-annotated error message for @p filter.
     *
     * Combines the expression with a caret/underline marking the error span
     * reported in lastDetail(). Returns an empty string when there is no error.
     */
    QString lastErrorFull(const QString &filter) const;

    /** @brief The deprecated token from the last validation, or empty. */
    QString deprecatedToken() const { return lastDetail().deprecatedToken; }

    /**
     * @brief Builds a full, location-annotated error string.
     * @param filter      The expression that failed validation.
     * @param err_msg     Short error message.
     * @param loc_start   Zero-based offset where the error begins.
     * @param loc_length  Number of characters the error spans.
     */
    static QString createSyntaxErrorMessageFull(const QString &filter,
                                                const QString &err_msg,
                                                qsizetype loc_start,
                                                size_t loc_length);
};

#endif // FILTER_VALIDATOR_H
