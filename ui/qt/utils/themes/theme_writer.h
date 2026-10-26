/* theme_writer.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_WRITER_H
#define THEME_WRITER_H

#include "ui/qt/utils/theme_manager.h"

#include <QByteArray>
#include <QColor>
#include <QCoreApplication>
#include <QList>
#include <QString>

/**
 * Serializes a ThemeDraft to a theme file (JSONC) and names theme files.
 *
 * The output is the one canonical form: fixed section order, schema key
 * spelling, one color per line.  Only the keys a draft sets are written.
 */
class ThemeWriter
{
    Q_DECLARE_TR_FUNCTIONS(ThemeWriter)
public:
    /** One settable color of a theme file. */
    struct KeyInfo {
        ThemeManager::ThemeToken token;
        QString                  section; ///< Section name as written in the file
        QString                  key;     ///< Key name, schema spelling
        const char              *description; ///< What the color is used for, untranslated; translate in the "ThemeWriter" context
    };

    /**
     * All settable color keys in the order they are written.  The rows come
     * from ThemeManager::settableKeys() (enum order); the descriptions come
     * from the writer's own table and are shown by the Theme Designer.
     * Separator is not part of it because it is not inside a section.  Rows
     * of one section are contiguous; the order of the sections' first rows is
     * the order toJsonc() writes them in.
     */
    static const QList<KeyInfo> &keyTable();

    /**
     * @param token  the color token.
     * @return "<section>.<key>" as written in the file, or an empty string
     *         for a token that is not in keyTable().
     */
    static QString keyPath(ThemeManager::ThemeToken token);

    /**
     * @param info  a row of keyTable().
     * @return "<section>.<key>" as written in the file.
     */
    static QString keyPath(const KeyInfo &info);

    /**
     * @param color  the color.
     * @return "#rrggbb" for an opaque color, "#aarrggbb" otherwise (the form
     *         QColor reads back), or an empty string for an invalid color.
     */
    static QString colorText(const QColor &color);

    /**
     * Serializes a draft.  Color entries and graph slots with an invalid
     * side are skipped; callers clean the draft with
     * ThemeDraft::removeInvalidEntries() first.
     *
     * @param draft  the draft to serialize.
     * @return UTF-8 theme file content.
     */
    static QByteArray toJsonc(const ThemeDraft &draft);

    /**
     * Turns a theme name into a safe file stem: lowercase letters, digits,
     * '-' and '_'; anything else becomes '-'.
     *
     * @param name  theme name.
     * @return the stem, never empty.
     */
    static QString sanitizeStem(const QString &name);

    /**
     * Returns a stem for @p wanted that is neither a bundled theme nor an
     * existing personal theme file, appending -2, -3, ... when needed.
     *
     * @param wanted      theme name or stem.
     * @param ignoreStem  stem that counts as free (a rename keeping its stem).
     */
    static QString uniqueStem(const QString &wanted, const QString &ignoreStem = QString());

    /**
     * Writes a draft to @p path, creating the parent directory.
     *
     * @param draft        the draft to write.
     * @param path         destination file.
     * @param errorString  optional; set on failure.
     * @return true when the file was written completely.
     */
    static bool writeFile(const ThemeDraft &draft, const QString &path,
                          QString *errorString = nullptr);

private:
    ThemeWriter() = delete;
};

#endif /* THEME_WRITER_H */
