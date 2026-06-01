/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_COMPLETER_H
#define CAPTURE_FILTER_COMPLETER_H

#include <ui/qt/models/filter_completer.h>

class QStringListModel;

/**
 * @brief FilterCompleter for libpcap capture filters.
 *
 * Sets the libpcap primitive token-character set and supplies the fixed list of
 * pcap-filter primitives as a completion source. libpcap has a small, closed set
 * of primitives, so the whole list is offered (the host merges it with recent +
 * saved filters via QConcatenateTablesProxyModel for the full typeahead source).
 */
class CaptureFilterCompleter : public FilterCompleter
{
    Q_OBJECT

public:
    explicit CaptureFilterCompleter(QObject *parent = nullptr);

    /**
     * @brief A model over the fixed libpcap primitive list, owned by this
     *        completer. The host adds it as a source of the merged completion
     *        model alongside history and bookmarks.
     */
    QStringListModel *primitivesModel() const { return primitives_; }

    /** @brief The fixed list of libpcap filter primitives. */
    static QStringList primitives();

private:
    QStringListModel *primitives_; /**< Owned primitive list model. */
};

#endif // CAPTURE_FILTER_COMPLETER_H
