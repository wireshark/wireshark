/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_VALIDATOR_H
#define CAPTURE_FILTER_VALIDATOR_H

#include <ui/qt/models/filter_validator.h>

/**
 * @brief FilterValidator for libpcap/BPF capture filters.
 *
 * validate() compiles the expression with pcap_compile() against the DLTs of
 * the currently selected capture interfaces (and verifies extcap interfaces via
 * extcap_verify_capture_filter()), mirroring the old CaptureFilterSyntaxWorker.
 *
 * The check is synchronous: it runs on the host widget's debounce and returns
 * immediately, giving instant in-place feedback. (The old code ran it on a
 * background thread because pcap_compile() may call gethostbyname() and block on
 * DNS for filters that name hosts; the synchronous form can briefly lag on such
 * input. The Busy state is reserved in FilterEdit for re-introducing an async
 * path if that ever proves necessary.)
 *
 * Cases the BPF backend cannot definitively check — DLT_USER interfaces, BPF
 * extensions that need a live handle, unknown extcap status — are reported as
 * Acceptable with a non-empty Detail::deprecatedToken so the host maps them to
 * the (amber) Deprecated state, matching historical behaviour.
 */
class CaptureFilterValidator : public FilterValidator
{
    Q_OBJECT

public:
    explicit CaptureFilterValidator(QObject *parent = nullptr);

    QValidator::State validate(QString &input, int &pos) const override;
    Detail lastDetail() const override { return detail_; }

private:
    mutable Detail detail_; /**< Stash for the most recent validate(); single-owner. */
};

#endif // CAPTURE_FILTER_VALIDATOR_H
