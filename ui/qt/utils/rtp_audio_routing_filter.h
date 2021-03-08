/* rtp_audio_routing_filter.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_AUDIO_ROUTING_FILTER_H
#define RTP_AUDIO_ROUTING_FILTER_H

#include "config.h"

#include <ui/rtp_media.h>
#include <ui/qt/utils/rtp_audio_routing.h>

#include <QObject>
#include <QIODevice>

class AudioRoutingFilter: public QIODevice
{
    Q_OBJECT

public:
    explicit AudioRoutingFilter(QIODevice *input, bool stereo_required, AudioRouting audio_routing);
    ~AudioRoutingFilter() { }

    void close() override;
    qint64 size() const override;
    qint64 pos() const override;
    bool seek(qint64 off) override;

protected:
    qint64 readData(char *data, qint64 maxSize) override;
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    QIODevice *input_;
    bool stereo_required_;
    AudioRouting audio_routing_;
};

#endif // RTP_AUDIO_ROUTING_FILTER_H
