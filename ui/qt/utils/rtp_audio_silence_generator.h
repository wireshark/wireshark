/* rtp_audio_silence_stream.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_AUDIO_SILENCE_GENERATOR_H
#define RTP_AUDIO_SILENCE_GENERATOR_H

#include "config.h"

#include <QIODevice>

class AudioSilenceGenerator: public QIODevice
{
    Q_OBJECT

public:
    explicit AudioSilenceGenerator();
    ~AudioSilenceGenerator() { }

    qint64 size() const override;
    qint64 pos() const override;
    bool seek(qint64 off) override;

protected:
    qint64 readData(char *data, qint64 maxSize) override;
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    quint64 pos_;
};

#endif // RTP_AUDIO_SILENCE_GENERATOR_H
