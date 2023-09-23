/* rtp_audio_silence_stream.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rtp_audio_silence_generator.h"
#include <ws_attributes.h>

AudioSilenceGenerator::AudioSilenceGenerator(QObject *parent) :
    QIODevice(parent),
    pos_(0)
{
    QIODevice::open(QIODevice::ReadOnly);
}

qint64 AudioSilenceGenerator::size() const
{
    return std::numeric_limits <qint64>::max();
}

qint64 AudioSilenceGenerator::pos() const
{
    return pos_;
}

bool AudioSilenceGenerator::seek(qint64 off)
{
    pos_ = off;
    return true;
}

qint64 AudioSilenceGenerator::readData(char *data, qint64 maxSize)
{
    memset(data, 0, maxSize);
    pos_ += maxSize;

    return maxSize;
}

qint64 AudioSilenceGenerator::writeData(const char *data _U_, qint64 maxSize)
{
    return maxSize;
}
