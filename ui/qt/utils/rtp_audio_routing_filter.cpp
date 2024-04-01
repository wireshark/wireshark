/* rtp_audio_routing_filter.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rtp_audio_routing_filter.h"

AudioRoutingFilter::AudioRoutingFilter(QIODevice *input, bool stereo_required, AudioRouting audio_routing) :
    QIODevice(input),
    input_(input),
    stereo_required_(stereo_required),
    audio_routing_(audio_routing)
{
    QIODevice::open(input_->openMode());
}

void AudioRoutingFilter::close()
{
    input_->close();
}

qint64 AudioRoutingFilter::size() const
{
    if (!stereo_required_)
    {
        return input_->size();
    } else {
        // For stereo we must return twice more bytes
        return input_->size() * 2;
    }
}

qint64 AudioRoutingFilter::pos() const
{
    if (!stereo_required_)
    {
        return input_->pos();
    } else {
        // For stereo we must return twice more bytes
        return input_->pos() * 2;
    }
}

bool AudioRoutingFilter::seek(qint64 off)
{
    if (!stereo_required_)
    {
        return input_->seek(off);
    } else {
        // For stereo we must return half of offset
        return input_->seek(off / 2);
    }
}

qint64 AudioRoutingFilter::readData(char *data, qint64 maxSize)
{
    if (!stereo_required_)
    {
        // For mono we just return data
        return input_->read(data, maxSize);
    } else {
        // For stereo
        int64_t silence = 0;

        // Read half of data
        qint64 readBytes = input_->read(data, maxSize/SAMPLE_BYTES);

        // If error or no data available, just return
        if (readBytes < 1)
            return readBytes;

        // Expand it
        for(qint64 i = (readBytes / SAMPLE_BYTES) - 1; i > 0; i--) {
            qint64 j = SAMPLE_BYTES * i;
            if (audio_routing_.getChannel() == channel_stereo_left) {
                memcpy(&data[j*2], &data[j], SAMPLE_BYTES);
                memcpy(&data[j*2+SAMPLE_BYTES], &silence, SAMPLE_BYTES);
            } else if (audio_routing_.getChannel() == channel_stereo_right) {
                memcpy(&data[j*2], &silence, SAMPLE_BYTES);
                memcpy(&data[j*2+SAMPLE_BYTES], &data[j], SAMPLE_BYTES);
            } else if (audio_routing_.getChannel() == channel_stereo_both) {
                memcpy(&data[j*2], &data[j], SAMPLE_BYTES);
                memcpy(&data[j*2+SAMPLE_BYTES], &data[j], SAMPLE_BYTES);
            } else {
                // Should not happen ever
                memcpy(&data[j*2], &silence, SAMPLE_BYTES*2);
            }
        }

        return readBytes * 2;
    }
}

qint64 AudioRoutingFilter::writeData(const char *data, qint64 maxSize)
{
    return input_->write(data, maxSize);
}


/*
bool AudioRoutingFilter::atEnd() const
{
  return input_->atEnd();
}

bool AudioRoutingFilter::canReadLine() const
{
  return input_->canReadLine();
}
*/
