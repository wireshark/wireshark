/* rtp_audio_routing.h
 * Declarations of RTP audio routing class
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_AUDIO_ROUTING_H
#define RTP_AUDIO_ROUTING_H

#include "config.h"

#include <QMetaType>

typedef enum {
    channel_any,          // Used just for changes of mute
    channel_mono,         // Play
    channel_stereo_left,  // L
    channel_stereo_right, // R
    channel_stereo_both   // L+R
} audio_routing_channel_t;

class AudioRouting
{
public:
    AudioRouting() = default;
    ~AudioRouting() = default;
    AudioRouting(const AudioRouting &) = default;
    AudioRouting &operator=(const AudioRouting &) = default;

    AudioRouting(bool muted, audio_routing_channel_t channel);
    bool isMuted() { return muted_; }
    void setMuted(bool muted) { muted_ = muted; }
    audio_routing_channel_t getChannel() { return channel_; }
    void setChannel(audio_routing_channel_t channel) { channel_ = channel; }
    char const *formatAudioRoutingToString();
    AudioRouting getNextChannel(bool stereo_available);
    AudioRouting convert(bool stereo_available);
    void mergeAudioRouting(AudioRouting new_audio_routing);

private:
    bool muted_;
    audio_routing_channel_t channel_;
};
Q_DECLARE_METATYPE(AudioRouting)

#define AUDIO_MUTED true
#define AUDIO_UNMUTED false


#endif // RTP_AUDIO_ROUTING_H
