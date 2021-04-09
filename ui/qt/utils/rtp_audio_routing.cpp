/* rtp_audio_routing.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rtp_audio_routing.h"

AudioRouting::AudioRouting(bool muted, audio_routing_channel_t channel):
    muted_(muted),
    channel_(channel)
{
}

char const *AudioRouting::formatAudioRoutingToString()
{
    if (muted_) {
        return "Muted";
    } else {
        switch (channel_) {
            case channel_any:
                // Should not happen ever
                return "ERR";
            case channel_mono:
                return "Play";
            case channel_stereo_left:
                return "L";
            case channel_stereo_right:
                return "R";
            case channel_stereo_both:
                return "L+R";
        }
    }

    // Should not happen ever
    return "ERR";
}

AudioRouting AudioRouting::getNextChannel(bool stereo_available)
{
    if (stereo_available) {
        // Stereo
        if (muted_) {
            return AudioRouting(AUDIO_UNMUTED, channel_stereo_left);
        } else {
            switch (channel_) {
                case channel_stereo_left:
                    return AudioRouting(AUDIO_UNMUTED, channel_stereo_both);
                case channel_stereo_both:
                    return AudioRouting(AUDIO_UNMUTED, channel_stereo_right);
                case channel_stereo_right:
                    return AudioRouting(AUDIO_MUTED, channel_stereo_right);
                default:
                    return AudioRouting(AUDIO_UNMUTED, channel_stereo_left);
            }
        }
    } else {
        // Mono
        if (muted_) {
            return AudioRouting(AUDIO_UNMUTED, channel_mono);
        } else {
            return AudioRouting(AUDIO_MUTED, channel_mono);
        }
    }
}

AudioRouting AudioRouting::convert(bool stereo_available)
{
    // Muting is not touched by conversion

    if (stereo_available) {
        switch (channel_) {
            case channel_mono:
                // Mono -> Stereo
                return AudioRouting(muted_, channel_stereo_both);
            case channel_any:
                // Unknown -> Unknown
                return AudioRouting(muted_, channel_any);
            default:
                // Stereo -> Stereo
                return AudioRouting(muted_, channel_);
        }
    } else {
        switch (channel_) {
            case channel_mono:
                // Mono -> Mono
                return AudioRouting(muted_, channel_mono);
            case channel_any:
                // Unknown -> Unknown
                return AudioRouting(muted_, channel_any);
            default:
                // Stereo -> Mono
                return AudioRouting(muted_, channel_mono);
        }
    }
}

void AudioRouting::mergeAudioRouting(AudioRouting new_audio_routing)
{
    if (new_audio_routing.getChannel() == channel_any) {
      muted_ = new_audio_routing.isMuted();
    } else {
      muted_ = new_audio_routing.isMuted();
      channel_ = new_audio_routing.getChannel();
    }
}

