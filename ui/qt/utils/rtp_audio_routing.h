/** @file
 *
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

/**
 * @brief Audio routing destination for a single audio stream.
 */
typedef enum {
    channel_any,          /**< used only when changing mute state. */
    channel_mono,         /**< Mono playback on a single output. */
    channel_stereo_left,  /**< Stereo output, left channel only. */
    channel_stereo_right, /**< Stereo output, right channel only. */
    channel_stereo_both   /**< Stereo output, both left and right channels. */
} audio_routing_channel_t;


/**
 * @brief Encapsulates the mute state and channel assignment for one audio stream.
 */
class AudioRouting
{
public:
    /**
     * @brief Construct a default AudioRouting with unmuted mono output.
     */
    AudioRouting() = default;

    /**
     * @brief Destruct an AudioRouting.
     */
    ~AudioRouting() = default;

    /**
     * @brief Copy an AudioRouting.
     */
    AudioRouting(const AudioRouting &) = default;

    /**
     * @brief Assign an AudioRouting.
     * @param other The AudioRouting to copy.
     * @return A reference to this AudioRouting.
     */
    AudioRouting &operator=(const AudioRouting &) = default;

    /**
     * @brief Construct an AudioRouting with explicit mute state and channel.
     * @param muted   true if the stream should be silenced; false to play.
     * @param channel The output channel assignment for this stream.
     */
    AudioRouting(bool muted, audio_routing_channel_t channel);

    /**
     * @brief Return whether the stream is currently muted.
     * @return true if the stream is muted; false if it is audible.
     */
    bool isMuted() { return muted_; }

    /**
     * @brief Set the mute state of the stream.
     * @param muted true to silence the stream; false to make it audible.
     */
    void setMuted(bool muted) { muted_ = muted; }

    /**
     * @brief Return the current channel assignment.
     * @return The active @c audio_routing_channel_t value.
     */
    audio_routing_channel_t getChannel() { return channel_; }

    /**
     * @brief Set the channel assignment.
     * @param channel The new channel destination for this stream.
     */
    void setChannel(audio_routing_channel_t channel) { channel_ = channel; }

    /**
     * @brief Return a human-readable string describing this routing.
     *
     * @return A null-terminated string literal describing the routing.
     *         The caller must not free or modify this pointer.
     */
    char const *formatAudioRoutingToString();

    /**
     * @brief Return the next logical channel in the cycling order.
     *
     * @param stereo_available true if the audio device supports stereo
     *                         output; false for mono-only devices.
     * @return A new AudioRouting with the mute state preserved and the
     *         channel advanced to the next value in the cycle.
     */
    AudioRouting getNextChannel(bool stereo_available);

    /**
     * @brief Convert this routing to be valid for the given output capability.
     *
     * @param stereo_available true if the audio device supports stereo.
     * @return A valid AudioRouting for the given output capability.
     */
    AudioRouting convert(bool stereo_available);

    /**
     * @brief Merge an updated routing into this object.
     * @param new_audio_routing The incoming routing update to apply.
     */
    void mergeAudioRouting(AudioRouting new_audio_routing);

private:
    bool muted_; /**< true if this stream is muted. */
    audio_routing_channel_t channel_; /**< Current output channel assignment. */
};
Q_DECLARE_METATYPE(AudioRouting)

#define AUDIO_MUTED true
#define AUDIO_UNMUTED false


#endif // RTP_AUDIO_ROUTING_H
