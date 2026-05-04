/** @file
 *
 * randpkt_core.h
 * ---------
 * Creates random packet traces. Useful for debugging sniffers by testing
 * assumptions about the veracity of the data found in the packet.
 *
 * Copyright (C) 1999 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RANDPKT_CORE_H__
#define __RANDPKT_CORE_H__

#include <glib.h>
#include "wiretap/wtap.h"

typedef struct {
	const char*  abbrev;
	const char*  longname;
	int          produceable_type;
	int          sample_wtap_encap;
	uint8_t*     sample_buffer;
	int          sample_length;
	uint8_t*     pseudo_buffer;
	unsigned     pseudo_length;
	wtap_dumper* dump;
	const char*  filename;
	unsigned     produce_max_bytes;

} randpkt_example;

/* Return the number of active examples */

/**
 * @brief Return the count of active examples.
 *
 * @return The number of active examples.
 */
unsigned randpkt_example_count(void);

/**
 * @brief Returns the list of active examples, including their abbreviations and long names.
 *
 * @param abbrev_list Pointer to a list where the abbreviations of the examples will be stored.
 * @param longname_list Pointer to a list where the long names of the examples will be stored.
 */
void randpkt_example_list(char*** abbrev_list, char*** longname_list);

/**
 * @brief Parse command-line option "type" and return enum type
 *
 * @param string The string to parse, which may be NULL or empty to indicate a random type.
 * @return The enum type corresponding to the string, or a random type if the string is NULL or empty. Returns -1 if the type is not known.
 */
int randpkt_parse_type(char *string);

/**
 * @brief Find pkt_example record and return pointer to it.
 *
 * @param type The type of the example to find.
 * @return randpkt_example* A pointer to the found pkt_example record, or NULL if not found.
 */
randpkt_example* randpkt_find_example(int type);

/* Init a new example */
/**
 * @brief Initializes a random packet example with parameters for packet production.
 *
 * This function initializes the necessary structures and opens the file or standard output
 * to begin producing random packets.
 *
 * @param example Pointer to the randpkt_example structure to be initialized.
 * @param produce_filename The filename where packets will be written, or "-" for stdout.
 * @param produce_max_bytes The maximum number of bytes per packet.
 * @param file_type_subtype The type and subtype of the file format.
 * @return 0 on success, non-zero on failure.
 */
int randpkt_example_init(randpkt_example* example, char* produce_filename, int produce_max_bytes, int file_type_subtype);

/* Loop the packet generation */

/**
 * @brief Loops to produce a specified number of random packets with a given delay.
 *
 * This function generates and sends a series of random packets, each delayed by a specified amount of time.
 *
 * @param example Pointer to the randpkt_example structure containing configuration and state information.
 * @param produce_count The number of packets to generate and send.
 * @param packet_delay_ms The delay in milliseconds between sending each packet.
 */
void randpkt_loop(randpkt_example* example, uint64_t produce_count, uint64_t packet_delay_ms);

/* Close the current example */

/**
 * @brief Closes a random packet example.
 *
 * This function closes the specified random packet example, ensuring all resources are properly released.
 *
 * @param example Pointer to the randpkt_example structure to be closed.
 * @return true if the close operation was successful, false otherwise.
 */
bool randpkt_example_close(randpkt_example* example);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
