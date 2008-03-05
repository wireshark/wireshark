/* Included *after* config.h, in order to re-define these macros */

#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "ethercat"

#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */
/*#define VERSION "0.0.6"   * first version */
/*#define VERSION "0.0.7"   * new dissector for mailbox inserted */
/*#define VERSION "0.0.9"   * nv-protocol inserted */
/*#define VERSION "0.0.10"  */
/*#define VERSION "0.0.11"  * support of AoE protocol */
/*#define VERSION "0.0.12"  * port to Wireshark */
/*#define VERSION "0.1.0"   * First version integrated into the Wireshark sources*/
#define VERSION "0.1.1"    /* Added the ability for sub dissectors to decode the data section of EtherCAT using heuristics */
