
/* we limit the number of BPF records a jmp can take by using a few of the
 * jmp values as special identifiers during the compilation process. Many
 * pieces of code need to jump to the end of the entire BPF block, returing
 * either a successful value or a failure value (either the number of bytes
 * to read, or 0). The code creator uses these 4 variables to represent
 * the retval of failure or success, then the code cleaner fills in the
 * true value for these variables.
 */
#define NO_LABEL			255
#define END_OF_PROGRAM_FAILURE		254
#define END_OF_PROGRAM_SUCCESS		253
#define NEXT_BLOCK			252

void
wtap_filter_bpf_init(void);

void
wtap_filter_offline_init(wtap *wth);

void
wtap_filter_offline_clear(wtap *wth);
