#include <netinet/if_ether.h>

/**
* MacOS does not have the netinet/ether.h file so we are using netinet/if_ether.h instead.
* In addition, for some reason MacOS does not supply the iphdr struct, so we define it.
*/

typedef struct iphdr {
        uint8_t 	version:4,
                        ihl:4;
        uint8_t	        tos;
        uint16_t        tot_len;
        uint16_t        id;
        uint16_t        frag_off;
        uint8_t         ttl;
        uint8_t         protocol;
        uint16_t        check;
        uint32_t        saddr;
        uint32_t        daddr;
} iphdr;

