#ifndef WIRESHARK_MARINE_DEV_H
#define WIRESHARK_MARINE_DEV_H

#include <stdlib.h>
#include <stdio.h>
#include <zconf.h>

/*
* Author:  David Robert Nadeau
* Site:    http://NadeauSoftware.com/
* License: Creative Commons Attribution 3.0 Unported License
*          http://creativecommons.org/licenses/by/3.0/deed.en_US
*/
size_t get_current_rss(void) {
    long rss = 0L;
    FILE *fp = NULL;
    if ((fp = fopen("/proc/self/statm", "r")) == NULL) {
        return (size_t) 0L;
    }
    if (fscanf(fp, "%*s%ld", &rss) != 1) {
        fclose(fp);
        return (size_t) 0L;
    }
    fclose(fp);
    return (size_t) rss * (size_t) sysconf(_SC_PAGESIZE);
}

#endif //WIRESHARK_MARINE_DEV_H
