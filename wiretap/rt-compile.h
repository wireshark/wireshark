
#ifndef __WTAP_H_
#include "wtap.h"
#endif

/* Holds info for fields defined as bytecmp. */
typedef struct {
	int	ftype;
	int	ctype;
	int	offset;
	int	length;
} bytecmp_info;


/* Holds info for fields defined as either_of */
typedef struct {
	int	ftype;
	int	ctype;
	int	field1;
	int	field2;
} eitherof_info;

int wtap_lex(void);
int wtap_parse(void);
void wtap_error(char *string);

void lex_init(char *);

int wtap_offline_filter_compile(wtap *wth, int encap_type);
