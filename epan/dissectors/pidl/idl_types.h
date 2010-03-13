#define STR_ASCII	LIBNDR_FLAG_STR_ASCII
#define STR_LEN4	LIBNDR_FLAG_STR_LEN4
#define STR_SIZE4	LIBNDR_FLAG_STR_SIZE4
#define STR_SIZE2	LIBNDR_FLAG_STR_SIZE2
#define STR_NOTERM	LIBNDR_FLAG_STR_NOTERM
#define STR_NULLTERM	LIBNDR_FLAG_STR_NULLTERM
#define STR_BYTESIZE	LIBNDR_FLAG_STR_BYTESIZE
#define STR_CONFORMANT  LIBNDR_FLAG_STR_CONFORMANT
#define STR_CHARLEN	LIBNDR_FLAG_STR_CHARLEN
#define STR_UTF8	LIBNDR_FLAG_STR_UTF8

/*
  a null terminated UCS2 string
*/
#define nstring		[flag(STR_NULLTERM)] string

/*
  an ascii string prefixed with [offset] [length], both 32 bits
  null terminated
*/
#define ascstr2		[flag(STR_ASCII|STR_LEN4)] string

/*
  an ascii string prefixed with [size], 32 bits
*/
#define asclstr		[flag(STR_ASCII|STR_SIZE4)] string

/*
  an ascii string prefixed with [size], 16 bits
  null terminated
*/
#define ascstr3		[flag(STR_ASCII|STR_SIZE2)] string

/*
  an ascii string prefixed with [size] [offset] [length], all 32 bits
  not null terminated
*/
#define ascstr_noterm	[flag(STR_NOTERM|STR_ASCII|STR_SIZE4|STR_LEN4)] string

/*
  a null terminated ascii string
*/
#define astring		[flag(STR_ASCII|STR_NULLTERM)] string

/*
  a null terminated UTF8 string
*/
#define utf8string	[flag(STR_UTF8|STR_NULLTERM)] string

/*
  a null terminated UCS2 string
*/
#define nstring_array	[flag(STR_NULLTERM)] string_array

#define NDR_NOALIGN       LIBNDR_FLAG_NOALIGN
#define NDR_REMAINING     LIBNDR_FLAG_REMAINING
#define NDR_ALIGN2        LIBNDR_FLAG_ALIGN2
#define NDR_ALIGN4        LIBNDR_FLAG_ALIGN4
#define NDR_ALIGN8        LIBNDR_FLAG_ALIGN8

/* this flag is used to force a section of IDL as little endian. It is
   needed for the epmapper IDL, which is defined as always being LE */
#define NDR_LITTLE_ENDIAN LIBNDR_FLAG_LITTLE_ENDIAN
#define NDR_BIG_ENDIAN LIBNDR_FLAG_BIGENDIAN

/*
  this is used to control formatting of uint8 arrays
*/
#define NDR_PAHEX LIBNDR_PRINT_ARRAY_HEX

#define NDR_RELATIVE_REVERSE LIBNDR_FLAG_RELATIVE_REVERSE
#define NDR_NO_RELATIVE_REVERSE LIBNDR_FLAG_NO_RELATIVE_REVERSE
