

extern GList* (*mk_bytecmp)
	(int ftype, int rel_opcode, guint8 *bytes);

extern void (*mk_optimize)
	(GList *L);


/* for those modules that are interested in mk_attach,
 * wtap.h will have already been included.
 */
#ifdef __WTAP_H__
extern int (*mk_attach)
	(wtap *wth);
#endif

extern bytecmp_info bytecmp_table[];
extern int comp_encap_type;
extern int filter_parsed;

bytecmp_info* lookup_bytecmp(int ftype);
eitherof_info* lookup_eitherof(int ftype);
