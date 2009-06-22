#ifdef __cplusplus
extern "C" {
#endif

/* Global definitions for Reed-Solomon encoder/decoder
 * Phil Karn KA9Q, September 1996
 */
/* Set one of these to enable encoder/decoder debugging and error checking,
 * at the expense of speed */
/* #undef DEBUG 1*/
/* #undef DEBUG 2*/
#undef DEBUG

/* To select the CCSDS standard (255,223) code, define CCSDS. This
 * implies standard values for MM, KK, B0 and PRIM.
 */
/* #undef CCSDS 1*/
#undef CCSDS
#ifndef CCSDS

/* Otherwise, leave CCSDS undefined and set the parameters below:
 *
 * Set MM to be the size of each code symbol in bits. The Reed-Solomon
 * block size will then be NN = 2**M - 1 symbols. Supported values are
 * defined in rs.c.
 */
#define MM 8 /* Symbol size in bits */

/*
 * Set KK to be the number of data symbols in each block, which must be
 * less than the block size. The code will then be able to correct up
 * to NN-KK erasures or (NN-KK)/2 errors, or combinations thereof with
 * each error counting as two erasures.
 */
#define KK 207 /* Number of data symbols per block */

/* Set B0 to the first root of the generator polynomial, in alpha form, and
 * set PRIM to the power of alpha used to generate the roots of the
 * generator polynomial. The generator polynomial will then be
 * @**PRIM*B0, @**PRIM*(B0+1), @**PRIM*(B0+2)...@**PRIM*(B0+NN-KK)
 * where "@" represents a lower case alpha.
 */
#define B0 1 /* First root of generator polynomial, alpha form */
#define PRIM 1 /* power of alpha used to generate roots of generator poly */
#define STANDARD_ORDER

/* If you want to select your own field generator polynomial, you'll have
 * to edit that in rs.c.
 */

#else /* CCSDS */
/* Don't change these, they're CCSDS standard */
#define MM 8
#define KK 223
#define B0 112
#define PRIM 11
#endif

#define	NN ((1 << MM) - 1)

#if MM <= 8
typedef unsigned char dtype;
#else
typedef unsigned int dtype;
#endif

/* Reed-Solomon encoding
 * data[] is the input block, parity symbols are placed in bb[]
 * bb[] may lie past the end of the data, e.g., for (255,223):
 *	encode_rs(&data[0],&data[223]);
 */
int encode_rs(dtype data[], dtype bb[]);

/* Reed-Solomon erasures-and-errors decoding
 * The received block goes into data[], and a list of zero-origin
 * erasure positions, if any, goes in eras_pos[] with a count in no_eras.
 *
 * The decoder corrects the symbols in place, if possible and returns
 * the number of corrected symbols. If the codeword is illegal or
 * uncorrectible, the data array is unchanged and -1 is returned
 */
int eras_dec_rs(dtype data[], int eras_pos[], int no_eras);

#ifdef __cplusplus
}
#endif
