/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef FFT_INCLUDES_H
#define FFT_INCLUDES_H

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define FFTLONG uint_fast64_t
#define PRIuFFTLONG PRIuFAST64
#define FFTSHORT uint_fast32_t
#define PRIuFFTSHORT PRIuFAST32

#define ADD(x, a, b) \
do {\
        x = (a) + (b);\
} while (0)

#define MUL_MOD(x, a, b, q) \
do {\
        uint64_t x64 = (uint64_t) (a)*(b);\
        x64 = x64 % (q);\
        x = (FFTSHORT) x64;\
} while(0)

#define ADD_MOD(x, a, b, q) \
do {\
        x = (a) + (b);\
        x -= (x >= (q)) ? (q) : 0;\
} while (0)

#define SUB_MOD(x, a, b, q) \
do {\
        x = (a) + ((q) - (b));\
        x -= (x >= (q)) ? (q) : 0;\
} while (0)

/*Needed for indexing in the FFT*/
#define SUB_MODn(x, a, b, n)			\
do {\
        x = (a) + (n-(b));\
        x -= (x >= n) ? n : 0;\
} while (0)

/*v = e0*b, multiply and add in the ring. All done in the FFT / CRT domain, so point-wise multiplication and addition*/
#define POINTWISE_MUL(v, b, e0, m, q)		\
  do {   uint16_t _i;\
	for (_i = 0; _i < m; ++_i) {\
		MUL_MOD((v)[_i], (e0)[_i], (b)[_i], (q));\
	}\
} while(0)

/*v = e0+b, multiply and add in the ring. All done in the FFT / CRT domain, so point-wise multiplication and addition*/
#define POINTWISE_ADD(v, b, e0, m, q)		\
    do {  uint16_t _i;\
	for (_i = 0; _i < m; ++_i) {\
		ADD_MOD((v)[_i], (e0)[_i], (b)[_i], (q));\
	}\
} while(0)


/*v = e0*b+e1, multiply and add in the ring. All done in the FFT / CRT domain, so point-wise multiplication and addition*/
#define POINTWISE_MUL_ADD(v, b, e0, e1, m, q)	\
    do {  uint16_t _i;\
	for (_i = 0; _i < m; ++_i) {\
		MUL_MOD((v)[_i], (e0)[_i], (b)[_i], (q));\
		ADD_MOD((v)[_i], (v)[_i], (e1)[_i], (q));\
	}\
} while(0)



/*Map a length m object in the ring F_q[x]/<x^m-1> to a length m-1 object in the ring F_q[x]/<1+x+...+x^{m-1}>*/
#define MAPTOCYCLOTOMIC(v, m, q)		\
    do {  uint16_t _i;\
        for (_i = 0; _i < m-1; ++_i) {				\
			SUB_MOD((v)[_i], (v)[_i], (v)[m-1], q);\
		}\
		v[m-1] = 0;\
	} while(0)

#endif

void _FFT_forward_1024_40961(FFTSHORT x[1024]);
void _FFT_backward_1024_40961(FFTSHORT x[1024]);

void _FFT_forward_821_49261(FFTSHORT x[821]);
void _FFT_backward_821_49261(FFTSHORT x[821]);

void _FFT_forward_739_47297(FFTSHORT x[739]);
void _FFT_backward_739_47297(FFTSHORT x[739]);

void _FFT_forward_631_44171(FFTSHORT x[631]);
void _FFT_backward_631_44171(FFTSHORT x[631]);

void _FFT_forward_541_41117(FFTSHORT x[541]);
void _FFT_backward_541_41117(FFTSHORT x[541]);

void _FFT_forward_512_25601(FFTSHORT x[512]);
void _FFT_backward_512_25601(FFTSHORT x[512]);

void _FFT_forward_433_35507(FFTSHORT x[433]);
void _FFT_backward_433_35507(FFTSHORT x[433]);

void _FFT_forward_337_32353(FFTSHORT x[337]);	
void _FFT_backward_337_32353(FFTSHORT x[337]);

void _FFT_forward_256_15361(FFTSHORT x[256]);
void _FFT_backward_256_15361(FFTSHORT x[256]);


void FFT_forward_2048_8816641(FFTSHORT x[2048]);
void FFT_backward_2048_8816641(FFTSHORT x[2048]);

void FFT_forward_2048_17633281(FFTSHORT x[2048]);
void FFT_backward_2048_17633281(FFTSHORT x[2048]);

void FFT_forward_1024_8816641(FFTSHORT x[1024]);
void FFT_backward_1024_8816641(FFTSHORT x[1024]);

void FFT_forward_1024_17633281(FFTSHORT x[1024]);
void FFT_backward_1024_17633281(FFTSHORT x[1024]);


