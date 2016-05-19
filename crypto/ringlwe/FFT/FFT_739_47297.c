/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

/* Code to compute a Number Theoretic Transform for multiplication in the ring 
F_q[x] / <x^n+1>.
	n = 739, q = 47297	*/

#include "FFT_includes.h"
#include "FFT_constants.h"

/*
We use Bluestein's trick and integer convoution by CRT.
*/
void FFT_forward_739_47297(FFTSHORT x[739]) {
        const FFTSHORT n = 739;
        const FFTSHORT q = 47297;
        const FFTSHORT N = 2048;

	FFTSHORT x0[2048], x1[2048];
	FFTSHORT i;
	FFTLONG x_crt[2048];
	const FFTSHORT q0 = 8816641, Ninvq0 = 8812336;	
	const FFTSHORT q1 = 17633281, Ninvq1 = 17624671;
	const FFTLONG h0 = 17633282UL, h1 = 17633281UL;
	const FFTLONG q0q1 = 155466308229121UL;
	
	/*Setup Bluestein's method*/
	for (i = 0; i < n; ++i) {
		MUL_MOD(x0[i], x[i], Bluestein_mul_739_47297[i], q);
	}
	memset((void *) (x0+n), 0, (N-n)*sizeof(FFTSHORT)); /*Pad with 0's*/
	memcpy((void *) x1, (void *) x0, N*sizeof(FFTSHORT)); /*Copy x0 into x1*/
	
	/*Cyclic convolution*/
	FFT_forward_2048_8816641(x0);
	FFT_forward_2048_17633281(x1);
	
	for (i = 0; i < N; ++i) {
		MUL_MOD(x0[i], x0[i], Bluestein_roots_fft_739_8816641[i], q0);
		MUL_MOD(x1[i], x1[i], Bluestein_roots_fft_739_17633281[i], q1);		
	}
	FFT_backward_2048_8816641(x0);
	FFT_backward_2048_17633281(x1);
	
	/*Apply the CRT*/
	for (i = 0; i < N; ++i) {
		MUL_MOD(x0[i], x0[i], Ninvq0, q0); /*Scaling for the convolution*/
		MUL_MOD(x1[i], x1[i], Ninvq1, q1); /*Scaling for the convolution*/
		x_crt[i] = h1*x0[i] % q0q1;
		x_crt[i] = q0q1 - x_crt[i];
		x_crt[i] += h0*x1[i];
		x_crt[i] = x_crt[i] % q0q1; //Will now be the integer convolution
		x_crt[i] = x_crt[i] % q; 
	}
		
	/*Complete Bluestein's trick*/
	x[0] = (FFTSHORT) x_crt[(N>>1)-1];
	for (i = 0; i < n-1; ++i) {
		MUL_MOD(x[i+1], x_crt[(N>>1)+i], Bluestein_mul_739_47297[i], q);
	}		
	
}

void FFT_backward_739_47297(FFTSHORT x[739]) {
        const FFTSHORT n = 739;
        const FFTSHORT q = 47297;
        const FFTSHORT N = 2048;

	FFTSHORT x0[2048], x1[2048];
	FFTSHORT i;
	FFTLONG x_crt[2048];
	const FFTSHORT q0 = 8816641, Ninvq0 = 8812336;	
	const FFTSHORT q1 = 17633281, Ninvq1 = 17624671;
	const FFTLONG h0 = 17633282UL, h1 = 17633281UL;
	const FFTLONG q0q1 = 155466308229121UL;
	
	/*Setup Bluestein's method*/
	for (i = 0; i < n; ++i) {
		MUL_MOD(x0[i], x[i], Bluestein_mul_inv_739_47297[i], q);
	}
	memset((void *) (x0+n), 0, (N-n)*sizeof(FFTSHORT)); /*Pad with 0's*/
	memcpy((void *) x1, (void *) x0, N*sizeof(FFTSHORT)); /*Copy x0 into x1*/
		
	/*Cyclic convolution*/
	FFT_forward_2048_8816641(x0);
	FFT_forward_2048_17633281(x1);
	for (i = 0; i < N; ++i) {
		MUL_MOD(x0[i], x0[i], Bluestein_roots_inv_fft_739_8816641[i], q0);
		MUL_MOD(x1[i], x1[i], Bluestein_roots_inv_fft_739_17633281[i], q1);		
	}
	FFT_backward_2048_8816641(x0);
	FFT_backward_2048_17633281(x1);
	
	/*Apply the CRT*/
	for (i = 0; i < N; ++i) {
		MUL_MOD(x0[i], x0[i], Ninvq0, q0); /*Scaling for the convolution*/
		MUL_MOD(x1[i], x1[i], Ninvq1, q1); /*Scaling for the convolution*/
		x_crt[i] = h1*x0[i] % q0q1;
		x_crt[i] = q0q1 - x_crt[i];
		x_crt[i] += h0*x1[i];
		x_crt[i] = x_crt[i] % q0q1; //Will now be the integer convolution
		x_crt[i] = x_crt[i] % q; 
	}
			
	/*Complete Bluestein's trick*/
	x[0] = (FFTSHORT) x_crt[(N>>1)-1];	
	for (i = 0; i < n-1; ++i) {
		MUL_MOD(x[i+1], x_crt[(N>>1)+i], Bluestein_mul_inv_739_47297[i], q);		
	}
				
}


void _FFT_forward_739_47297(FFTSHORT *x) {
  FFT_forward_739_47297(x);
}

void _FFT_backward_739_47297(FFTSHORT *x) {
  int i;
  FFT_backward_739_47297(x);
  for (i=0; i<739; ++i)
    MUL_MOD(x[i], x[i], 47233, 47297);
}
