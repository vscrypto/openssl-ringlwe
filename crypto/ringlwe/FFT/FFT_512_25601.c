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
	n = 512, q = 25601	*/

#include "FFT_includes.h"
#include "FFT_constants.h"

/*
We use Gentleman-Sande, decimation-in-frequency FFT, for the forward FFT.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will invert 
the fourier transform using decimation-in-time.
*/
void FFT_forward_512_25601(FFTSHORT x[512]) {
        const FFTSHORT n = 512;
        const FFTSHORT q = 25601;
	FFTSHORT index, step;
	FFTSHORT i,j,m;
	FFTSHORT t0,t1;

	step = 1;
	for (m = n>>1; m >= 1; m=m>>1) {
		index = 0;
		for (j = 0 ; j < m; ++j) {
			for (i = j; i < n; i += (m<<1)) {
				ADD_MOD(t0, x[i], x[i+m], q);
				ADD(t1, x[i], q - x[i+m]);
				MUL_MOD(x[i+m], t1, W_512_25601[index], q);				
				x[i] = t0;				
			}
			SUB_MODn(index, index, step, n);
		}
		step = step << 1;
	}	 
}

/*
We use Cooley-Tukey, decimation-in-time FFT, for the inverse FFT.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will the forward
fourier transform is using decimation-in-frequency.
*/
void FFT_backward_512_25601(FFTSHORT x[512]) {
        const FFTSHORT n = 512;
        const FFTSHORT q = 25601;
	FFTSHORT index, step;
	FFTSHORT i,j,m;
	FFTSHORT t0,t1;

	step = n>>1;
	for (m = 1; m < n; m=m<<1) {
		index = 0;
		for (j = 0 ; j < m; ++j) {
			for (i = j; i < n; i += (m<<1)) {							
				t0 = x[i];
				t0 -= (t0 >= q) ? q : 0;
				MUL_MOD(t1, x[i+m], W_rev_512_25601[index], q);				
				ADD(x[i], t0, t1);
				ADD(x[i+m], t0, q - t1);
				
			}
			SUB_MODn(index, index, step, n);
		}
		step = step >> 1;
	}	
	for (i = 0; i < n; ++i) {
		x[i] -= (x[i] >= q) ? q : 0;
	}
}


/*
We use Gentleman-Sande, decimation-in-frequency FFT, for the forward FFT.
We premultiply x by the 2n'th roots of unity to affect a Discrete Weighted Fourier Transform, 
so when we apply pointwise multiplication we obtain the negacyclic convolution, i.e. multiplication 
modulo x^n+1.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will invert 
the fourier transform using decimation-in-time.
*/
void FFT_twisted_forward_512_25601(FFTSHORT x[512]) {
        const FFTSHORT n = 512;
        const FFTSHORT q = 25601;
	FFTSHORT index, step;
	FFTSHORT i,j,m;
	FFTSHORT t0,t1;

	//Pre multiplication for twisted FFT
	j = 0;
	for (i = 0; i < n>>1; ++i) {
		MUL_MOD(x[j], x[j], W_512_25601[i], q);
		j++;	
		MUL_MOD(x[j], x[j], W_sqrt_512_25601[i], q);	
		j++;
	}

	step = 1;
	for (m = n>>1; m >= 1; m=m>>1) {
		index = 0;
		for (j = 0 ; j < m; ++j) {
			for (i = j; i < n; i += (m<<1)) {				
				ADD_MOD(t0, x[i], x[i+m], q);
				ADD(t1, x[i], q - x[i+m]);
				MUL_MOD(x[i+m], t1, W_512_25601[index], q);				
				x[i] = t0;						
			}
			SUB_MODn(index, index, step, n);
		}
		step = step << 1;
	}	 
}

/*
We use Cooley-Tukey, decimation-in-time FFT, for the inverse FFT.
We postmultiply x by the inverse of the 2n'th roots of unity * n^-1 to affect a Discrete Weighted Fourier Transform, 
so when we apply pointwise multiplication we obtain the negacyclic convolution, i.e. multiplication 
modulo x^n+1.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will the forward
fourier transform is using decimation-in-frequency.
*/
void FFT_twisted_backward_512_25601(FFTSHORT x[512]) {
        const FFTSHORT n = 512;
        const FFTSHORT q = 25601;
	FFTSHORT index, step;
	FFTSHORT i,j,m;
	FFTSHORT t0,t1;

	step = n>>1;
	for (m = 1; m < n; m=m<<1) {
		index = 0;
		for (j = 0 ; j < m; ++j) {
			for (i = j; i < n; i += (m<<1)) {							
				t0 = x[i];
				t0 -= (t0 >= q) ? q : 0;
				MUL_MOD(t1, x[i+m], W_rev_512_25601[index], q);				
				ADD(x[i], t0, t1);
				ADD(x[i+m], t0, q - t1);
			}
			SUB_MODn(index, index, step, n);
		}
		step = step >> 1;
	}

	//Post multiplication for twisted FFT
	j = 0;
	for (i = 0; i < n>>1; ++i) {
		MUL_MOD(x[j], x[j], W_rev_512_25601[i], q);
		j++;	
		MUL_MOD(x[j], x[j], W_sqrt_rev_512_25601[i], q);
		j++;
	} 
}


void _FFT_forward_512_25601(FFTSHORT *x) {
  FFT_twisted_forward_512_25601(x);
}

void _FFT_backward_512_25601(FFTSHORT *x) {
  int i;
  FFT_twisted_backward_512_25601(x);
  for (i=0; i<512; ++i)
    MUL_MOD(x[i], x[i], 25551, 25601);
}
