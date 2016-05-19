/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#include "ringlwe_locl.h"
#include "FFT/FFT_includes.h"

/* Encapsulation routine. Returns an element in R_q x R_2
 * input:  Alice's public key b in Fourier Domain
 * output: Bob's public key u in Fourier Domain
 *         reconciliation data cr_v
 *         shared secret mu
 */
void KEM1_Encapsulate(RINGELT *u,
		      uint64_t *cr_v,
		      uint64_t *mu,
		      const RINGELT *b,
		      const RINGLWE_PARAM_DATA *p);

void KEM1_Decapsulate(uint64_t *mu,  /*[muwords]*/
		      const RINGELT *u,    /*[m]*/
		      const RINGELT *s_1,  /*[m]*/
		      const uint64_t *cr_v, /*[muwords]*/
		      const RINGLWE_PARAM_DATA *p);

void KEM1_Generate(RINGELT *s, /*[2*m]*/
		   RINGELT *b, /*[m]*/
		   const RINGLWE_PARAM_DATA *p);

/* Sample secret. Only needed externally for benchmarking. */
void sample_secret(RINGELT *s, /*[m]*/
		   const RINGLWE_PARAM_DATA *p);

/* Round and cross-round. Only needed externally for benchmarking. */
void round_and_cross_round(uint64_t *modular_rnd, /*[muwords]*/
			   uint64_t *cross_rnd, /*[muwords]*/
			   const RINGELT *v /*[m]*/,
			   const RINGLWE_PARAM_DATA *p);

/* Reconcile. Only needed externally for benchmarking. */
void ringlwe_rec(uint64_t *r,
		 const RINGELT *w,
		 const uint64_t *b,
		 const RINGLWE_PARAM_DATA *p);
