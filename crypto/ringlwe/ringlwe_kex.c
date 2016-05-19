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
#include "ringlwe_kex.h"
#include <string.h>
#include <assert.h>

#include "rlwe_rand_openssl_aes.h"

/* Ring-LWE Key Exchange primitive functions
   Do not call directly, use the interface functions in ringlwe_key.c instead */

/*
  Sample the secret key. Each coefficient uniform in [-B,B].
  Set the m'th coefficient to be 0 if m is prime.
*/
void sample_secret(RINGELT *s, /*[m]*/
		   const RINGLWE_PARAM_DATA *p) {
  RANDOM_VARS;
  uint16_t i = 0;
  uint64_t r = RANDOM64;
  uint64_t l, shifts = 0;
  
  int loop_limit = p->m;
  if ((p->m)&1) { // prime case
    loop_limit = p->m-1;
    s[p->m-1] = 0;
  }
  
  while (i < loop_limit) {
    l = r & p->BMASK;
    if (l < p->BB) {
      /*Take this sample*/
      s[i] = p->small_coeff_table[l];
      i++;
    }
    /*Shift r along and continue*/
    shifts++;
    if (shifts * p->LOG2B >= 64) {
      /*Need a new random value*/
      r = RANDOM64;
      shifts = 0;
    }
    else r = (r >> p->LOG2B);
  }		
}


/* Round and cross-round */
void round_and_cross_round(uint64_t *modular_rnd, /*[muwords]*/
			   uint64_t *cross_rnd, /*[muwords]*/
			   const RINGELT *v /*[m]*/,
			   const RINGLWE_PARAM_DATA *p) {
  RANDOM_VARS;
  uint16_t i = 0;
  uint64_t r = RANDOM64;
  RINGELT word = 0, pos = 0, rbit = 0, val;
  
  memset((void *) modular_rnd, 0, p->muwords*sizeof(uint64_t));
  memset((void *) cross_rnd, 0, p->muwords*sizeof(uint64_t));
    
  int loop_limit = p->m;
  if ((p->m)&1) // prime case
    loop_limit = p->m-1;
    
  for (i = 0; i < loop_limit; ++i) {
    
    val = v[i];
    /*Randomize rounding procedure - probabilistic nudge*/
    if (p->qmod4 == 1) {
      if (val == 0) {
	if (r & 1) val = (p->q-1);
	rbit++;
	if (rbit >= 64) {
	  r = RANDOM64; rbit = 0;
	}
	else r = (r >> 1);
      }
      else if (val == p->q_1_4-1) {
	if (r & 1) val = p->q_1_4;
	rbit++;
	if (rbit >= 64) {
	  r = RANDOM64; rbit = 0;
	}
	else r = (r >> 1);
      }
    }
    else {
      if (val == 0) {
	if (r & 1) val = (p->q-1);
	rbit++;
	if (rbit >= 64) {
	  r = RANDOM64; rbit = 0;
	}
	else r = (r >> 1);
      }
      else if (val == p->q_3_4-1) {
	if (r & 1) val = p->q_3_4;
	rbit++;
	if (rbit >= 64) {
	  r = RANDOM64; rbit = 0;
	}
	else r = (r >> 1);
      }
    }
    
    /*Modular rounding process*/
    if (val > p->q_1_4 && val < p->q_3_4) modular_rnd[word] |= (1UL << pos);
    
    /*Cross Rounding process*/
    if ((val > p->q_1_4 && val <= p->q_2_4) || val >= p->q_3_4) cross_rnd[word] |= (1UL << pos);
    
    pos++;
    if (pos == 64) {
      word++; pos = 0;
    }
    
  }
  
  
}


/* Encapsulation routine. Returns an element in R_q x R_2
 * input:  Alice's public key b in Fourier Domain
 * output: Bob's public key u in Fourier Domain
 *         reconciliation data cr_v
 *         shared secret mu
 */
void KEM1_Encapsulate(RINGELT *u, /*[m]*/
		      uint64_t *cr_v, /*[muwords]*/
		      uint64_t *mu, /*[muwords]*/
		      const RINGELT *b, /*[m]*/
		      const RINGLWE_PARAM_DATA *p) {
  const RINGELT m=p->m, q=p->q;
  RINGELT e[3*p->m];
  RINGELT v[p->m];
  
  /*Sample Bob's ephemeral keys*/	
  sample_secret(e, p);
  sample_secret(e+m, p);
  sample_secret(e+2*m, p);	

  /*Fourer Transform e0 and e1*/
  assert(p->fft_forward);
  assert(p->fft_backward);
  
  p->fft_forward((FFTSHORT *)e);
  p->fft_forward((FFTSHORT *)(e+m));

  POINTWISE_MUL_ADD(u, p->a, e, e+m, m, q);
  /* Combine with a to produce e_0*a+e_1 in the Fourier domain. Bob's public key. */
  
  POINTWISE_MUL(v, b, e, m, q); /* Create v = e0*b */
  p->fft_backward((FFTSHORT *)v); /* Undo the Fourier Transform */
  if ((m)&1) /* prime case */
    MAPTOCYCLOTOMIC(v, m, q);
  
  POINTWISE_ADD(v, v, e+2*m, m, q); /* Create v = e0*b+e2 */
  
  round_and_cross_round(mu, cr_v, v, p);

  memset(e, 0, 3*p->m * sizeof(RINGELT));
  memset(v, 0, p->m * sizeof(RINGELT));
}


/* Decapsulation routine.
 * input:  Bob's public key u in Fourier Domain
 *         Alice's private key s_1 in Fourier Domain
 *         reconciliation data cr_v
 * output: shared secret mu
 */
void KEM1_Decapsulate(uint64_t *mu,  /*[muwords]*/
			const RINGELT *u,    /*[m]*/
			const RINGELT *s_1,  /*[m]*/
			const uint64_t *cr_v, /*[muwords]*/
			const RINGLWE_PARAM_DATA *p) {
  RINGELT w[p->m];

  POINTWISE_MUL(w, s_1, u, p->m, p->q); /* Create w = s1*u */
  assert(p->fft_backward);
 
  p->fft_backward((FFTSHORT *)w); /* Undo the Fourier Transform */
  if ((p->m)&1)  /* prime case */
    MAPTOCYCLOTOMIC(w, p->m, p->q);

  ringlwe_rec(mu, w, cr_v, p);
  memset(w, 0, p->m * sizeof(RINGELT));
}


void KEM1_Generate(RINGELT *s, /*[2*m]*/
		   RINGELT *b, /*[m]*/
		   const RINGLWE_PARAM_DATA *p)
{
  const RINGELT m=p->m, q=p->q;

  /* Sample Alice's secret keys */
  sample_secret(s, p);
  sample_secret(s+m, p);

  /* Fourier Transform secret keys */
  p->fft_forward((FFTSHORT *)s);
  p->fft_forward((FFTSHORT *)s+m);
    
  POINTWISE_MUL_ADD(b, p->a, s+m, s, m, q);
  /* Combine with a to produce s_1*a+s_0 in the Fourier domain. Alice's public key. */

  return;
}


/* Reconcile */ 
void ringlwe_rec(uint64_t *r, /*[muwords]*/
		 const RINGELT *w,  /*[m]*/
		 const uint64_t *b, /*[muwords]*/
		 const RINGLWE_PARAM_DATA *p) {
  
  RINGELT i = 0;
  RINGELT word = 0, pos = 0;
  
  memset((void *) r, 0, p->muwords*sizeof(uint64_t));
  
  int loop_limit = p->m;
  if ((p->m)&1) /* prime case */
    loop_limit = p->m-1;
  
  for (i = 0; i < loop_limit; ++i) {
    if ((b[word] >> pos) & 1UL) {
      if (w[i] > p->r1_l && w[i] < p->r1_u) r[word] |= (1UL << pos);
    }
    else {
      if (w[i] > p->r0_l && w[i] < p->r0_u) r[word] |= (1UL << pos);
    }
    pos++;
    if (pos == 64) {
      word++; pos = 0;
    }
  }
}

