/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

/* ringlwe_key.c
   Provides API to Ring-LWE key exchange primitive functions in ringlwe_kex.c */

#include <string.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include "ringlwe_locl.h"
#include "rlwe_rand_openssl_aes.h"
#include "ringlwe_kex.h"


/* Allocate auxiliary variables (context) data structure */

RLWE_CTX *RLWE_CTX_new(const int nid) {
  RLWE_CTX *ctx;
  ctx = (RLWE_CTX *)OPENSSL_malloc(sizeof(RLWE_CTX));
  if (ctx == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_CTX_NEW, ERR_R_MALLOC_FAILURE);
    return (NULL);
  }
  
  ctx->nid = nid;
  ctx->param_data = RINGLWE_PARAM_DATA_set(nid);
  if (ctx->param_data == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_CTX_NEW, RINGLWE_R_PARAM_UNKNOWN);
    goto err;
  }
  
  /* Make 32-byte descriptor for parameter set
     0-3:   "RLWE"
     4-7:   m
     8-11:  q
     12-31: truncated hash of a */
  
  memcpy(ctx->descriptor, (const unsigned char *)"RLWE", 4);
  ctx->descriptor[4] = (ctx->param_data->m>>24) & 0xff;
  ctx->descriptor[5] = (ctx->param_data->m>>16) & 0xff;
  ctx->descriptor[6] = (ctx->param_data->m>>8) & 0xff;
  ctx->descriptor[7] = (ctx->param_data->m) & 0xff;
  ctx->descriptor[8] = (ctx->param_data->q>>24) & 0xff;
  ctx->descriptor[9] = (ctx->param_data->q>>16) & 0xff;
  ctx->descriptor[10]= (ctx->param_data->q>>8) & 0xff;
  ctx->descriptor[11]= (ctx->param_data->q) & 0xff;
  
#ifndef OPENSSL_NO_SHA
  unsigned char sha_outbuf[SHA_DIGEST_LENGTH];
  SHA1((void *)ctx->param_data->a, ctx->param_data->m * sizeof(RINGELT), sha_outbuf);
  memcpy(ctx->descriptor+12, sha_outbuf, _RLWE_DESCRIPTOR_LEN - 12);
#else
  memset(ctx->descriptor+12, 0, 20);
#endif
  
  
  return (ctx);
 err:
  OPENSSL_free(ctx);
  return (NULL);
}

/* Deallocate auxiliary variables (context) data structure */

void RLWE_CTX_free(RLWE_CTX *r) {
  if (r == NULL) return;
  
  OPENSSL_cleanse((void *)r, sizeof(RLWE_CTX));
  OPENSSL_free(r);
}


RINGLWE_PARAM_DATA *RINGLWE_PARAM_DATA_set(const int nid)
{
  /* Select ring-LWE parameter set based on supplied nid */
  RINGLWE_PARAM_DATA *ret = NULL;
  switch (nid)
    {
    case NID_ringLearningWithErrors_1024_40961:
      ret = &_ringlwe_param_1024;
      break;
    case NID_ringLearningWithErrors_821_49261:
      ret = &_ringlwe_param_821;
      break;
    case NID_ringLearningWithErrors_739_47297:
      ret = &_ringlwe_param_739;
      break;
    case NID_ringLearningWithErrors_631_44171:
      ret = &_ringlwe_param_631;
      break;
    case NID_ringLearningWithErrors_541_41117:
      ret = &_ringlwe_param_541;
      break;
    case NID_ringLearningWithErrors_512_25601:
      ret = &_ringlwe_param_512;
      break;
    case NID_ringLearningWithErrors_433_35507:
      ret = &_ringlwe_param_433;
      break;
    case NID_ringLearningWithErrors_337_32353:
      ret = &_ringlwe_param_337;
      break;
    case NID_ringLearningWithErrors_256_15361:
      ret = &_ringlwe_param_256;
      break;
    }
  return ret;
}

int RLWE_get_nid_from_descriptor(const unsigned char descriptor[_RLWE_DESCRIPTOR_LEN]) {
 /* Parse 32-byte descriptor for parameter set
     0-3:   "RLWE"
     4-7:   m
     8-11:  q
     12-31: truncated hash of a */

  if (memcmp(descriptor, (const char *)"RLWE", 4)) {
    return 0;
  }
  
  int i;
  uint32_t m;
  RINGELT  q;
  m = (descriptor[4] << 24) | (descriptor[5] << 16) |
    (descriptor[6] << 8) | descriptor[7];
  q = (descriptor[8] << 24) | (descriptor[9] << 16) |
    (descriptor[10] << 8) | descriptor[11];
  
  int rlwe_nid_list[9] = {
    NID_ringLearningWithErrors_1024_40961,
    NID_ringLearningWithErrors_821_49261,
    NID_ringLearningWithErrors_739_47297,
    NID_ringLearningWithErrors_631_44171,
    NID_ringLearningWithErrors_541_41117,
    NID_ringLearningWithErrors_512_25601,
    NID_ringLearningWithErrors_433_35507,
    NID_ringLearningWithErrors_337_32353,
    NID_ringLearningWithErrors_256_15361
  };
  
  /* Loop through list of valid parameter sets looking for match with 32-byte
     descriptor */
  int nid = 0;
  for (i = 0; i < 9; i++) {
    RINGLWE_PARAM_DATA *p = RINGLWE_PARAM_DATA_set(rlwe_nid_list[i]);
    if (p == NULL)
      continue;
    if ((p->m != m) || (p->q != q))
      continue;
#ifndef OPENSSL_NO_SHA
    unsigned char sha_outbuf[SHA_DIGEST_LENGTH];
    SHA1((void *)p->a, p->m * sizeof(RINGELT), sha_outbuf);
    if (memcmp(descriptor+12, sha_outbuf, _RLWE_DESCRIPTOR_LEN -12))
      continue;
#endif
    /* Found a match */
    nid = rlwe_nid_list[i];
  }
  return nid;
}



/* Allocate public key data structure */

RLWE_PUB *RLWE_PUB_new(const RLWE_CTX *ctx) {
  RLWE_PUB *pub;
  
  if (ctx == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PUB_NEW, ERR_R_PASSED_NULL_PARAMETER);
    return (NULL);
  }
  
  if (ctx->param_data == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PUB_NEW, ERR_R_PASSED_NULL_PARAMETER);
    return (NULL);
  }
  
  pub = (RLWE_PUB *)OPENSSL_malloc(sizeof(RLWE_PUB));
  if (pub == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PUB_NEW, ERR_R_MALLOC_FAILURE);
    return (NULL);
  }
  
  pub->param_data = ctx->param_data;
  memcpy(pub->descriptor, ctx->descriptor, _RLWE_DESCRIPTOR_LEN);
  
  pub->b = (RINGELT *) OPENSSL_malloc(ctx->param_data->m * sizeof(RINGELT));
  if (pub->b == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PUB_NEW, ERR_R_MALLOC_FAILURE);
    RLWE_PUB_free(pub);
    return (NULL);
  }
  
  return (pub);
}

/* Make a copy of public key data structure */

RLWE_PUB *RLWE_PUB_dup(const RLWE_PUB *src) {
  RLWE_PUB *dest;
  
  if (src == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PUB_DUP, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }
	
  dest = (RLWE_PUB *)OPENSSL_malloc(sizeof(RLWE_PUB));
  if (dest == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PUB_DUP, ERR_R_MALLOC_FAILURE);
    return (NULL);
  }
  
  /* copy the parameters */
  dest->param_data = src->param_data;
  memcpy(dest->descriptor, src->descriptor, _RLWE_DESCRIPTOR_LEN);

  /* copy the public key */
  if (src->b && src->param_data) {
    dest->b = (RINGELT *) OPENSSL_malloc(dest->param_data->m * sizeof (RINGELT));
    if (dest->b == NULL) {
      RINGLWEerr(RINGLWE_F_RLWE_PUB_DUP, ERR_R_MALLOC_FAILURE);
      RLWE_PUB_free(dest);
      return (NULL);
    }
    memcpy(dest->b, src->b, src->param_data->m * sizeof(RINGELT));
  }
  
  return dest;
}

/* Deallocate public key data structure */

void RLWE_PUB_free(RLWE_PUB *r) {
  if (r == NULL) return;
  
  if (r->b && r->param_data) {
    OPENSSL_cleanse(r->b, r->param_data->m * sizeof(RINGELT));
  }
  if (r->b) {
    OPENSSL_free(r->b);
  }
  
  OPENSSL_cleanse((void *)r, sizeof(RLWE_PUB));
  OPENSSL_free(r);
}

/* Allocate public key / private key pair data structure */

RLWE_PAIR *RLWE_PAIR_new(RLWE_CTX *ctx) {
  RLWE_PAIR *pair;
  
  if (ctx == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PAIR_NEW, ERR_R_PASSED_NULL_PARAMETER);
    return (NULL);
  }
  
  if (ctx->param_data == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PAIR_NEW, ERR_R_PASSED_NULL_PARAMETER);
    return (NULL);
  }
  
  pair = (RLWE_PAIR *)OPENSSL_malloc(sizeof(RLWE_PAIR));
  if (pair == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PAIR_NEW, ERR_R_MALLOC_FAILURE);
    return (NULL);
  }
  
  pair->param_data = ctx->param_data;
  memcpy(pair->descriptor, ctx->descriptor, _RLWE_DESCRIPTOR_LEN);
  pair->keys_set = 0;
  
  pair->pub = (RLWE_PUB *)RLWE_PUB_new(ctx);
  pair->s = (RINGELT *) OPENSSL_malloc(2 * ctx->param_data->m * sizeof(RINGELT));
  if ((pair->pub == NULL) || (pair->s == NULL)) {
    RINGLWEerr(RINGLWE_F_RLWE_PAIR_NEW, ERR_R_MALLOC_FAILURE);
    RLWE_PAIR_free(pair);
    return (NULL);
  }
  
  return (pair);
}

/* Make a copy of public key / private key pair data structure */

RLWE_PAIR *RLWE_PAIR_dup(const RLWE_PAIR *src) {
  RLWE_PAIR *dest;
  
  if (src == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PAIR_DUP, ERR_R_PASSED_NULL_PARAMETER);
    return (NULL);
  }
  
  dest = (RLWE_PAIR *)OPENSSL_malloc(sizeof(RLWE_PAIR));
  if (dest == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PAIR_DUP, ERR_R_MALLOC_FAILURE);
    return (NULL);
  }
  
  /* copy the parameters */
  dest->param_data = src->param_data;
  memcpy(dest->descriptor, src->descriptor, _RLWE_DESCRIPTOR_LEN);
  
  /* copy the public key */
  dest->pub = (RLWE_PUB *)RLWE_PUB_dup(src->pub);
  if (dest->pub == NULL) {
    RLWE_PAIR_free(dest);
    return (NULL);
  }
  
  /* copy the secret key */
  if (src->s && src->param_data) {
    dest->s = (RINGELT *) OPENSSL_malloc(2 * dest->param_data->m * sizeof (RINGELT));
    if (dest->s == NULL) {
      RINGLWEerr(RINGLWE_F_RLWE_PAIR_DUP, ERR_R_MALLOC_FAILURE);
      RLWE_PAIR_free(dest);
      return (NULL);
    }
    memcpy(dest->s, src->s, 2 * src->param_data->m * sizeof(RINGELT));
  }
  dest->keys_set = src->keys_set;
  
  return dest;
}

/* Deallocate public key / private key pair data structure */

void RLWE_PAIR_free(RLWE_PAIR *r) {
  if (r == NULL) return;
  
  RLWE_PUB_free(r->pub);
  
  if (r->s && r->param_data) {
    OPENSSL_cleanse(r->s, 2 * r->param_data->m * sizeof(RINGELT));
  }
  if (r->s) {
    OPENSSL_free(r->s);
  }
  
  OPENSSL_cleanse((void *)r, sizeof(RLWE_PAIR));
  OPENSSL_free(r);
}

/* Allocate and deallocate reconciliation data structure */

RLWE_REC *RLWE_REC_new(uint32_t muwords) {
  RLWE_REC *rec;

  if (muwords == 0) {
    RINGLWEerr(RINGLWE_F_RLWE_REC_NEW, ERR_R_PASSED_NULL_PARAMETER);
    return (NULL);
  }
  
  rec = (RLWE_REC *)OPENSSL_malloc(sizeof(RLWE_REC));
  if (rec == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_REC_NEW, ERR_R_MALLOC_FAILURE);
    return (NULL);
  }
  
  rec->muwords = muwords;
  rec->c = (uint64_t *) OPENSSL_malloc(muwords * sizeof(uint64_t));
  if (rec->c == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_REC_NEW, ERR_R_MALLOC_FAILURE);
    RLWE_REC_free(rec);
    return (NULL);
  }
  
  return rec;
}

void RLWE_REC_free(RLWE_REC *r) {
  if (r == NULL) return;
  if (r->c) {
    OPENSSL_free(r->c);
  }
  
  OPENSSL_cleanse((void *)r, sizeof(RLWE_REC));
  OPENSSL_free(r);
}

/* Generate key pair */

int RLWE_PAIR_generate_key(RLWE_PAIR *keypair) {
  // wrapper for KEM1_Generate
  RINGLWE_PARAM_DATA *p;
  
  if (keypair == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PAIR_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (keypair->pub == NULL) {
    RINGLWEerr(RINGLWE_F_RLWE_PAIR_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  
  p = keypair->param_data;
  if ((p == NULL) || (keypair->pub->param_data == NULL)) {
    RINGLWEerr(RINGLWE_F_RLWE_PAIR_GENERATE_KEY, RINGLWE_R_PARAM_UNKNOWN);
    return 0;
  }
  
  KEM1_Generate(keypair->s, keypair->pub->b, p);
  keypair->keys_set = 1;
  return 1;
}

/* Convert public key data structure from binary */

RLWE_PUB *o2i_RLWE_PUB(RLWE_PUB **pub, const unsigned char *in, size_t len) {
  size_t i;
  
  if ((pub == NULL) || (in == NULL)) {
    RINGLWEerr(RINGLWE_F_O2I_RLWE_PUB, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (len < _RLWE_DESCRIPTOR_LEN) {
    RINGLWEerr(RINGLWE_F_O2I_RLWE_PUB, RINGLWE_R_INVALID_FORMAT);
    return 0;
  }
  
  /* Read 32-byte descriptor and get parameters */
  const unsigned char *descriptor = in;
  
  int nid;
  nid  = RLWE_get_nid_from_descriptor(descriptor);
	
  if (nid == 0) {
    RINGLWEerr(RINGLWE_F_O2I_RLWE_PUB, RINGLWE_R_PARAM_UNKNOWN);
    return 0;
  }
  
  RLWE_CTX *ctx;
  ctx = RLWE_CTX_new(nid);
  if (ctx == NULL) {
    RINGLWEerr(RINGLWE_F_O2I_RLWE_PUB, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  
  uint32_t m = ctx->param_data->m;
  RINGELT  q = ctx->param_data->q;
  uint32_t n_ringelt_bytes = 2;
  if (q >= 0x00010000)
    n_ringelt_bytes = 4;
  
  if (len != _RLWE_DESCRIPTOR_LEN + m * n_ringelt_bytes) {
    RLWE_CTX_free(ctx);
    RINGLWEerr(RINGLWE_F_O2I_RLWE_PUB, RINGLWE_R_INVALID_FORMAT);
    return 0;
  }
  
 
  RLWE_PUB *pub_key;
  if (*pub != NULL) {
    if (memcmp(ctx->param_data, (*pub)->param_data, sizeof(RINGLWE_PARAM_DATA))) {
      RLWE_CTX_free(ctx);
      RINGLWEerr(RINGLWE_F_O2I_RLWE_PUB, RINGLWE_R_PARAM_INVALID);
      return  0;
    }
    RLWE_CTX_free(ctx);
    pub_key = *pub;
  }
  else {
    pub_key = RLWE_PUB_new(ctx);
    RLWE_CTX_free(ctx);
    if (pub_key == NULL) {
      RINGLWEerr(RINGLWE_F_O2I_RLWE_PUB, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  }
  
  /* Get public key data from binary into structure */
  const unsigned char *ptr = (const unsigned char *)in + _RLWE_DESCRIPTOR_LEN;
  for (i = 0; i < m; i++) {
    pub_key->b[i] = 0;
    if (n_ringelt_bytes == 4) {
      pub_key->b[i] |= ((RINGELT)*ptr++) << 24;
      pub_key->b[i] |= ((RINGELT)*ptr++) << 16; }
    pub_key->b[i] |= ((RINGELT)*ptr++) << 8;
    pub_key->b[i] |= (RINGELT)*ptr++;
  }
  *pub = pub_key;
  return *pub;
}

/* Convert private key data structure from binary */

RLWE_PAIR *o2i_RLWE_SEC(RLWE_PAIR **pair, const unsigned char *in, size_t len) {
  size_t i;
  
  if ((pair == NULL) || (in == NULL)) {
    RINGLWEerr(RINGLWE_F_O2I_RLWE_SEC, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (len < _RLWE_DESCRIPTOR_LEN) {
    RINGLWEerr(RINGLWE_F_O2I_RLWE_SEC, RINGLWE_R_INVALID_FORMAT);
    return 0;
  }
  
  /* Read 32-byte descriptor and get parameters */
  const unsigned char *descriptor = in;
  
  int nid;
  nid  = RLWE_get_nid_from_descriptor(descriptor);
  
  if (nid == 0) {
    RINGLWEerr(RINGLWE_F_O2I_RLWE_SEC, RINGLWE_R_PARAM_UNKNOWN);
    return 0;
  }
  
  RLWE_CTX *ctx;
  ctx = RLWE_CTX_new(nid);
  if (ctx == NULL) {
    RINGLWEerr(RINGLWE_F_O2I_RLWE_SEC, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  
  uint32_t m = ctx->param_data->m;
  RINGELT  q = ctx->param_data->q;
  uint32_t n_ringelt_bytes = 2;
  if (q >= 0x00010000)
    n_ringelt_bytes = 4;
  
  if (len != _RLWE_DESCRIPTOR_LEN + m * n_ringelt_bytes) {
    RLWE_CTX_free(ctx);
    RINGLWEerr(RINGLWE_F_O2I_RLWE_SEC, RINGLWE_R_INVALID_FORMAT);
    return 0;
  }
  
  RLWE_PAIR *key_pair;
  if (*pair != NULL) {
    if (memcmp(ctx->param_data, (*pair)->param_data, sizeof(RINGLWE_PARAM_DATA))) {
      RLWE_CTX_free(ctx);
      RINGLWEerr(RINGLWE_F_O2I_RLWE_SEC, RINGLWE_R_PARAM_INVALID);
      return  0;
    }
    RLWE_CTX_free(ctx);
    key_pair = *pair;
  }
  else {
    key_pair = RLWE_PAIR_new(ctx);
    RLWE_CTX_free(ctx);
    if (key_pair == NULL) {
      RINGLWEerr(RINGLWE_F_O2I_RLWE_SEC, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  }
  
  /* Get public key data from binary into structure */
  const unsigned char *ptr = (const unsigned char *)in + _RLWE_DESCRIPTOR_LEN;
  for (i = 0; i < m; i++) {
    key_pair->s[m+i] = 0;
    if (n_ringelt_bytes == 4) {
      key_pair->s[m+i] |= ((RINGELT)*ptr++) << 24;
      key_pair->s[m+i] |= ((RINGELT)*ptr++) << 16; }
    key_pair->s[m+i] |= ((RINGELT)*ptr++) << 8;
    key_pair->s[m+i] |= (RINGELT)*ptr++;
  }
  *pair = key_pair;
  return *pair;
}

/* Convert public key data structure into binary */

size_t i2o_RLWE_PUB(RLWE_PUB *pub, unsigned char **out) {
  size_t buf_len = 0;
  int new_buffer = 0, i;
  
  if (pub == NULL) {
    RINGLWEerr(RINGLWE_F_I2O_RLWE_PUB, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (pub->param_data == NULL) {
    RINGLWEerr(RINGLWE_F_I2O_RLWE_PUB, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  
  
  uint32_t m = pub->param_data->m;
  RINGELT  q = pub->param_data->q;
  uint32_t n_ringelt_bytes = 2;
  if (q >= 0x00010000)
    n_ringelt_bytes = 4;
  
  buf_len = _RLWE_DESCRIPTOR_LEN + m * n_ringelt_bytes; 
  
  if (out == NULL || buf_len == 0)
    /* out == NULL => just return the length of the octet string */
    return buf_len;
  
  if (*out == NULL) {
    if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
      RINGLWEerr(RINGLWE_F_I2O_RLWE_PUB, ERR_R_MALLOC_FAILURE);
      return 0;
    }
    new_buffer = 1;
  }
  unsigned char *ptr = *out;
  /* Copy 32-byte descriptor */
  memcpy (ptr, pub->descriptor, _RLWE_DESCRIPTOR_LEN);
  ptr += _RLWE_DESCRIPTOR_LEN;

  /* Copy public key data */
  for (i = 0; i < m; i++) {
    if (n_ringelt_bytes == 4) {
      *ptr++ = (unsigned char) ((pub->b[i] >> 24) & 0xff);
      *ptr++ = (unsigned char) ((pub->b[i] >> 16) & 0xff);
    }
    *ptr++ = (unsigned char) ((pub->b[i] >> 8) & 0xff);
    *ptr++ = (unsigned char) ((pub->b[i]) & 0xff);
  }
  if (!new_buffer)
    *out = ptr;
  return buf_len;
}

/* Convert private key data structure into binary */

size_t i2o_RLWE_SEC(RLWE_PAIR *pair, unsigned char **out) {
  size_t buf_len = 0;
  int new_buffer = 0, i;
  
  if (pair == NULL) {
    RINGLWEerr(RINGLWE_F_I2O_RLWE_SEC, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (pair->param_data == NULL) {
    RINGLWEerr(RINGLWE_F_I2O_RLWE_SEC, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
    
  uint32_t m = pair->param_data->m;
  RINGELT  q = pair->param_data->q;
  uint32_t n_ringelt_bytes = 2;
  if (q >= 0x00010000)
    n_ringelt_bytes = 4;
  
  buf_len = _RLWE_DESCRIPTOR_LEN + m * n_ringelt_bytes; 
  
  if (out == NULL || buf_len == 0)
    /* out == NULL => just return the length of the octet string */
    return buf_len;
  
  if (*out == NULL) {
    if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
      RINGLWEerr(RINGLWE_F_I2O_RLWE_SEC, ERR_R_MALLOC_FAILURE);
      return 0;
    }
    new_buffer = 1;
  }
  unsigned char *ptr = *out;
  /* Copy 32-byte descriptor */
  memcpy (ptr, pair->descriptor, _RLWE_DESCRIPTOR_LEN);

  /* Copy private key data */
  ptr += _RLWE_DESCRIPTOR_LEN;
  for (i = 0; i < m; i++) {
    if (n_ringelt_bytes == 4) {
      *ptr++ = (unsigned char) ((pair->s[m+i] >> 24) & 0xff);
      *ptr++ = (unsigned char) ((pair->s[m+i] >> 16) & 0xff);
    }
    *ptr++ = (unsigned char) ((pair->s[m+i] >> 8) & 0xff);
    *ptr++ = (unsigned char) ((pair->s[m+i]) & 0xff);
  }
  if (!new_buffer)
    *out = ptr;
  return buf_len;
}


/* Convert reconciliation data structure from binary */

RLWE_REC *o2i_RLWE_REC(RLWE_REC **rec, const unsigned char *in, size_t len) {
  size_t buf_len;
  size_t i;
  
  if (len < 4) {
    RINGLWEerr(RINGLWE_F_O2I_RLWE_REC, RINGLWE_R_INVALID_FORMAT);
    return 0;
  }
  uint32_t muwords;
  muwords = (in[0]<<24) | (in[1]<<16) | (in[2]<<8) | (in[3]);
  buf_len = 4 + muwords * 8;
  
  if (buf_len != len) {
    RINGLWEerr(RINGLWE_F_I2O_RLWE_REC, RINGLWE_R_INVALID_FORMAT);
  }
  
  if (*rec == NULL) {
    if ((*rec = RLWE_REC_new(muwords)) == NULL) {
      RINGLWEerr(RINGLWE_F_O2I_RLWE_REC, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  }
  
  for (i = 0; i < muwords; i++) {
    int k = 0;
    (*rec)->c[i] = 0;
    for (k = 0; k < 8; k++) {
      (*rec)->c[i] |= ((uint64_t)in[4 + 8*i +k]) << (8*k);
    }
  }
  
  return *rec;
}

/* Convert reconciliation data structure into binary */

size_t i2o_RLWE_REC(RLWE_REC *rec, unsigned char **out) {
  size_t buf_len = 0;
  int new_buffer = 0, i;
  
  if (rec == NULL) {
    RINGLWEerr(RINGLWE_F_I2O_RLWE_REC, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  
  uint32_t muwords = rec->muwords;
  
  buf_len = 4 + muwords * 8;
  
  if (out == NULL || buf_len == 0)
    /* out == NULL => just return the length of the octet string */
    return buf_len;
  
  if (*out == NULL) {
    if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
      RINGLWEerr(RINGLWE_F_I2O_RLWE_REC, ERR_R_MALLOC_FAILURE);
      return 0;
    }
    new_buffer = 1;
  }
  (*out)[0] = (muwords >> 24) & 0xff;
  (*out)[1] = (muwords >> 16) & 0xff;
  (*out)[2] = (muwords >> 8) & 0xff;
  (*out)[3] = (muwords) & 0xff;
  
  for (i = 0; i < muwords; i++) {
    int k = 0;
    for (k = 0; k < 8; k++) {
      (*out)[4 + 8*i + k] = (rec->c[i] >> (8*k)) & 0xff;
    }
  }
  
  if (!new_buffer)
    *out += buf_len;
  return buf_len;
}

/* Get public key from a key pair */
RLWE_PUB *RLWE_PAIR_get_publickey(RLWE_PAIR *pair) {
  if (pair == NULL)
    return NULL;
  if (pair->keys_set == 0)
    return NULL;
  return pair->pub;
}

/* Does private key exist? */
int RLWE_PAIR_has_privatekey(RLWE_PAIR *pair) {
  return pair->keys_set;
}

/* Return value of m from context */
uint32_t RLWE_CTX_get_m(RLWE_CTX *ctx) {
  if (ctx == NULL) return 0;
  if (ctx->param_data == NULL) return 0;
  return ctx->param_data->m;
}

/* Return value of q from context */
RINGELT RLWE_CTX_get_q(RLWE_CTX *ctx) {
  if (ctx == NULL) return 0;
  if (ctx->param_data == NULL) return 0;
  return ctx->param_data->q;
}


/* Compute shared secret values */
size_t RINGLWE_compute_key_alice(void *out,
			      size_t outlen,
			      const RLWE_PUB *bob_pub,
			      const RLWE_REC *reconciliation,
			      const RLWE_PAIR *alice_keypair,
			      void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen)) {

  size_t ret = 0;
  
  if ((bob_pub == NULL) || (alice_keypair == NULL) || (reconciliation==NULL)) {
    RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_ALICE, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  
  /* Check sender and recipient are using same parameters */
  if (bob_pub->param_data != alice_keypair->param_data) {
    RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_ALICE, RINGLWE_R_PARAM_INVALID);
    return 0;
  }
  
  RINGLWE_PARAM_DATA *p = alice_keypair->param_data;
  uint64_t *ka = (uint64_t *)OPENSSL_malloc(p->muwords * sizeof(uint64_t));
  if (ka == NULL) {
      RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_ALICE, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  
  memset(ka, 0, p->muwords * sizeof(uint64_t));
  RINGELT *alice_s1 = &(alice_keypair->s[p->m]);
  
  /* Compute shared key from Bob's public key, Alice's private key and
     reconciliation data */
  KEM1_Decapsulate(ka, bob_pub->b, alice_s1, reconciliation->c, p);

  size_t nchars = (p->m + 7) / 8;
  unsigned char *ka_buf = (unsigned char *)OPENSSL_malloc(nchars * sizeof(unsigned char));
  if (ka_buf == NULL) {
    RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_ALICE, ERR_R_MALLOC_FAILURE);
    return 0;
    }
  size_t i;
  for (i = 0; i < p->muwords * sizeof(uint64_t); i+= sizeof(uint64_t)) {
    size_t k;
    for (k = i; (k < i + sizeof(uint64_t)) && (k < nchars); k++) {
      ka_buf[k] = (unsigned char)(ka[i/sizeof(uint64_t)] >> (8*(k&7)));
    }
  }

  /* Apply KDF if specified */
  if (KDF != NULL) {
    if (KDF(ka_buf, nchars * sizeof(unsigned char), out, &outlen) == NULL) {
      RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_ALICE, RINGLWE_R_KDF_FAILED);
    }
    else {
      ret = outlen;
    }
  } else {
    /* no KDF, just copy as much as we can */
    if (outlen > nchars * sizeof(unsigned char))
      outlen = nchars * sizeof(unsigned char);
    memcpy(out, ka_buf, outlen);
    ret = outlen;
  }
  
  /* Cleanse memory */
  if (ka) {
      OPENSSL_cleanse(ka, p->muwords * sizeof(uint64_t));
      OPENSSL_free(ka);
    }
  if (ka_buf) {
    OPENSSL_cleanse(ka_buf, nchars);
    OPENSSL_free(ka_buf);
  }
  
  return (ret);

}

/* Compute shared secret values */
size_t RINGLWE_compute_key_bob(void *out,
			    size_t outlen,
			    RLWE_REC **reconciliation,
			    const RLWE_PUB *alice_pub,
			    const RLWE_PUB *bob_pub,
                            void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen)) {
  
  size_t ret = 0;
  
  if ((alice_pub == NULL) || (bob_pub == NULL)) {
    RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_BOB, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  
  /* Check sender and recipient are using same parameters */
  if (alice_pub->param_data != bob_pub->param_data) {
    RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_BOB, RINGLWE_R_PARAM_INVALID);
    return 0;
  }

  RINGLWE_PARAM_DATA *p = bob_pub->param_data;

  if (reconciliation == NULL) {
    RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_BOB, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (*reconciliation == NULL) {
    *reconciliation = RLWE_REC_new(p->muwords);
  }
  if (*reconciliation == NULL) {
  RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_BOB, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  
  uint64_t *kb = (uint64_t *)OPENSSL_malloc(p->muwords * sizeof(uint64_t));
  if (kb == NULL) {
      RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_BOB, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  memset(kb, 0, p->muwords * sizeof(uint64_t));
  
  /* Bob generates shared key, public key and reconciliation data */
  KEM1_Encapsulate(bob_pub->b, (*reconciliation)->c, kb, alice_pub->b, p);

  size_t nchars = (p->m + 7) / 8;
  unsigned char *kb_buf = (unsigned char *)OPENSSL_malloc(nchars * sizeof(unsigned char));
  if (kb_buf == NULL) {
    RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_ALICE, ERR_R_MALLOC_FAILURE);
    return 0;
    }
  size_t i;
  for (i = 0; i < p->muwords * sizeof(uint64_t); i+= sizeof(uint64_t)) {
    size_t k;
    for (k = i; (k < i + sizeof(uint64_t)) && (k < nchars); k++) {
      kb_buf[k] = (unsigned char)(kb[i/sizeof(uint64_t)] >> (8*(k&7)));
    }
  }

  /* Apply KDF if specified */
  if (KDF != NULL) {
    if (KDF(kb_buf, nchars * sizeof(unsigned char), out, &outlen) == NULL) {
      RINGLWEerr(RINGLWE_F_RINGLWE_COMPUTE_KEY_BOB, RINGLWE_R_KDF_FAILED);
    }
    else {
      ret = outlen;
    }
  } else {
    /* no KDF, just copy as much as we can */
    if (outlen > nchars * sizeof(unsigned char))
      outlen = nchars * sizeof(unsigned char);
    memcpy(out, kb_buf, outlen);
    ret = outlen;
  }

   /* Cleanse memory */
  if (kb) {
    OPENSSL_cleanse(kb, p->muwords * sizeof(uint64_t));
    OPENSSL_free(kb);
  }
  if (kb_buf) {
    OPENSSL_cleanse(kb_buf, nchars * sizeof(unsigned char));
    OPENSSL_free(kb_buf);
  }

  return (ret);
  
}
