/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef HEADER_RINGLWE_LOCL_H
#define HEADER_RINGLWE_LOCL_H

#include <openssl/ringlwe.h>
#include "ringlwe_consts.h"

#define CONSTANT_TIME 1

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef RINGELT
#define RINGELT uint_fast16_t
#endif

#define _RLWE_DESCRIPTOR_LEN 32


struct rlwe_pub_st {
  unsigned char descriptor[_RLWE_DESCRIPTOR_LEN];
  RINGLWE_PARAM_DATA *param_data;
  RINGELT *b;   /* public key */
};

struct rlwe_pair_st {
  unsigned char descriptor[_RLWE_DESCRIPTOR_LEN];
  RINGLWE_PARAM_DATA *param_data;
  RLWE_PUB *pub;  /* public key structure */
  RINGELT *s;  /* ephemeral s_0 followed by secret s_1 */
  int keys_set;
};

struct rlwe_rec_st {
  uint32_t muwords;
  uint64_t *c;  /* reconciliation vector */
};

struct rlwe_ctx_st {
  unsigned char descriptor[_RLWE_DESCRIPTOR_LEN];
  int nid;
  RINGLWE_PARAM_DATA *param_data;
};

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_RINGLWE_LOCL_H */
