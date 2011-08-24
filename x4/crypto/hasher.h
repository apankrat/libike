/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: hasher.h,v 1.3 2003/04/27 21:37:37 alex Exp $
 */

#ifndef _CPHL_CRYPTO_HASH_H_
#define _CPHL_CRYPTO_HASH_H_

/*
 *  crypto / hashing algorithms
 *
 *    md5, sha1
 *
 */

#include "x4/misc/buffer.h"

/*
 *  The longest hash currently defined
 */
#define x4c_hash_max  24

/*
 *
 */
x4m_declare_struct( x4s_hasher_alg );

/*
 *  [hasher] is an instance of particular hashing algorithm.
 *  The instance is dynamically allocated and must be disposed by
 *  calling complete() (possibly with zero hval parameter].
 */
x4m_struct( x4s_hasher )
{
  x4s_hasher_alg * api;

  void (*update)(x4s_hasher * h, const void * data, size_t dlen);
  void (*complete)(x4s_hasher * h, uint8 * hval);
};

/*    
 *    [hasher_alg] is an interface to a given hashing algorithm.
 *    [hlen] is a length of the hash it produces
 *    [blen] is a size of the block it processes the data at
 *    [process] computes the hash of the given data block
 *    [instance] creates a hashing context that may be fed multiple
 *               separate datablocks prior to computing the final hash 
 *               value
 */
x4m_define_struct( x4s_hasher_alg )
{
  const size_t hlen;
  const size_t blen;

  void (*process)(const void * data, size_t dlen, uint8 * hval);

  x4s_hasher * (*instance)();
};

/*
 *    The list of currently defined hashing algotihms
 */
extern x4s_hasher_alg * x4v_md5;
extern x4s_hasher_alg * x4v_sha1;
extern x4s_hasher_alg * x4v_sha2_256;
extern x4s_hasher_alg * x4v_sha2_384;
extern x4s_hasher_alg * x4v_sha2_512;
extern x4s_hasher_alg * x4v_ripemd;
extern x4s_hasher_alg * x4v_tiger;

/*
 *    Convenience macros for the hasher/hasher_alg
 */
#define x4_hasher_update(h, p, n) \
  { x4_assert(h); \
    (h)->update((h), (p), (n)); }

#define x4_hasher_complete(h, v) \
  { x4_assert(h); \
    (h)->complete((h), (v)); }

#define x4_hasher_process(ha, p, n, hv) \
  { x4_assert((ha) && (b)); \
    (ha)->process((p), (n), (hv)); }

/*    bbuf equivalents    */
#define x4_hasher_updateb(h, b) \
  { x4_assert((h) && (b)); \
    (h)->update((h), (b)->data, (b)->len); }

#define x4_hasher_completeb(h, b) \
  { x4_assert((h) && (b) && (h)->api->hlen == (b)->len); \
    (h)->complete((h), (b)->data); }

#define x4_hasher_processb(ha, b, hv) \
  { x4_assert((ha) && (b)); \
    (ha)->process((b)->data, (b)->len, (hv)); }


#endif
