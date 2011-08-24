/*
 *	This file is a part of libike library.
 *	Copyright (c) 2003-2011 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/libike
 */

/*
 *	The library is distributed under terms of BSD license. 
 *	You can obtain the copy of the license by visiting:
 *
 *	http://www.opensource.org/licenses/bsd-license.php
 */

/*
 *	$Id: hasher_sha2.c,v 1.2 2003/04/27 22:20:30 alex Exp $
 */

#include "x4/crypto/hasher.h"
#include "x4/core/memory.h"

#include "sha2/sha2.h"

static void _sha2_update(x4s_hasher * h, const void * data, size_t dlen)
{
  x4_assert(h && h->update == _sha2_update);

  sha2_hash(data, dlen, (sha2_ctx*)(h+1));
}

static void _sha2_complete(x4s_hasher * h, uint8 * hval)
{
  x4_assert(h && h->complete == _sha2_complete);

  if (hval)
    sha2_end(hval, (sha2_ctx*)(h+1));

  x4_free(h);
}

static void _sha2_process(x4s_hasher_alg * alg,
                          const void * data, size_t dlen, uint8 * hval)
{
  sha2(hval, alg->hlen, data, dlen);
}

static x4s_hasher * _sha2_instance(x4s_hasher_alg * alg)
{
  x4s_hasher * h;
  sha2_ctx * ctx;

  x4_assert(alg);
  
  h = x4_malloc(sizeof(x4s_hasher) + sizeof(sha2_ctx));
  if (! h)
    return 0;

  ctx = (void*)(h+1);

  h->api = alg;
  h->update = _sha2_update;
  h->complete = _sha2_complete;

  sha2_begin(alg->hlen, ctx);

  return h;
}

/*  */
#define IMPLEMENT(N)                                                 \
  static void _sha2_process_##N(const void * d, size_t n, uint8 * h) \
  { _sha2_process(x4v_sha2_##N, d, n, h); }                          \
                                                                     \
  static x4s_hasher * _sha2_instance_##N()                           \
  { return _sha2_instance(x4v_sha2_##N); }                           \
                                                                     \
  static x4s_hasher_alg ha_sha2_##N = { 20,                          \
                                        N/8,                         \
                                        _sha2_process_##N,           \
                                        _sha2_instance_##N };        \
                                                                     \
  x4s_hasher_alg * x4v_sha2_##N = &ha_sha2_##N;

IMPLEMENT(256)
IMPLEMENT(384)
IMPLEMENT(512)
