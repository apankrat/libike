/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: hasher_ripemd.c,v 1.1 2003/04/27 21:37:37 alex Exp $
 */

#include "x4/crypto/hasher.h"
#include "x4/core/memory.h"

#include <openssl/ripemd.h>

/*  */
static void _ripemd_update(x4s_hasher * h, const void * data, size_t dlen)
{
  x4_assert(h && 
            h->update == _ripemd_update);

  RIPEMD160_Update((RIPEMD160_CTX*)(h+1), data, dlen);
}

/*  */
static void _ripemd_complete(x4s_hasher * h, uint8 * hval)
{
  x4_assert(h && 
            h->complete == _ripemd_complete);

  if (hval)
    RIPEMD160_Final(hval, (RIPEMD160_CTX*)(h+1));

  x4_free(h);
}

/*  */
static void _ripemd_process(const void * data, size_t dlen, uint8 * hval)
{
  RIPEMD160_CTX  temp;

  RIPEMD160_Init(&temp);
  RIPEMD160_Update(&temp, data, dlen);
  RIPEMD160_Final(hval, &temp);
}

/*  */
static x4s_hasher * _ripemd_instance()
{
  x4s_hasher * h;
  RIPEMD160_CTX  * ctx;

  h = x4_malloc(sizeof(x4s_hasher) + sizeof(RIPEMD160_CTX));
  if (! h)
    return 0;

  ctx = (RIPEMD160_CTX*)(h+1);

  h->api = x4v_md5;
  h->update = _ripemd_update;
  h->complete = _ripemd_complete;

  RIPEMD160_Init(ctx);

  return h;
}

/*
 *
 */
static x4s_hasher_alg ha_ripemd = { 20, 64, 
                                    _ripemd_process, 
                                    _ripemd_instance };

x4s_hasher_alg * x4v_ripemd = &ha_ripemd;
