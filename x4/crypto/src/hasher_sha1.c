/*
 *	This file is a part of libike library.
 *	Copyright (c) 2003-2011 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/libike
 */

/*
 *	The program is distributed under terms of BSD license. 
 *	You can obtain the copy of the license by visiting:
 *
 *	http://www.opensource.org/licenses/bsd-license.php
 */

/*
 *	$Id: hasher_sha1.c,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#include "x4/crypto/hasher.h"
#include "x4/core/memory.h"

#include <openssl/sha.h>

/*  */
static void _sha1_update(x4s_hasher * h, const void * data, size_t dlen)
{
  x4_assert(h && 
             h->update == _sha1_update);

  SHA1_Update((SHA_CTX*)(h+1), data, dlen);
}

/*  */
static void _sha1_complete(x4s_hasher * h, uint8 * hval)
{
  x4_assert(h && 
             h->complete == _sha1_complete);

  if (hval)
    SHA1_Final(hval, (SHA_CTX*)(h+1));

  x4_free(h);
}

/*  */
static void _sha1_process(const void * data, size_t dlen, uint8 * hval)
{
  SHA_CTX  temp;

  SHA1_Init(&temp);
  SHA1_Update(&temp, data, dlen);
  SHA1_Final(hval, &temp);
}

/*  */
static x4s_hasher * _sha1_instance()
{
  x4s_hasher  * h;
  SHA_CTX * ctx;

  h = x4_malloc(sizeof(x4s_hasher) + sizeof(SHA_CTX));
  if (! h)
    return 0;

  ctx = (SHA_CTX*)(h+1);

  h->api = x4v_sha1;
  h->update = _sha1_update;
  h->complete = _sha1_complete;

  SHA1_Init(ctx);

  return h;
}

/*
 *
 */
static x4s_hasher_alg ha_sha1 = { 20, 64, _sha1_process, _sha1_instance };
x4s_hasher_alg * x4v_sha1 = &ha_sha1;
