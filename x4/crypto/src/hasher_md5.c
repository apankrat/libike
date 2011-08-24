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
 *	$Id: hasher_md5.c,v 1.2 2003/04/27 21:37:37 alex Exp $
 */

#include "x4/crypto/hasher.h"
#include "x4/core/memory.h"

#include <openssl/md5.h>

/*  */
static void _md5_update(x4s_hasher * h, const void * data, size_t dlen)
{
  x4_assert(h && h->update == _md5_update);
  MD5_Update((MD5_CTX*)(h+1), data, dlen);
}

/*  */
static void _md5_complete(x4s_hasher * h, uint8 * hval)
{
  x4_assert(h && h->complete == _md5_complete);

  if (hval)
    MD5_Final(hval, (MD5_CTX*)(h+1));

  x4_free(h);
}

/*  */
static void _md5_process(const void * data, size_t dlen, uint8 * hval)
{
  MD5_CTX  temp;

  MD5_Init(&temp);
  MD5_Update(&temp, data, dlen);
  MD5_Final(hval, &temp);
}

/*  */
static x4s_hasher * _md5_instance()
{
  x4s_hasher * h;
  MD5_CTX  * ctx;

  h = x4_malloc(sizeof(x4s_hasher) + sizeof(MD5_CTX));
  if (! h)
    return 0;

  ctx = (MD5_CTX*)(h+1);

  h->api = x4v_md5;
  h->update = _md5_update;
  h->complete = _md5_complete;

  MD5_Init(ctx);

  return h;
}

/*
 *
 */
static x4s_hasher_alg ha_md5 = { 16, 64, _md5_process, _md5_instance };
x4s_hasher_alg * x4v_md5 = &ha_md5;
