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
 *	$Id: hmac.c,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#include "x4/crypto/hmac.h"

/*
    H(K XOR opad, H(K XOR ipad, text))
 */

x4m_struct( x4s_hmac_context )
{
  x4s_hasher * h_opad;
  x4s_hasher * h_ipad;
  size_t hlen;          /* target hash length (for HASH-XX-96) */
  size_t blen;
};

/*  */
static void _hmac_complete(x4s_hasher * h, uint8 * hval);

/*  */
static void _hmac_update(x4s_hasher * h, const void * data, size_t dlen)
{
  x4s_hmac_context * hm;
  
  x4_assert(h &&
            h->update == _hmac_update &&
            h->complete == _hmac_complete);

  hm = (x4s_hmac_context*)(h+1);
  hm->h_ipad->update(hm->h_ipad, data, dlen);
}

/*  */
static void _hmac_complete(x4s_hasher * h, uint8 * hval)
{
  x4s_hmac_context * hm;
  uint8 local[x4c_hash_max];
  
  x4_assert(h &&
            h->update == _hmac_update &&
            h->complete == _hmac_complete);

  hm = (x4s_hmac_context*)(h+1);

  if (hval)
  {
    uint8 temp[x4c_hash_max];

    hm->h_ipad->complete(hm->h_ipad, temp);
    hm->h_opad->update(hm->h_opad, temp, hm->h_opad->api->hlen);
  }
  else
    hm->h_ipad->complete(hm->h_ipad, 0);
  
  hm->h_opad->complete(hm->h_opad, local);
  x4_memmove(hval, local, hm->hlen);

  x4_free(h);
}

/*  */
x4s_hasher * x4_hmac(x4s_hasher_alg * hapi, const void * key, 
                     size_t klen, size_t hlen)
{
  x4s_hasher       * h, * h_opad, * h_ipad;
  x4s_hmac_context * hm;
  uint8    k[256] = { 0 };
  size_t   blen, i;

  /*  */
  x4_assert(hapi && key && klen);
  x4_assert(hlen <= hapi->hlen);

  /*  */
  h = x4_malloc(sizeof(x4s_hasher) + sizeof(x4s_hmac_context));
  if (! h)
    return 0;

  hm = (x4s_hmac_context*)(h+1);

  /* initialize hmac */
  x4_assert(hapi->blen <= sizeof(k));

  hm->hlen = hlen ? hlen : hapi->hlen;
  hm->blen = hapi->blen;

  h_opad = hm->h_opad = hapi->instance();
  h_ipad = hm->h_ipad = hapi->instance();

  x4_assert(hm->h_opad && hm->h_ipad);

  /* prepare key */
  blen = hapi->blen;
  if (klen > blen)
  {
    hapi->process(key, klen, k);
    klen = hapi->hlen;
  }
  else
  {
    x4_memmove(k, key, klen);
  }

  /* initialize opad */
  for (i=0; i<blen; i++)
    k[i] ^= 0x5C;

  h_opad->update(h_opad, k, blen);

  /* initialize ipad */
  for (i=0; i<blen; i++)
    k[i] ^= 0x5C ^ 0x36;

  h_ipad->update(h_ipad, k, blen);

  /* initialize */
  h->api    = (x4s_hasher_alg *)(&hm->hlen); /* hack hack hack */
  h->update = _hmac_update;
  h->complete = _hmac_complete;
  
  return h;
}
