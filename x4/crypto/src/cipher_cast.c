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
 *	$Id: cipher_cast.c,v 1.1 2003/04/27 21:37:37 alex Exp $
 */

#include "x4/crypto/cipher.h"

#include <openssl/cast.h>

/*  */
static size_t _cast_init_kl(size_t kbits)
{
  // accept only 8 bit aligned keys between 40 and 448 bits in length
  return (! (kbits & 0x07) && 40 <= kbits && kbits <= 128) ? 
         kbits : 
         kbits ? 0 : 128;
}

/*  */
static x4s_cipher_key * _cast_init_ks(size_t kbits, const void * key)
{
  x4s_cipher_key * ck;

  x4_assert(key);
  
  if (!kbits || !_cast_init_kl(kbits))
    return 0;

  ck = x4_malloc(sizeof(*ck)-1+sizeof(CAST_KEY));
  if (! ck)
    return 0;

  ck->klen = kbits/8;
  CAST_set_key((CAST_KEY*)ck->opaque, kbits/8, key);

  return ck;
}

/*  */
static void _cast_encrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  x4_assert(key && iv && in && out && n);  
  
  CAST_cbc_encrypt(in, out, 8*n, (CAST_KEY*)key->opaque, iv, 1);
}

/*  */
static void _cast_decrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  x4_assert(key && iv && in && out && n);  
  
  CAST_cbc_encrypt(in, out, 8*n, (CAST_KEY*)key->opaque, iv, 0);
}

/*
 *
 */
static x4s_cipher_alg ca_cast = { 8, 
                                  _cast_init_kl,
                                  _cast_init_ks, 
                                  _cast_encrypt, 
                                  _cast_decrypt };

x4s_cipher_alg * x4v_cast = &ca_cast;
