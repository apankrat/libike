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
 *	$Id: cipher_rc5.c,v 1.1 2003/04/27 21:37:37 alex Exp $
 */

#include "x4/crypto/cipher.h"

#include <openssl/rc5.h>

/*  */
static size_t _rc5_init_kl(size_t kbits)
{
  // accept only 8 bit aligned keys between 40 and 448 bits in length
  return (! (kbits & 0x07) && 40 <= kbits && kbits <= 2040) ? 
         kbits : 
         kbits ? 0 : 128;
}

/*  */
static x4s_cipher_key * _rc5_init_ks(size_t kbits, const void * key)
{
  x4s_cipher_key * ck;

  x4_assert(key);
  
  if (!kbits || !_rc5_init_kl(kbits))
    return 0;

  ck = x4_malloc(sizeof(*ck)-1+sizeof(RC5_32_KEY));
  if (! ck)
    return 0;

  ck->klen = kbits/8;
  RC5_32_set_key((RC5_32_KEY*)ck->opaque, kbits/8, key, 16);

  return ck;
}

/*  */
static void _rc5_encrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  x4_assert(key && iv && in && out && n);  
  
  RC5_32_cbc_encrypt(in, out, 8*n, (RC5_32_KEY*)key->opaque, iv, RC5_ENCRYPT);
}

/*  */
static void _rc5_decrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  x4_assert(key && iv && in && out && n);  
  
  RC5_32_cbc_encrypt(in, out, 8*n, (RC5_32_KEY*)key->opaque, iv, RC5_DECRYPT);
}

/*
 *
 */
static x4s_cipher_alg ca_rc5 = { 8, 
                                _rc5_init_kl,
                                _rc5_init_ks, 
                                _rc5_encrypt, 
                                _rc5_decrypt };

x4s_cipher_alg * x4v_rc5 = &ca_rc5;
