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
 *	$Id: cipher_3des.c,v 1.2 2003/04/27 21:37:37 alex Exp $
 */

#include "x4/crypto/cipher.h"

#include <openssl/des.h>

/*  */
static size_t _3des_init_kl(size_t kbits)
{
  return (!kbits || kbits == 192) ? 192 : 0;
}

/*  */
static x4s_cipher_key * _3des_init_ks(size_t kbits, const void * key)
{
  x4s_cipher_key   * ck;
  des_key_schedule * ks;

  x4_assert(key);
  
  if (kbits != 192)
    return 0;

  ck = x4_malloc(sizeof(*ck)-1+3*sizeof(des_key_schedule));
  if (! ck)
    return 0;

  ks = (void*)ck->opaque;
  
  ck->klen = 24;
  des_set_key((des_cblock *)key + 0, ks[0]);
  des_set_key((des_cblock *)key + 1, ks[1]);
  des_set_key((des_cblock *)key + 2, ks[2]);

  return ck;
}

/*  */
static void _3des_encrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  des_key_schedule * ks;

  x4_assert(key && iv && in && out && n);  
  
  ks = (void*)key->opaque;
  des_ede3_cbc_encrypt((uint8*)in, out, (int)8*n, 
                       ks[0], ks[1], ks[2], (des_cblock*)iv, 1);
}

/*  */
static void _3des_decrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  des_key_schedule * ks;

  x4_assert(key && iv && in && out && n);  
  
  ks = (void*)key->opaque;
  des_ede3_cbc_encrypt((uint8*)in, out, (int)8*n, 
                       ks[0], ks[1], ks[2], (des_cblock*)iv, 0);
}

/*
 *
 */
static x4s_cipher_alg ca_3des = { 8, 
                                 _3des_init_kl, 
                                 _3des_init_ks, 
                                 _3des_encrypt, 
                                 _3des_decrypt };

x4s_cipher_alg * x4v_3des = &ca_3des;
