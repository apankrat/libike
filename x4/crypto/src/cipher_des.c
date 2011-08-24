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
 *	$Id: cipher_des.c,v 1.2 2003/04/27 21:37:37 alex Exp $
 */

#include "x4/crypto/cipher.h"

#include <openssl/des.h>

/*  */
static size_t _des_init_kl(size_t kbits)
{
  return (!kbits || kbits == 64) ? 64 : 0;
}

/*  */
static x4s_cipher_key * _des_init_ks(size_t kbits, const void * key)
{
  x4s_cipher_key * ck;

  x4_assert(key);
  
  if (kbits != 64)
    return 0;

  ck = x4_malloc(sizeof(*ck)-1+sizeof(des_key_schedule));
  if (! ck)
    return 0;

  ck->klen = 8;
  des_set_key((des_cblock*)key, *(des_key_schedule*)ck->opaque);

  return ck;
}

/*  */
static void _des_encrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  des_key_schedule * ks;

  x4_assert(key && iv && in && out && n);  
  
  ks = (void*)key->opaque;
  des_ncbc_encrypt((uint8*)in, out, (int)8*n, *ks, (des_cblock*)iv, 1);
}

/*  */
static void _des_decrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  des_key_schedule * ks;

  x4_assert(key && iv && in && out && n);  
  
  ks = (void*)key->opaque;
  des_ncbc_encrypt((uint8*)in, out, (int)8*n, *ks, (des_cblock*)iv, 0);
}

/*
 *
 */
static x4s_cipher_alg ca_des = { 8,
                                 _des_init_kl,
                                 _des_init_ks, 
                                 _des_encrypt, 
                                 _des_decrypt };

x4s_cipher_alg * x4v_des = &ca_des;
