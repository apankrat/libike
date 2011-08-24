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
 *	$Id: cipher_idea.c,v 1.1 2003/04/27 21:37:37 alex Exp $
 */

#include "x4/crypto/cipher.h"

#include <openssl/idea.h>

/*  */
static size_t _idea_init_kl(size_t kbits)
{
  return (!kbits || kbits == 128) ? 128 : 0;
}

/*  */
static x4s_cipher_key * _idea_init_ks(size_t kbits, const void * key)
{
  x4s_cipher_key * ck;
  IDEA_KEY_SCHEDULE * ks;

  x4_assert(key);
  
  if (!kbits || !_idea_init_kl(kbits))
    return 0;

  ck = x4_malloc(sizeof(*ck)-1+2*sizeof(IDEA_KEY_SCHEDULE));
  if (! ck)
    return 0;

  ck->klen = kbits/8;
  ks = (void*)ck->opaque;

  idea_set_encrypt_key(key, ks);
  idea_set_decrypt_key(ks, ks+1);

  return ck;
}

/*  */
static void _idea_encrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  IDEA_KEY_SCHEDULE * ks;

  x4_assert(key && iv && in && out && n);  
  
  ks = (void*)key->opaque;
  idea_cbc_encrypt(in, out, 8*n, ks, iv, IDEA_ENCRYPT);
}

/*  */
static void _idea_decrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  IDEA_KEY_SCHEDULE * ks;

  x4_assert(key && iv && in && out && n);  
  
  ks = (void*)key->opaque;
  idea_cbc_encrypt(in, out, 8*n, ks+1, iv, IDEA_DECRYPT);
}

/*
 *
 */
static x4s_cipher_alg ca_idea = { 8, 
                                  _idea_init_kl,
                                  _idea_init_ks, 
                                  _idea_encrypt, 
                                  _idea_decrypt };

x4s_cipher_alg * x4v_idea = &ca_idea;
