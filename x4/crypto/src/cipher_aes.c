/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: cipher_aes.c,v 1.2 2003/04/27 21:37:37 alex Exp $
 */

#include "x4/crypto/cipher.h"

#include "rijndael/rijndael-api-fst.h"

/*  */
static size_t _aes_init_kl(size_t kbits)
{
  return (kbits == 128 || kbits == 192 || kbits == 256) ? 
         kbits : 
         kbits ? 0 : 128;            
}

/*  */
static x4s_cipher_key * _aes_init_ks(size_t kbits, const void * key)
{
  x4s_cipher_key * ck;
  keyInstance    * k;
  uint8 enc;

  x4_assert(key);
  
  if (!kbits || !_aes_init_kl(kbits))
    return 0;

  ck = x4_malloc(sizeof(*ck)-1+2*sizeof(keyInstance));
  if (! ck)
    return 0;

  ck->klen = kbits/8;
  k = (void*)ck->opaque;

  /* instantiate decryption and encryption keys */
  for (enc=0; enc<2; enc++, k++)
  {
    uint8 temp[MAXKB];

    k->direction = enc ? DIR_ENCRYPT : DIR_DECRYPT;
    k->keyLen = kbits;

    x4_memmove(temp, key, kbits/8);

    if (enc)
      k->Nr = rijndaelKeySetupEnc(k->rk, temp, k->keyLen);
    else
      k->Nr = rijndaelKeySetupDec(k->rk, temp, k->keyLen);

    rijndaelKeySetupEnc(k->ek, temp, k->keyLen);
  }  

  return ck;
}

/*  */
static void _aes_encrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  cipherInstance c = { MODE_CBC, 0 };
  keyInstance  * k;

  x4_assert(key && iv && in && out && n);  
  
  k = (void*)key->opaque;
  x4_memmove(c.IV, iv, 16);

  blockEncrypt(&c, k+1, (uint8*)in, 128*n, out);
  x4_memmove(iv, 16*(n-1)+(uint8*)in, 16);
}

/*  */
static void _aes_decrypt(x4s_cipher_key * key, uint8 * iv,
                         const void * in, void * out, size_t n)
{
  cipherInstance c = { MODE_CBC, 0 };
  keyInstance  * k;

  x4_assert(key && iv && in && out && n);  
  
  k = (void*)key->opaque;

  x4_memmove(c.IV, iv, 16);

  x4_memmove(iv, 16*(n-1)+(uint8*)in, 16);
  blockDecrypt(&c, k, (uint8*)in, 128*n, out);
}

/*
 *
 */
static x4s_cipher_alg ca_aes = { 16, 
                                 _aes_init_kl,
                                 _aes_init_ks, 
                                 _aes_encrypt, 
                                 _aes_decrypt };

x4s_cipher_alg * x4v_aes = &ca_aes;
