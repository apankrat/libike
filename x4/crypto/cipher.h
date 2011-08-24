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
 *	$Id: cipher.h,v 1.3 2003/04/27 21:37:37 alex Exp $
 */

#ifndef _CPHL_CRYPTO_CIPHER_H_
#define _CPHL_CRYPTO_CIPHER_H_

/*
 *  The interface to the symmetrical encryption algorithms. 
 *
 *    des, 3des, aes-128, aes-192, aes-256
 *
 *    All ciphers currently operate only in CBC mode.
 *
 */

#include "x4/misc/buffer.h"

/*
 *  The largest block size of all currently defined ciphers
 */
#define x4c_iv_max  16

/*
 *  x4s_cipher_key holds one or more key schedules, which are
 *  calculated from the original key by 'init_ks'. 'len' field
 *  is set to the size of the *key* (not the ks) in bytes and 
 *  'data' marks the start of transparent ks data. the structure
 *  must be disposed with free() once it's no longer needed.
 *
 */
x4m_struct( x4s_cipher_key )
{
  size_t klen;
  uint8  opaque[1];
};

/*
 *  x4s_cipher_alg defines an interface to a symmetric block cipher.
 *
 *  'blen' is a length of the single block, 
 *
 *  'init_kl' return 'kbits' if it specifies acceptable key length,
 *            or 0 otherwise. if 'kbits' is 0, it returns default
 *            key length.
 *  'init_ks' expands given key into the schedule that can later be
 *            used with 'encrypt' and 'decrypt' methods. the method
 *            returns 0 is key is weak or if its length is invalid.
 *  'encrypt' encrypts 'n' blocks of data (n*blen bytes) from 'in'
 *            into the 'out' with 'iv' (usually in CBC mode)
 *  'decrypt' decrypts the data
 */
x4m_struct( x4s_cipher_alg )
{
  const size_t blen;

  size_t           (*init_kl)(size_t kbits);

  x4s_cipher_key * (*init_ks)(size_t kbits, const void * key);

  void (*encrypt)(x4s_cipher_key * key, uint8 * iv, 
                  const void * in, void * out, size_t n);

  void (*decrypt)(x4s_cipher_key * key, uint8 * iv, 
                  const void * in, void * out, size_t n);
};

/*
 *    The list of currently defined symmetrical ciphers
 */
extern x4s_cipher_alg * x4v_des;
extern x4s_cipher_alg * x4v_3des;
extern x4s_cipher_alg * x4v_aes;
extern x4s_cipher_alg * x4v_blowfish;
extern x4s_cipher_alg * x4v_cast;
extern x4s_cipher_alg * x4v_rc5;
extern x4s_cipher_alg * x4v_idea;

#endif
