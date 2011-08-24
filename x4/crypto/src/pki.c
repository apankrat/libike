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
 *	$Id: pki.c,v 1.3 2003/04/04 19:56:53 alex Exp $
 */

#include "x4/crypto/pki.h"

#include <openssl/pem.h>

/*  */
x4s_buf x4_load_pem_x509_cert(const char * file)
{
  FILE   * fh = 0;
  X509   * x  = 0;
  uint8  * head;
  int      xlen;
  x4s_buf cert = { 0 };

  if (! (fh = fopen(file, "r")))
    return cert;

  if (! (x = PEM_read_X509(fh,0,0,0)))
    goto done;

  if ((xlen = i2d_X509(x, NULL)) <= 0)
    goto done;

  head = x4_buf_resize(&cert, xlen);
  if (i2d_X509(x, &head) != xlen)
    x4_buf_free(&cert);

done:

  X509_free(x);
  fclose(fh);
  return cert;
}

/*  */
x4s_buf x4_load_pem_rsa_prikey(const char * file, const char * pass)
{
  FILE     * fh = 0;
  EVP_PKEY * k = 0;
  int        klen;
  uint8    * head;
  x4s_buf   pkey = { 0 };
 
  x4_assert(file);
  
  if (! (fh = fopen(file, "r")))
    return pkey;

  if (! (k = PEM_read_PrivateKey(fh,0,0,(void*)pass)) ||
      EVP_PKEY_type(k->type) != EVP_PKEY_RSA)
    goto done;

  if ((klen = i2d_PrivateKey(k,0)) <= 0)
    goto done;

  head = x4_buf_resize(&pkey, klen);
  if (i2d_PrivateKey(k, &head) != klen)
    x4_buf_free(&pkey);

done:
  
  EVP_PKEY_free(k);
  fclose(fh);
  return pkey;
}

/*  */
x4s_buf x4_get_rsa_pubkey(x4s_buf * cert)
{
  X509     * x = 0;
  uint8    * ptr;
  EVP_PKEY * k = 0;
  int        klen;
  x4s_buf   pkey = { 0 };
 
  x4_assert(cert);

  ptr = cert->data;

  if (! (x = d2i_X509(NULL, &ptr, cert->len)))
    return pkey;

  if (! (k = X509_get_pubkey(x)))
    goto done;

  if (k->type != EVP_PKEY_RSA)
    goto done;

  if ((klen = i2d_PublicKey(k,0)) <= 0)
    goto done;

  ptr = x4_buf_resize(&pkey, klen);
  if (i2d_PublicKey(k, &ptr) != klen)
    x4_buf_free(&pkey);

done:
  EVP_PKEY_free(k);
  X509_free(x);
  return pkey;
}

/*  */
x4s_buf x4_get_x509_subject(x4s_buf * cert)
{
  X509   * x = 0;
  uint8  * ptr;
  int      len;
  x4s_buf subj = { 0 };
 
  x4_assert(cert);

  ptr = cert->data;

  if (! (x = d2i_X509(NULL, &ptr, cert->len)))
    return subj;

	if ( (len = i2d_X509_NAME(x->cert_info->subject, 0)) <= 0)
    goto done;

  ptr = x4_buf_resize(&subj, len);
  if (i2d_X509_NAME(x->cert_info->subject, &ptr) != len)
    x4_buf_free(&subj);

done:

  X509_free(x);
  return subj;
}


/*  */
x4s_buf x4_rsa_sign(const x4s_buf * data, const x4s_buf * pkey)
{
  EVP_PKEY * k = 0;
  int        len;
  uint8    * ptr;
  x4s_buf   sig = { 0 };

  /*  */
  x4_assert(data && pkey);

  /*  */
  ptr = pkey->data;
  if (! (k = d2i_PrivateKey(EVP_PKEY_RSA, 0, 
                            &ptr, pkey->len)))
    return sig;

  /*  */
  if ((len = RSA_size(k->pkey.rsa)) < 0)
    goto done;

  /*  */
  x4_buf_resize(&sig, len);
  if (RSA_private_encrypt(data->len, data->data, 
                          sig.data, k->pkey.rsa, 
                          RSA_PKCS1_PADDING) != len)
    x4_buf_free(&sig);

done:
  
  EVP_PKEY_free(k);
  return sig;
}

/*  */
bval x4_rsa_verify(const x4s_buf * data, 
                   const x4s_buf * pkey, 
                   const x4s_buf * sig)
{
  EVP_PKEY * k = 0;
  int       len;
  uint8   * ptr;
  x4s_buf  temp = { 0 };
  bval      r = bfalse;

  /*  */
  x4_assert(data && pkey && sig);

  /*  */
  ptr = pkey->data;
  if (! (k = d2i_PublicKey(EVP_PKEY_RSA, 0, &ptr, pkey->len)))
    return bfalse;

  /*  */
  if ((len = RSA_size(k->pkey.rsa)) < 0 ||
      len < (int)data->len)
    goto done;

  /*  */
  x4_buf_resize(&temp, len);
  if ( (len = RSA_public_decrypt(sig->len, sig->data,
                                 temp.data, k->pkey.rsa, 
                                 RSA_PKCS1_PADDING)) < 0)
    goto done;

  /*  */
  r = x4_buf_compare(data, &temp);

done:

  x4_buf_free(&temp);
  EVP_PKEY_free(k);
  return r;
}

