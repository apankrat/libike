/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: pki.h,v 1.3 2003/04/04 19:56:53 alex Exp $
 */

#ifndef _CPHL_CRYPTO_PKI_H_
#define _CPHL_CRYPTO_PKI_H_

/*
 *    The assymetric cryptography functions such as RSA digital signing 
 *    and verification.
 *
 *    $todo - expand the comment
 */

#include "x4/misc/buffer.h"

x4s_buf x4_load_pem_x509_cert(const char * file);
x4s_buf x4_load_pem_rsa_prikey(const char * file, const char * pass);

x4s_buf x4_get_rsa_pubkey(x4s_buf * cert);
x4s_buf x4_get_x509_subject(x4s_buf * cert);

x4s_buf x4_rsa_sign(const x4s_buf * data, const x4s_buf * pkey);
bval    x4_rsa_verify(const x4s_buf * data, const x4s_buf * pkey, 
                      const x4s_buf * sig);


#endif
