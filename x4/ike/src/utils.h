/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: utils.h,v 1.5 2003/04/27 21:37:37 alex Exp $
 */

#ifndef _CPHL_IKE_UTILITY_FUNCTIONS_H_
#define _CPHL_IKE_UTILITY_FUNCTIONS_H_

/*
 *  $todo - add comment here
 */
 
#include "phase1.h"
#include "phase2.h"

/*
 *
 */
x4s_hasher_alg * x4_ike_select_hasher(uint16 v);
x4s_cipher_alg * x4_ike_select_cipher(uint16 v);
x4s_buf          x4_ike_select_prime (uint16 v);

/*
 *
 */
void x4_ike_compute1_skeyids(x4s_ike_phase1 * s1);
void x4_ike_compute1_enckey(x4s_ike_phase1 * s1);

void x4_ike_compute1_hashi(x4s_ike_phase1 * s1, uint8 * hv);
void x4_ike_compute1_hashr(x4s_ike_phase1 * s1, uint8 * hv);

void x4_ike_compute1_iv(x4s_ike_phase1 * s1);
void x4_ike_compute2_iv(uint32 msgid, x4s_ike_phase1 * s1, uint8 * iv);

void x4_ike_compute2_hash1(uint32 msgid, x4s_ike_phase1 * s1, 
                          x4s_buf * pkt, uint8 * hv);

void x4_ike_compute2_hash2(x4s_ike_phase2 * s2, x4s_buf * pkt, uint8 * hv);
void x4_ike_compute2_hash3(x4s_ike_phase2 * s2, uint8 * hv);

void x4_ike_compute2_keymat(x4s_ike_phase2 * s2);

/*
 *
 */
x4s_buf x4_ike_link_to_id(const x4s_net_link *, bval local);
x4s_buf x4_ike_selector_to_id(const x4s_net_selector *, bval local);

bval x4_ike_id_to_selector(const x4s_buf *, x4s_net_selector *, bval local);

#endif

