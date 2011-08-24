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
 *	$Id: natt.h,v 1.3 2003/04/10 03:45:41 alex Exp $
 */

#ifndef _CPHL_IKE_NATT_H_
#define _CPHL_IKE_NATT_H_

#include "x4/ike/const.h"
#include "phase1.h"

/*
 *    $comment
 */
void  x4_natt_compute_hashes(x4s_ike_phase1 * s1);

void  x4_natt_append_vid(x4s_ike_phase1 * s1);
void  x4_natt_append_natd(x4s_ike_phase1 * s1);
void  x4_natt_process_vid(x4s_ike_phase1 * s1);
bval  x4_natt_process_natd(x4s_ike_phase1 * s1);

/*
 *    These methods convert specified 'encaps' and 'pt' values to the
 *    NAT-T draft-specific constants.
 */
uint8  x4_natt_pt(uint8, x4e_ike_payload_type);
bval   x4_natt_float(uint8);
uint16 x4_natt_encaps(uint8, x4e_ike_a2_encaps);

#endif

