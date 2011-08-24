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
 *	$Id: phase2.h,v 1.4 2003/04/10 03:45:41 alex Exp $
 */

#ifndef _CPHL_IKE_PHASE_2_H_
#define _CPHL_IKE_PHASE_2_H_

/*
 *  $todo - add comment here
 */

#include "phase1.h"

/*
 *
 */
x4m_struct( x4s_ike_data2 )
{
  bval commit;

  x4s_buf ni;  /* initiator's nonce */
  x4s_buf nr;  /* respondes's nonce */

  x4s_dh_data ke;

  x4s_buf idi;
  x4s_buf idr;
};

/*
 *
 */
x4m_struct( x4s_ike_sa2 )
{
  x4s_ike_config2  c;
  x4s_ike_keys2    k;

  x4s_buf        raw;         /* the body of ISAKMP SA payload */
};

/*
 *
 */
x4m_define_struct( x4s_ike_phase2 )
{
  uint32 msgid;
  
  x4s_ike_exchange   xchg;
  x4s_ike_sa2        sa;
  x4s_ike_data2      data;

  /* internal */
  x4s_ike_phase1 * s1;        /* an owning phase 1 session */
  x4s_ike_phase2 * next;      /* a linked list of phase 2 sessions  */
};

/*
 *
 */
void x4_ike_phase2_free(x4s_ike_phase2 *); /* phase2.c   */

/*  */
x4s_ike_phase2 * x4_ike_i2_create(const x4s_ike_config2 *,
                                  const x4s_ike_phase1 *);
x4s_ike_phase2 * x4_ike_r2_create(const x4s_ike_phase1 *);

/*
 *  -- quick mode, as initiator --
 */
bval x4_ike_q_send1(x4s_ike_exchange *);  /* phase2_i.c */
bval x4_ike_q_recv2(x4s_ike_exchange *);  /* phase2_i.c */
bval x4_ike_q_send3(x4s_ike_exchange *);  /* phase2_i.c */
bval x4_ike_q_recv4(x4s_ike_exchange *);  /* phase2_i.c */

/*
 *  -- quick mode, as responder --
 */
bval x4_ike_q_recv1(x4s_ike_exchange *);  /* phase2_r.c */
bval x4_ike_q_send2(x4s_ike_exchange *);  /* phase2_r.c */
bval x4_ike_q_recv3(x4s_ike_exchange *);  /* phase2_r.c */
bval x4_ike_q_send4(x4s_ike_exchange *);  /* phase2_r.c */

#endif
