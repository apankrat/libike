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
 *	$Id: exchange.h,v 1.4 2003/04/27 21:37:37 alex Exp $
 */

#ifndef _CPHL_IKE_EXCHANGE_H_
#define _CPHL_IKE_EXCHANGE_H_

#include "packet.h"
#include "x4/ike/sa.h"

/*
 *
 */
#define x4c_ike_state_dead       0
#define x4c_ike_state_completed  0xff

/*
 *  ike_exchange structure hold data common to 3 core IKE exchanges -
 *  Main Mode, Aggressive Mode and Quick Mode.
 *
 *  Every ike_exchange is configured to support mode-specific behaviour
 *  via a set of callbacks, which wrap inbound and outbound ISAKMP packet 
 *  processing, the specifics of the state machine and some other stuff.
 *  
 *  See the comments below for further information.
 */
x4m_struct( x4s_ike_exchange )
{
  uint8  et;                        /* exchange type                      */
  bval   initiator;                 /* if we act as initiator             */
  uint   seqno;                     /* seq # of the last packet processed */

  /*
   *
   */
  x4s_ike_packet_in  in;            /* the inbound packet being processed */
  x4s_ike_packet_out out;           /* the most recent outbound packet    */

  /*
   *
   */
  x4s_cipher_alg * cipher;          /* ISAKMP SA encryption algorithm     */
  x4s_cipher_key * key;             /* ISAKMP SA encryption key           */
  uint8            iv[x4c_iv_max];  /* current encryption IV value        */

  /*
   *  the following set of callbacks is used to pass execution from generic 
   *  exchange code to mode-specific routines, which process inbound packets, 
   *  format outbound messages and advance state of the exchange
   */
  bval  (*on_send[5])(x4s_ike_exchange *); /* outbound packet handler     */

  struct
  {
    bval  (*h)(x4s_ike_exchange *); /* inbound packet handler             */
    uint  required;                 /* bitmask of required payload types  */
    uint  optional;                 /* bitmask of optional payload types  */

  } on_recv[5];

  uint8 (*on_advance)(x4s_ike_exchange *); /*                             */

  /*
   *  the following callbacks are invoked by mode-specific code to transmit 
   *  and retransmit outbound packets, and to notify on ISAKMP SA use. all 
   *  three methods point *outside* of libike.
   */
  bval  (*on_packet) (void *, const x4s_buf *);
  uint  (*on_resend) (void *, uint seqno, uint retry, bval dejavu);
  void  (*on_crypto) (void *, uint bytes);

  /*
   *  on_die() callback is used by mode-specific and generic exchange 
   *  code to request invalidation of an exchange and its removal from 
   *  the datamodel. it normally points inside of datamodel management code.
   */
  void  (*on_die)    (x4s_ike_exchange *);

  /*  */
  void * modedata;                  /* context for mode-specific callbacks */
  void * userdata;                  /* context for external callbacks      */
};

/*
 *
 */
void x4_ike_exchange_free(x4s_ike_exchange *);

/*
 *  exchange_filter() - verifies the hash of an inbound packet against 
 *    xchg->in.hash value and requests retransmission of the xchg->out.pkt 
 *    if hashes are the same. Returns btrue indicating that the packet has 
 *    been consumed and thus the inbound processing is complete.
 */
bval x4_ike_exchange_filter(x4s_ike_exchange *, x4s_buf *);

/*
 *  exchange_decrypt() - decrypts inbound packet taking IV value from
 *    xchg->in.iv, which must be properly set prior to calling the method. 
 */
bval x4_ike_exchange_decrypt(x4s_ike_exchange *, x4s_buf *);

/*
 *  exchange_recv() - takes decrypted and unpacked xchg->in packet, 
 *    verifies its exchange type, payloads' types, verifies the exchange is 
 *    not completed, invokes an inbound processing handler (on_recv), advances 
 *    the state, checks the exchange is not completed, invokes an outbound 
 *    processing handler (on_send) and advances the state 
 */
bval x4_ike_exchange_recv(x4s_ike_exchange *);

/*
 *  exchange_initiate() - sends first packet out and advances the state
 */
bval x4_ike_exchange_send_1st(x4s_ike_exchange *);

/*
 *  exchange_send() - takes plaintext xchg->out packet, encrypts it, sends 
 *    it out (via on_packet), sets up retransmission schedule 
 */
bval x4_ike_exchange_send(x4s_ike_exchange *, uint8 * iv);

/*
 *  exchange_tick() - takes care of timed packet retransmissions
 */
bval x4_ike_exchange_tick(x4s_ike_exchange *, x4t_time tnow);

/*
 *  exchange_die() - $todo - add comment
 *
 */
void x4_ike_exchange_die(x4s_ike_exchange *);

#endif
