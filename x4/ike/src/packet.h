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
 *	$Id: packet.h,v 1.3 2003/04/10 03:45:41 alex Exp $
 */

#ifndef _CPHL_IKE_PACKET_H_
#define _CPHL_IKE_PACKET_H_

#include "x4/core/time.h"
#include "x4/crypto/hasher.h"

#include "message.h"

/*
 *  packet_in structure stores information pertaining to an inbound
 *  ISAKMP packet processing.
 *
 *  msg  - holds parsed ISAKMP message in internal format (message.h)
 *  hash - is MD5 hash of the original (possibly encrypted) ISAKMP packet.
 *  iv   - IV after the decryption of the packet. The actual length of the 
 *         IV is (s1->sa.cipher->blen).
 */
x4m_struct( x4s_ike_packet_in )
{
  x4s_ike_message msg;
  uint8   hash[x4c_hash_max];
  uint8   iv  [x4c_iv_max];
};

/*
 *  packet_out contains data associated with an outbound ISAKMP packet
 *
 *  pkt  - is an actual (possibly encrypted) ISAKMP message.
 *  hash - is MD5 hash of an associated inbound packet (if any).
 *  
 *  remaining fields define packet retransmission context as per comments
 *  below.
 *
 */
x4m_struct( x4s_ike_packet_out )
{
  x4s_buf  pkt;                /* outgoing packet */
  uint8    hash[x4c_hash_max]; /* MD5 hash of an associated inbound message */
                          
  x4t_time timestamp;          /* time of the last send */
  uint     timeout;            /* the retransmission timeout */
  uint     retry;              /* number of copies sent */
};

/*
 *
 */
void x4_ike_packet_in_free(x4s_ike_packet_in *);
void x4_ike_packet_out_free(x4s_ike_packet_out *);

/*
 *
 */
void x4_ike_packet_out_reset(x4s_ike_packet_out *, uint8 * hash);


#endif

