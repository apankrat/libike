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
 *	$Id: message.h,v 1.5 2003/04/10 03:45:41 alex Exp $
 */

#ifndef _CPHL_IKE_MESSAGE_H_
#define _CPHL_IKE_MESSAGE_H_

/*
 *    isakmp.h defines isakmp_header and isakmp_payload that implement
 *    RFC ISAKMP message header and ISAKMP payload respectively.
 *    
 *    Neither inbound not outbound processing code use these structures
 *    directly. They operate with their internal equivalents instead.
 *    
 *    Inbound processing code builds (ike_message) structure from the
 *    original ISAKMP packet by calling message_unpack(). (ike_message)'s
 *    fields refer and point at original packet's content and thus
 *    become invalid once the original ISAKMP packet is discarded.
 *    
 *    Outbound processing code composes new ISAKMP ike_message by first 
 *    calling message_create(). It then adds ISAKMP payloads to the 
 *    ike_message by calling message_append(). 
 *
 */

#include "x4/misc/buffer.h"
#include "x4/crypto/cipher.h"
#include "x4/ike/const.h"

#include "isakmp.h"

/*
 *    the maximum number of payloads libike allows in any given inbound 
 *    ISAKMP message. messages with a larger number of payloads are 
 *    rejected as invalid.
 */
#define x4c_ike_payload_max 32


/*
 *    parsed ISAKMP payload
 */
x4m_struct( x4s_ike_payload )
{
  uint8   type;
  x4s_buf body;
};


/*
 *    parsed ISAKMP message. 
 *    by_order array holds payloads in the order they appear in the message,
 *    and by_type elements point at first payload of respective type.
 */
x4m_struct( x4s_ike_message )
{
  x4s_buf pkt;                  /* original ISAKMP packet */
  x4s_isakmp_header * hdr;      /* convenience shortcut, casted pkt->body */
  
  x4s_ike_payload   by_order[x4c_ike_payload_max+1]; 
  x4s_ike_payload * by_type [x4c_ike_pt_max+1];

  uint32  mask_t;               /* bitmask of present ike_payload types   */
  uint32  mask_r;               /* bitmask of redundant ike_payload types */
};


/*
 * -- inbound processing --
 */
bval x4_ike_message_unpack(x4s_buf * pkt, x4s_ike_message * m, size_t blen);

/*
 * -- outbound processing --
 */
void x4_ike_message_create(x4s_buf *, 
                           uint8 * ci, uint8 * cr, 
                           uint8 et, uint32 msgid);

void x4_ike_message_append(x4s_buf *, 
                           uint8 pt, 
                           const void * data, size_t len);

#define x4_ike_message_appendb(p, pt, b) \
  { x4_assert(b); x4_ike_message_append((p), (pt), (b)->data, (b)->len); }

/*
 *  ike_message.mask_x fields contain bitmasks of ike_payload types. Bit 
 *  values they operate with are defined below.
 *  
 *  $Note that the bit names do not follow a naming convention to allow for
 *        a compact code. That's intentional and does not create any name 
 *        collisions as message.h is internal to libike.
 *
 */
typedef enum
{
  SA     = 1L << x4c_ike_pt_sa,
  P      = 1L << x4c_ike_pt_p,
  T      = 1L << x4c_ike_pt_t,
  KE     = 1L << x4c_ike_pt_ke,
  ID     = 1L << x4c_ike_pt_id,
  CERT   = 1L << x4c_ike_pt_cert,
  CR     = 1L << x4c_ike_pt_cr,
  HASH   = 1L << x4c_ike_pt_hash,
  SIG    = 1L << x4c_ike_pt_sig,
  NONCE  = 1L << x4c_ike_pt_nonce,
  N      = 1L << x4c_ike_pt_n,
  D      = 1L << x4c_ike_pt_d,
  V      = 1L << x4c_ike_pt_v,

  NATD   = 1L << x4c_ike_pt_natd,
  NATOA  = 1L << x4c_ike_pt_natoa,

} x4e_payload_bits;

#endif
