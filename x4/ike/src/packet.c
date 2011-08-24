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
 *	$Id: packet.c,v 1.2 2003/04/04 19:56:53 alex Exp $
 */

#include "packet.h"
#include "x4/core/memory.h"

/*  */
void x4_ike_packet_in_free(x4s_ike_packet_in * in)
{
  x4_assert(in);
}

void x4_ike_packet_out_free(x4s_ike_packet_out * out)
{
  x4_assert(out);
  x4_buf_free(&out->pkt);
}

/*  */
void x4_ike_packet_out_reset(x4s_ike_packet_out * out, uint8 * hash)
{
  x4_assert(out);

  /* no packet to reply with yet */
  x4_buf_free(&out->pkt);

  /* set an associated inbound packet's hash */
  if (hash) x4_memmove(out->hash, hash, x4c_hash_max);
  else      x4_memset(out->hash, 0, x4c_hash_max);

  /* reset retransmission info */
  out->retry     = 0;
  out->timestamp = 0;
  out->timeout   = 0;
}
