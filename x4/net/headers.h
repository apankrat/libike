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
 *	$Id: headers.h,v 1.3 2003/04/04 21:17:13 alex Exp $
 */

#ifndef _CPHL_NET_HEADERS_H_
#define _CPHL_NET_HEADERS_H_

#include "x4/core/bswap.h"
#include "x4/net/address.h"

/*
 *  Various protocol IDs
 */
typedef enum
{
  x4c_net_eth_proto_arp = x4m_bswap16(0x0806),
  x4c_net_eth_proto_ip4 = x4m_bswap16(0x0800),

  x4c_net_ip4_proto_icmp = 1,
  x4c_net_ip4_proto_ip4  = 4,
  x4c_net_ip4_proto_tcp  = 6,
  x4c_net_ip4_proto_udp  = 17,
  x4c_net_ip4_proto_esp  = 50,

} x4e_net_protocols;

/*
 *  Various network protocol headers
 */
#include "x4/core/_pack1"

x4m_struct( x4s_net_hdr_ethernet )
{
  x4t_net_eth dst;
  x4t_net_eth src;
  uint16  type;
};


x4m_struct( x4s_net_hdr_arp )
{
  uint16  ht;                 /* hardware_type;         */
  uint16  proto;              /* proto_type;            */
  uint8   has;                /* hardware_address_size; */
  uint8   pas;                /* proto_address_size;    */
  uint16  opcode;
  x4t_net_eth  sma;           /* sender_mac_address;    */
  x4t_net_ip4  sia;           /* sender_ip_address;     */
  x4t_net_eth  tma;           /* target_mac_address;    */
  x4t_net_ip4  tia;           /* target_ip_address;     */
};


x4m_struct( x4s_net_hdr_ip4 )
{
  uint8   verlen;
  uint8   tos;
  uint16  len;
  uint16  id;
  uint16  frag;
  uint8   ttl;
  uint8   proto;
  uint16  checksum;

  x4t_net_ip4 src;
  x4t_net_ip4 dst;
};


x4m_struct( x4s_net_hdr_icmp )
{
  uint8   type;
  uint8   code;
  uint16  checksum;
/*uint8   data[1]; // varies */
};


x4m_struct( x4s_net_hdr_udp )
{
  uint16  src;
  uint16  dst;
  uint16  len;
  uint16  checksum;
};


x4m_struct( x4s_net_hdr_tcp )
{
  uint16  src;
  uint16  dst;
  uint32  seq;
  uint32  ack;
  uint8   hdrlen;
  uint8   flags;
  uint16  window;
  uint16  checksum;
  uint16  urgent;
};


x4m_struct( x4s_net_hdr_esp )
{
  uint32  spi;
  uint32  seqno;
};

#include "x4/core/_unpack"

/*
 *  Commonly used header macros
 */
#define x4_ip_version(h)       (( (h)->verlen >> 4) & 0x0F )
#define x4_ip4_header_size(h)  (( (h)->verlen & 0x0F ) << 2)
#define x4_ip4_frag_offset(h)  (( lx_bswap16((h)->frag) & 0x1FFF ) << 3)
#define x4_ip4_is_fragment(h)  (    (h)->frag & lxm_bswap16(0x3FFF)   )
#define x4_ip4_is_last_frag(h) (! ( (h)->frag & lxm_bswap16(0x2000) ) )
#define x4_ip4_can_fragment(h) (! ( (h)->frag & lxm_bswap16(0x4000) ) )

#define x4_tcp_header_size(h)  (( (h)->hdrlen >> 2 ) & 0x3C )

#endif
