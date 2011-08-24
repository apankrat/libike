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
 *	$Id: selector.h,v 1.3 2003/04/04 19:56:53 alex Exp $
 */

#ifndef _CPHL_NET_SELECTORS_H_
#define _CPHL_NET_SELECTORS_H_

#include "x4/net/headers.h"

/*
 *  General purpose traffic selector and supporting structures.
 *  $note: port_range of { 0, 0 } is equivalent to { 0, 65535 }
 */

/*
 *  A range of IP addresses
 */
x4m_struct( x4s_net_ip_range )          /* x4s_net_ip_range         */
{
  x4u_net_ip lo;
  x4u_net_ip hi;
};

/*
 *  A port range. 
 */
x4m_struct( x4s_net_port_range )        /* x4s_net_port_range       */
{
  uint16 lo;
  uint16 hi;
};

/*
 *
 */
x4m_struct( x4s_net_socket_range )        /* x4s_net_port_range       */
{
  x4s_net_ip_range   ip;
  x4s_net_port_range port;
};

/*
 *  A bidirectional IP traffic selector.
 *
 *    'proto' defines an associated IP protocol ID (ICMP,TCP,UDP..)
 *    'type'  defines which and if IP addressing scheme is used
 *    'ip'    defines a range of associated IP addresses (if type is not 0)
 *    'port'  defines a range of associated ports (if proto is TCP/UDP)
 *
 *    'l, r'  combine IP/port information by the side (local / remote)
 *
 *  $note: initializing all fields to 0 creates 'match all' selector
 *
 */
x4m_struct( x4s_net_selector )          /* x4s_net_selector         */
{
  uint8       proto;
  x4e_net_ip  type;
  
  x4s_net_socket_range  l, r; /* x.ip is valid if type is non-zero */
                              /* x.port is valid if proto is TCP or UDP */
};

/*
 *  Checks if selector is empty
 */
bval x4_net_is_empty_selector(const x4s_net_selector *);
bval x4_net_is_ip2ip_selector(const x4s_net_selector *, const x4s_net_link *);

void x4_net_ip2ip_to_selector(const x4s_net_link *, x4s_net_selector *);


#endif
