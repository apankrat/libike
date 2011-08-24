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
 *	$Id: selector.c,v 1.2 2003/04/04 19:56:54 alex Exp $
 */

#include "x4/net/selector.h"
#include "x4/core/debug.h"
#include "x4/core/memory.h"

/*  */
bval x4_net_is_empty_selector(const x4s_net_selector * s)
{
  x4_assert(s);

  return !(s)->proto && !(s)->type;
}

/*  */
bval x4_net_is_ip2ip_selector(const x4s_net_selector * s, 
                              const x4s_net_link * l)
{
  x4_assert(s && l);

  return ! s->proto && 
           s->type &&
           s->type == l->type &&
         ! x4_net_compare_ip(&s->l.ip.lo, &l->l.ip, s->type) &&
         ! x4_net_compare_ip(&s->l.ip.hi, &l->l.ip, s->type) &&
         ! x4_net_compare_ip(&s->r.ip.lo, &l->r.ip, s->type) &&
         ! x4_net_compare_ip(&s->r.ip.hi, &l->r.ip, s->type);
}

/*  */
void x4_net_ip2ip_to_selector(const x4s_net_link * l, x4s_net_selector * s)
{
  x4_assert(l && s);
  x4_assert(l->type);

  s->proto = 0;
  s->type = l->type;

  x4_memmove(&s->l.ip.lo, &l->l.ip, sizeof(x4u_net_ip));
  x4_memmove(&s->l.ip.hi, &l->l.ip, sizeof(x4u_net_ip));

  x4_memmove(&s->r.ip.lo, &l->r.ip, sizeof(x4u_net_ip));
  x4_memmove(&s->r.ip.hi, &l->r.ip, sizeof(x4u_net_ip));

  s->l.port.lo = 
  s->l.port.hi = l->l.port;

  s->r.port.lo = 
  s->r.port.hi = l->r.port;
}
