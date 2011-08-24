/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: address.c,v 1.2 2003/04/04 19:56:53 alex Exp $
 */

#include "x4/net/address.h"
#include "x4/core/debug.h"
#include "x4/core/memory.h"

/*  */
int x4_net_compare_ip(const x4u_net_ip * ip1, 
                      const x4u_net_ip * ip2, 
                      x4e_net_ip type)
{
  uint len = 0;

  x4_assert(ip1 && ip2);
  
  switch (type)
  {
  case x4c_net_ip_v4: len=4; break;
  case x4c_net_ip_v6: len=16; break;
  }

  x4_assert(len);

  return x4_memcmp(ip1, ip2, len); 
}

int x4_net_compare_link(const x4s_net_link * s1, 
                        const x4s_net_link * s2, 
                        bval local)
{
  int r;
  
  x4_assert(s1 && s2);

  r = s1->type - s2->type;
    
  if (!r)
    r = local ? x4_net_compare_ip(&s1->l.ip, &s2->l.ip, s1->type)
              : x4_net_compare_ip(&s1->r.ip, &s2->r.ip, s1->type);

  if (!r)
    r = local ? s1->l.port - s2->l.port
              : s1->r.port - s2->r.port;
    
  return r;
}
