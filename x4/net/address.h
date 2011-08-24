/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: address.h,v 1.5 2003/04/04 21:17:13 alex Exp $
 */

#ifndef _CPHL_NET_ADDRESS_H_
#define _CPHL_NET_ADDRESS_H_

#include "x4/core/types.h"
#include "x4/core/macros.h"

/*
 *  Various network related data types and constants.
 *
 */

/*
 *  ** Datalink layer **
 */
typedef enum
{
  x4c_net_media_unknown = 0,

  x4c_net_media_none,
  x4c_net_media_ethernet,
  x4c_net_media_tokenring,

} x4e_net_media;

typedef uint8 x4t_net_eth[6];

x4m_union( x4u_net_media )
{
  x4t_net_eth  eth;
  uint8 v[1];
};

x4m_struct( x4s_net_media )
{
  x4e_net_media  type;
  x4u_net_media  addr;
};


/*
 *  ** IP layer **
 */
typedef enum
{
  x4c_net_ip_unknown = 0,

  x4c_net_ip_v4,
  x4c_net_ip_v6,
  x4c_net_ip_ipx,

} x4e_net_ip;

typedef uint8  x4t_net_ip4[4];
typedef uint8  x4t_net_ip6[16];

x4m_union( x4u_net_ip )
{
  x4t_net_ip4  v4;
  x4t_net_ip6  v6;
  uint8  v[1];
  uint32 x;
};

x4m_struct( x4s_net_ip )
{
  x4e_net_ip  type;
  x4u_net_ip  addr;
};

/*
 *  ** misc addressing structures **
 */
x4m_struct( x4s_net_socket )
{
  x4e_net_ip  type;
  x4u_net_ip  ip;
  uint16      port;
};

x4m_struct( x4s_net_link )
{
  x4e_net_ip type;
  
  struct
  {
    x4u_net_ip ip;
    uint16     port;

  } l, r;
};


/*
 *  misc functions
 *
int x4_net_compare_socket(const x4s_net_socket * , const x4s_net_socket * );
int x4_net_compare_link  (const x4s_net_link * , const x4s_net_link * );
 */

int x4_net_compare_ip(const x4u_net_ip * , 
                      const x4u_net_ip * , 
                      x4e_net_ip);

int x4_net_compare_link(const x4s_net_link * , 
                        const x4s_net_link * , 
                        bval local);
 
#endif
