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
 *	$Id: sa.h,v 1.3 2003/04/10 03:45:41 alex Exp $
 */

#ifndef _CPHL_IKE_SA_H_
#define _CPHL_IKE_SA_H_

/*
 *  $todo - add a comment here
 */
#include "x4/misc/buffer.h"
#include "x4/net/address.h"

/*  */
#define x4c_ike_attribute_max   16
#define x4c_ike_transform_max   4
#define x4c_ike_proposal_max    16

/*
 *  SA payload & comrades
 */
x4m_struct( x4s_ike_sa_attribute )
{
  uint8 type;
  uint32 val;
};

x4m_struct( x4s_ike_sa_transform )
{
  uint8 index;
  uint8 type;

  x4s_ike_sa_attribute attr [x4c_ike_attribute_max+1];
};

x4m_struct( x4s_ike_sa_proposal )
{
  uint8  index;
  uint8  proto;
  x4s_buf spi;

  x4s_ike_sa_transform tr [x4c_ike_transform_max+1];
};

x4m_struct( x4s_ike_sa_payload )
{
  uint32  doi;
  uint32  sit;
  x4s_ike_sa_proposal pr [x4c_ike_proposal_max+1];
};

/*
 *  SA lifetime
 */
x4m_struct( x4s_ike_sa_lifetime )
{
  uint  seconds;  
  uint  kbytes;
};

/*
 *  Miscellaneous SA manipulation methods
 */
bval x4_ike_sa_unpack(const x4s_buf *, x4s_ike_sa_payload *);
void x4_ike_sa_pack  (const x4s_ike_sa_payload *, x4s_buf *);

int x4_ike_sa_compare(const x4s_buf * sa1, const x4s_buf * sa2, uint32 * spi);

#endif
