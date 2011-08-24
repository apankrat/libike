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
 *	$Id: isakmp.h,v 1.2 2003/04/10 03:45:41 alex Exp $
 */

#ifndef _CPHL_IKE_RFC_STRUCTURES_H_
#define _CPHL_IKE_RFC_STRUCTURES_H_

#include "x4/core/types.h"

/*
 *  Various RFC-defined ISAKMP/IKE structures including:
 *
 *    isakmp_header  - ISAKMP message header
 *    isakmp_payload - ISAKMP payload header
 *    isakmp_notify  - ISAKMP NOTIFY payload body
 *    isakmp_delete  - ISAKMP DELETE payload body
 *
 */
#include "x4/core/_pack1"

/*  */
x4m_struct( x4s_isakmp_header )
{
  uint8   ci[8];        /* I cookie                                     */
  uint8   cr[8];        /* R cookie                                     */
  uint8   np;           /* next_payload - from pt_xx enum               */
  uint8   ver;          /* major / minor (0x10)                         */
  uint8   et;           /* exchange type - from et_xx                   */
  uint8   flags;        /* hf_xx                                        */
  uint32  msgid;        /* message id                                   */
  uint32  len;          /* .. of the message (header+payloads) in bytes */
};                              
                                
/*  */
x4m_struct( x4s_isakmp_payload )
{                               
  uint8   np;           /* next_payload                                 */
  uint8   reserved;     /* must be 0                                    */
  uint16  len;          /* length of the payload in bytes (w/ header)   */
  uint8   data[1];          
};

/*  */
x4m_struct( x4s_isakmp_notify )
{
  uint32  doi;
  uint8   proto;
  uint8   spi_len;
  uint16  type;
/*uint8   spi[1];*/
};

/*  */
x4m_struct( x4s_isakmp_delete )
{
  uint32  doi;
  uint8   proto;
  uint8   spi_len;
  uint16  spi_count;
};

#include "x4/core/_unpack"


#endif
