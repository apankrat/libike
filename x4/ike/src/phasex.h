/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: phasex.h,v 1.2 2003/04/04 19:56:53 alex Exp $
 */

#ifndef _CPHL_IKE_PHASE_AGNOSTIC_STUFF_H_
#define _CPHL_IKE_PHASE_AGNOSTIC_STUFF_H_

/*
 *  $todo - add comment here
 */

#include "phase1.h"

bval   x4_ike_sx_check_notify(const x4s_buf * body, size_t spilen);
size_t x4_ike_sx_format_notify4(uint16 code, uint32 spi, uint8 * buf);

bval   x4_ike_sx_send_inf(x4s_ike_phase1 *, uint16 code, uint32 spi);
bval   x4_ike_sx_recv_inf(x4s_ike_phase1 *);

bval   x4_ike_sx_send_delete(x4s_ike_phase1 *, uint32 spi);

#endif
