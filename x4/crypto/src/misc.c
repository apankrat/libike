/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: misc.c,v 1.2 2003/04/04 19:56:53 alex Exp $
 */

#include "x4/crypto/misc.h"
#include "x4/crypto/dh.h"
#include "x4/crypto/random.h"

void x4_dh_data_free(x4s_dh_data * dh)
{
  x4_assert(dh);

  x4_buf_free(&dh->g);
  x4_buf_free(&dh->p);
  x4_buf_free(&dh->x);
  x4_buf_free(&dh->gx);
  x4_buf_free(&dh->gy);
  x4_buf_free(&dh->gxy);
}

/*  */
void x4_dh_initiate(x4s_dh_data * dh)
{
  x4_assert(dh);
  x4_assert(dh->g.len && dh->p.len);
  
  /* generate private value */
  x4_buf_resize(&dh->x, dh->p.len);
  x4_randomb(&dh->x);

  /* generate public DH key */
  x4_buf_free(&dh->gx);
  dh->gx = x4_dh_publicb(&dh->g, &dh->p, &dh->x);
  
  x4_assert(dh->gx.len);

  if (dh->gx.len < dh->p.len)
    x4_buf_prepend(&dh->gx, 0, dh->p.len - dh->gx.len);
}

/*  */
bval x4_dh_complete(x4s_dh_data * dh)
{
  x4_assert(dh);
  x4_assert(dh->g.len && dh->p.len && dh->x.len);
  x4_assert(dh->gx.len && dh->gy.len);

  /* generate shared DH key */
  x4_buf_free(&dh->gxy);
  dh->gxy = x4_dh_sharedb(&dh->g, &dh->p, &dh->x, &dh->gx, &dh->gy);

  return dh->gxy.len != 0;
}
