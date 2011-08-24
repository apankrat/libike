#include "natt.h"
#include "utils.h"
#include "x4/core/debug.h"

/*
 *  MD5 hashes of 'draft-ietf-ipsec-nat-t-ike-00' and
 *                'draft-ietf-ipsec-nat-t-ike-03'
 */
static const x4s_buf _natt_01 =
{ 
  (void*)"\x44\x85\x15\x2d\x18\xb6\xbb\xcd\x0b\xe8\xa8\x46\x95\x79\xdd\xcc", 
  0, 16
};

static const x4s_buf _natt_03 =
{ 
  (void*)"\x7d\x94\x19\xa6\x53\x10\xca\x6f\x2c\x17\x9d\x92\x15\x52\x9d\x56",
  0, 16
};

/*
 *
 */
void x4_natt_compute_hashes(x4s_ike_phase1 * s1)
{
  /*
   *  draft-ietf-ipsec-nat-t-ike-03.txt
   */
  uint local;

  x4_assert(s1 && s1->sa.hasher);

  for (local=0; local<2; local++)
  {
    x4s_hasher * h;
    uint16     port = local ? s1->link.l.port : s1->link.r.port;
    uint8    * ip   = local ? s1->link.l.ip.v : s1->link.r.ip.v;
    x4s_buf * buf  = local ? &s1->data.natd_l : &s1->data.natd_r;

    h = s1->sa.hasher->instance();
    x4_assert(h);

    /* HASH = HASH(CKY-I | CKY-R | IP | Port) */

    h->update(h, s1->ci, 8);
    h->update(h, s1->cr, 8);
    
    switch (s1->link.type)
    {
    case x4c_net_ip_v4: h->update(h, ip, 4); break;
    case x4c_net_ip_v6: h->update(h, ip, 16); break;
    default: x4_assert(0);
    }
    
    port = x4_bswap16(port);
    h->update(h, &port, 2);

    x4_buf_resize(buf, h->api->hlen);

    h->complete(h, buf->data);
  }
}

void x4_natt_append_vid(x4s_ike_phase1 * s1)
{
  x4s_ike_exchange * xchg = (x4_assert(s1), &s1->xchg);

  if (s1->natt & x4c_ike_natt_01)
    x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_v, &_natt_01);

  if (s1->natt & x4c_ike_natt_03)
    x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_v, &_natt_03);
}

void x4_natt_append_natd(x4s_ike_phase1 * s1)
{
  x4s_ike_exchange * xchg = (x4_assert(s1), &s1->xchg);

  x4_assert(s1->natt);
  x4_assert(s1->data.natd_l.len);
  x4_assert(s1->data.natd_r.len);

  x4_ike_message_appendb(&xchg->out.pkt, 
                         x4_natt_pt(s1->natt, x4c_ike_pt_natd), 
                         &s1->data.natd_r);

  x4_ike_message_appendb(&xchg->out.pkt, 
                         x4_natt_pt(s1->natt, x4c_ike_pt_natd), 
                         &s1->data.natd_l);
}

/*  */
void x4_natt_process_vid(x4s_ike_phase1 * s1)
{
  x4s_ike_message * m = (x4_assert(s1), &s1->xchg.in.msg);
  x4s_ike_payload * p;
  uint8 natt = 0;

  /* check if the peer supports NAT traversal draft */
  if (! s1->natt)
    return;

  /* scan all Vendor ID payloads */
  for (p = m->by_order; p->type; p++)
    if (p->type == x4c_ike_pt_v)
      if (x4_buf_compare(&p->body, &_natt_01) == 0)
        natt |= x4c_natt_00;
      else
      if (x4_buf_compare(&p->body, &_natt_03) == 0)
        natt |= x4c_natt_03;

  /* select only shared NAT traversal methods */
  natt &= s1->natt;

  /* .. and leave only the lowest ranking one */
  s1->natt = natt & -natt;
}

/*  */
bval x4_natt_process_natd(x4s_ike_phase1 * s1)
{
  x4s_ike_message * m = (x4_assert(s1), &s1->xchg.in.msg);
  x4s_ike_payload * p;
  uint i;
  bval nated_r = btrue;

  if (! s1->natt)
  {
    /* 
     * make sure the peer did not send any NATD payloads if
     * we dont share at least one common NAT-T capability 
     */
    return (m->mask_t & NATD) == 0;
  }

  s1->nated = btrue;
  
  for (p=m->by_order, i=0; p->type; p++)
    if (p->type == x4c_ike_pt_natd)
      if (! i++)
      {
        /* first NATD payload is our IP/port hashed */
        if (! x4_buf_compare(&p->body, &s1->data.natd_l) )

          /* same stuff, which means we are NOT behind NAT */
          s1->nated = bfalse;
      }
      else

        /* second+ NATD payloads are hashes of peer's IP/port */
        if (! x4_buf_compare(&p->body, &s1->data.natd_r) )
        {
          /* got a match, the peer is NOT behind the NAT */
          nated_r = bfalse;
          break;
        }

  if (i < 2)
    return bfalse;

  /* 
   *  Nobody's NAT'ed 
   *
   *  $note: some scenarios may still require exercising NAT traversal
   *         eventhough there is no NAT present between the peers. If 
   *         that's the need, the following two lines must commented out.
   *
   */
  if (! s1->nated && ! nated_r)
    s1->natt = 0;

  return (i < 2) ? bfalse : btrue;
}

/*
 *
 */
uint8 x4_natt_pt(uint8 natt, x4e_ike_payload_type pt)
{
  x4_assert(pt == x4c_ike_pt_natd ||
            pt == x4c_ike_pt_natoa);

  switch (natt)
  {
  case x4c_ike_natt_01: pt += (x4c_ike_pt_01_natd - x4c_ike_pt_natd); break;
  case x4c_ike_natt_03: pt += (x4c_ike_pt_03_natd - x4c_ike_pt_natd); break;
  case x4c_ike_natt_05: pt += (x4c_ike_pt_05_natd - x4c_ike_pt_natd); break;
  default:
    x4_assert(0);
  }

  return pt;
}

bval x4_natt_float(uint8 natt)
{
  switch(natt)
  {
  case x4c_ike_natt_01: return bfalse;
  case x4c_ike_natt_03: 
  case x4c_ike_natt_05: return btrue;
  }

  x4_assert(0);
  return bfalse;
}

uint16 x4_natt_encaps(uint8 natt, x4e_ike_a2_encaps encaps)
{
  x4_assert(x4c_ike_a2e_tunnel <= encaps && 
            encaps <= x4c_ike_a2e_transport);
  
  switch (natt)
  {
  case x4c_ike_natt_none:
    break;

  case x4c_ike_natt_01: 
    encaps += (x4c_ike_a2e_01_tunnel - x4c_ike_a2e_tunnel);
    break;

  case x4c_ike_natt_03: 
    encaps += (x4c_ike_a2e_03_tunnel - x4c_ike_a2e_tunnel);
    break;

  case x4c_ike_natt_05: 
    encaps += (x4c_ike_a2e_05_tunnel - x4c_ike_a2e_tunnel);
    break;

  default:
    x4_assert(0);
  }

  return encaps;
}
