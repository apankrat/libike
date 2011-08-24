/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: const.h,v 1.7 2003/04/27 21:37:37 alex Exp $
 */

#ifndef _CPHL_IKE_RFC_CONSTANTS_H_
#define _CPHL_IKE_RFC_CONSTANTS_H_

#include "x4/core/types.h"

/*
 *  ISAKMP payload types
 */
typedef enum
{
  /* isakmp - 3.1 */
  x4c_ike_pt_none = 0,

  x4c_ike_pt_sa,      /* pt_sa,                    //  1 0002 */
  x4c_ike_pt_p,       /* pt_proposal,              //  2 0004 */
  x4c_ike_pt_t,       /* pt_transform,             //  3 0008 */
  x4c_ike_pt_ke,      /* pt_key_exchange,          //  4 0010 */
  x4c_ike_pt_id,      /* pt_identification,        //  5 0020 */
  x4c_ike_pt_cert,    /* pt_certificate,           //  6 0040 */
  x4c_ike_pt_cr,      /* pt_certificate_request,   //  7 0080 */
  x4c_ike_pt_hash,    /* pt_hash,                  //  8 0100 */
  x4c_ike_pt_sig,     /* pt_signature,             //  9 0200 */
  x4c_ike_pt_nonce,   /* pt_nonce,                 //  a 0400 */
  x4c_ike_pt_n,       /* pt_notification,          //  b 0800 */
  x4c_ike_pt_d,       /* pt_delete,                //  c 1000 */
  x4c_ike_pt_v,       /* pt_vendor,                //  d 2000 */

  /* NAT-T draft-05, almost RFC */
  x4c_ike_pt_natd = 15,  /* NAT-D,  detect                    */
  x4c_ike_pt_natoa,      /* NAT-OA, original address          */

  /*  */
  x4c_ike_pt_max = x4c_ike_pt_natoa,

  /* draft-ietf-ipsec-nat-t-ike-01.txt */
  x4c_ike_pt_01_natd = 130,
  x4c_ike_pt_01_natoa,

  /* draft-ietf-ipsec-nat-t-ike-03.txt */
  x4c_ike_pt_03_natd = 130,
  x4c_ike_pt_03_natoa,

  /* draft-ietf-ipsec-nat-t-ike-05.txt */
  x4c_ike_pt_05_natd = 15,
  x4c_ike_pt_05_natoa,

} x4e_ike_payload_type;

/*
 *  Exchange types 
 */
typedef enum
{
  x4c_ike_et_none = 0,

  /* isakmp */
  x4c_ike_et_base,
  x4c_ike_et_identity_protection,
  x4c_ike_et_authentication_only,
  x4c_ike_et_aggressive,
  x4c_ike_et_informational,

  /* ike */
  x4c_ike_et_main_mode       = x4c_ike_et_identity_protection,
  x4c_ike_et_aggressive_mode = x4c_ike_et_aggressive,
  x4c_ike_et_quick_mode      = 32,
  x4c_ike_et_new_group_mode,
  x4c_ike_et_acknowledgement    /* informational ack */

} x4e_ike_exchange_type;

/*
 *  Header Flags
 */
typedef enum
{
  x4c_ike_hf_encryption = 0x01,
  x4c_ike_hf_commit     = 0x02,
  x4c_ike_hf_auth_only  = 0x04,
  x4c_ike_hf_reserved   = 0xF8, /* these must be 0 */

} x4e_ike_header_flag;

/*
 *  Certificate Encodings
 */
typedef enum
{
  x4c_ike_ce_none = 0,
  x4c_ike_ce_pkcs7,
  x4c_ike_ce_pgp,
  x4c_ike_ce_dns,
  x4c_ike_ce_x509_sig,
  x4c_ike_ce_x509_ke,
  x4c_ike_ce_kerberos,
  x4c_ike_ce_crl,
  x4c_ike_ce_arl,
  x4c_ike_ce_spki,
  x4c_ike_ce_x509_attr,

} x4e_ike_cert_encoding;

/*
 *  Notify Message Types - 
 */
typedef enum
{
  x4c_ike_nm_none = 0,

  /*
      x4c_ike_nme = Notify Messages, Error Type
      x4c_ike_nms = Notify Messages, Status Types
  */

  /* isakmp */
  x4c_ike_nme_invalid_payload_type = 1,
  x4c_ike_nme_doi_not_supported,
  x4c_ike_nme_situation_not_supported,
  x4c_ike_nme_invalid_cookie,
  x4c_ike_nme_invalid_major_version,    /*  5   */
  x4c_ike_nme_invalid_minor_version,
  x4c_ike_nme_invalid_exchange_type,
  x4c_ike_nme_invalid_flags,
  x4c_ike_nme_invalid_message_id,
  x4c_ike_nme_invalid_protocol_id,      /*  10  */
  x4c_ike_nme_invalid_spi,
  x4c_ike_nme_invalid_transform_id,
  x4c_ike_nme_attributes_not_supported,
  x4c_ike_nme_no_proposal_chosen,
  x4c_ike_nme_bad_proposal_syntax,      /*  15  */
  x4c_ike_nme_payload_malformed,
  x4c_ike_nme_invalid_key_information,
  x4c_ike_nme_invalid_id_information,
  x4c_ike_nme_invalid_cert_encoding,
  x4c_ike_nme_invalid_certificate,      /*  20  */
  x4c_ike_nme_cert_type_unsupported,
  x4c_ike_nme_invalid_cert_authority,
  x4c_ike_nme_invalid_hash_information,
  x4c_ike_nme_authentication_failed,
  x4c_ike_nme_invalid_signature,        /*  25  */
  x4c_ike_nme_address_notification,
  x4c_ike_nme_notify_p1sa_lifetime,
  x4c_ike_nme_certificate_unavailable,
  x4c_ike_nme_unsupported_exchange_type,
  x4c_ike_nme_unequal_payload_length,   /*  30  */

  x4c_ike_nms_connected = 16384,

  /* ipsec */
  x4c_ike_nme_reserved  = 8192,

  x4c_ike_nms_responder_lifetime = 24576,
  x4c_ike_nms_replay_status,
  x4c_ike_nms_initial_contact,

} x4e_ike_notify_message_type;

/*
 *  Domain of Interpretation
 */
typedef enum
{
  x4c_ike_doi_isakmp = 0,
  x4c_ike_doi_ipsec  = 1,

} x4e_ike_doi;

/*
 *  Protocol ID
 */
typedef enum
{
  /* isakmp */
  x4c_ike_proto_reserved = 0,
  x4c_ike_proto_isakmp   = 1,

  /* ipsec */
  x4c_ike_proto_ipsec_ah,
  x4c_ike_proto_ipsec_esp,
  x4c_ike_proto_ipsec_ipcomp,

} x4e_ike_protocol;

/*
 *  IPsec Situation
 */
typedef enum
{
  x4c_ike_sit_identity_only = 0x01,
  x4c_ike_sit_secrecy       = 0x02,
  x4c_ike_sit_integrity     = 0x04,

} x4e_ike_situation;

/*
 *  IPsec Transformation Types
 */
typedef enum
{
  /* ipsec isakmp */
  x4c_ike_tr_isakmp_reserved = 0,
  x4c_ike_tr_isakmp_key_ike  = 1,      /* oakley */

  /* ipsec ah */
  x4c_ike_tr_ah_reserved1 = 0,
  x4c_ike_tr_ah_reserved2,
  x4c_ike_tr_ah_md5,
  x4c_ike_tr_ah_sha,
  x4c_ike_tr_ah_des,

  /* ipsec esp */
  x4c_ike_tr_esp_reserved = 0,
  x4c_ike_tr_esp_des_iv64,
  x4c_ike_tr_esp_des,
  x4c_ike_tr_esp_3des,
  x4c_ike_tr_esp_rc5,
  x4c_ike_tr_esp_idea,
  x4c_ike_tr_esp_cast,
  x4c_ike_tr_esp_blowfish,
  x4c_ike_tr_esp_3idea,
  x4c_ike_tr_esp_des_iv32,
  x4c_ike_tr_esp_rc4,
  x4c_ike_tr_esp_null,
  x4c_ike_tr_esp_aes,

  /* ipsec ipcomp */
  x4c_ike_tr_ipcomp_reserved = 0,
  x4c_ike_tr_ipcomp_oui,
  x4c_ike_tr_ipcomp_deflate,
  x4c_ike_tr_ipcomp_lzs

} x4e_ike_transform;

/*
 *   Identification Types
 */
typedef enum
{
  x4c_ike_id_reserved = 0,
  x4c_ike_id_ipv4_addr,  
  x4c_ike_id_fqdn,       
  x4c_ike_id_user_fqdn,  
  x4c_ike_id_ipv4_subnet,
  x4c_ike_id_ipv6_addr,  
  x4c_ike_id_ipv6_subnet,
  x4c_ike_id_ipv4_range, 
  x4c_ike_id_ipv6_range, 
  x4c_ike_id_der_asn1_dn,
  x4c_ike_id_der_asn1_gn,
  x4c_ike_id_key_id,     

} x4e_ike_id_type;

/*
 *  Phase 1 Attribute Types
 */
typedef enum
{
  x4c_ike_a1_reserved = 0,
  x4c_ike_a1_encryption_algorithm,   /* B  x4c_ike_a1e_xxx  */
  x4c_ike_a1_hash_algorithm,         /* B  x4c_ike_a1h_xxx  */
  x4c_ike_a1_auth_method,            /* B  x4c_ike_a1a_xxx  */
  x4c_ike_a1_group_description,      /* B  x4c_ike_a1g_xxx  */
  x4c_ike_a1_group_type,             /* B  x4c_ike_a1gt_xxx */
  x4c_ike_a1_group_prime,            /* V                   */
  x4c_ike_a1_group_generator_1,      /* V                   */
  x4c_ike_a1_group_generator_2,      /* V                   */
  x4c_ike_a1_group_curve_a,          /* V                   */
  x4c_ike_a1_group_curve_b,          /* V                   */
  x4c_ike_a1_life_type,              /* B  x4c_ike_a1l_xxx  */
  x4c_ike_a1_life_duration,          /* V                   */
  x4c_ike_a1_prf,                    /* B  <none defined>   */
  x4c_ike_a1_key_length,             /* B  <in bits>        */
  x4c_ike_a1_field_size,             /* B  <in bits>        */
  x4c_ike_a1_group_order,            /* V                   */

} x4e_ike_ph1_sa_attribute;

typedef enum
{
  x4c_ike_a1e_reserved = 0,
  x4c_ike_a1e_des_cbc,
  x4c_ike_a1e_idea_cbc,
  x4c_ike_a1e_blowfish_cbc,
  x4c_ike_a1e_rc5_cbc,               /* 16 rounds, 64 bits/block */
  x4c_ike_a1e_3des_cbc,
  x4c_ike_a1e_cast_cbc,
  x4c_ike_a1e_aes_cbc,

} x4e_ike_a1_encryption;

typedef enum
{
  x4c_ike_a1h_reserved = 0,
  x4c_ike_a1h_md5,
  x4c_ike_a1h_sha1,
  x4c_ike_a1h_tiger,
  x4c_ike_a1h_sha2_256,
  x4c_ike_a1h_sha2_384,
  x4c_ike_a1h_sha2_512,

} x4e_ike_a1_hashing;

typedef enum
{
  x4c_ike_a1a_reserved = 0,
  x4c_ike_a1a_preshared,
  x4c_ike_a1a_dss_sig,
  x4c_ike_a1a_rsa_sig,
  x4c_ike_a1a_rsa,
  x4c_ike_a1a_rsa_rev,
  x4c_ike_a1a_elgamal,
  x4c_ike_a1a_elgamal_rev,

} x4e_ike_a1_authentication;

typedef enum
{
  x4c_ike_a1g_reserved = 0,
  x4c_ike_a1g_modp_768,
  x4c_ike_a1g_modp_1024,
  x4c_ike_a1g_ec2n_155,
  x4c_ike_a1g_ec2n_185,
  x4c_ike_a1g_modp_1536,

  /* draft-ietf-ipsec-ike-modp-groups-05.txt */
  x4c_ike_a1g_modp_2048 = 14, /* was 42048 in *-03.txt */
  x4c_ike_a1g_modp_3072 = 15, /* was 43072 in *-03.txt */
  x4c_ike_a1g_modp_4096 = 16, /* was 44096 in *-03.txt */
  x4c_ike_a1g_modp_6144 = 17, /* was 46144 in *-03.txt */
  x4c_ike_a1g_modp_8192 = 18, /* was 48192 in *-03.txt */

} x4e_ike_a1_group_desc;

typedef enum
{
  x4c_ike_a1gt_reserved = 0,
  x4c_ike_a1gt_modp,
  x4c_ike_a1gt_ecp,
  x4c_ike_a1gt_ec2n,

} x4e_ike_a1_group_type;

typedef enum
{
  x4c_ike_a1l_reserved = 0,
  x4c_ike_a1l_seconds,
  x4c_ike_a1l_kilobytes,

} x4e_ike_a1_life_type;

/*
 *  Phase 2 Attribute Types
 */
typedef enum
{
  /*
    The following SA attribute definitions are used in Phase II of an 
    IKE negotiation. Attribute types can be either Basic (B) or Variable-
    Length (V).

    Attributes described as basic MUST NOT be encoded as variable.
    Variable length attributes MAY be encoded as basic attributes if
    their value can fit into two octets.
  */

  x4c_ike_a2_life_type = 1,      /* B, e_p1a_life_type               */
  x4c_ike_a2_life_duration,      /* V                                */
  x4c_ike_a2_oakley_group,       /* B, e_p1a_group_desc              */
  x4c_ike_a2_encapsulation_mode, /* B, e_p2a_encapsulation           */
  x4c_ike_a2_auth_algorithm,     /* B, e_p2a_authentication          */
  x4c_ike_a2_key_length,         /* B                                */
  x4c_ike_a2_key_rounds,         /* B                                */
  x4c_ike_a2_comp_dict_size,     /* B, the only value is 'reserved'  */
  x4c_ike_a2_comp_algorithm,     /* V                                */

} x4e_ike_phase2_sa_attribute;

typedef enum
{
  x4c_ike_a2e_reserved = 0,
  x4c_ike_a2e_tunnel,
  x4c_ike_a2e_transport,

  /* NAT-T draft-05, almost RFC */
  x4c_ike_a2e_tunnel_udp,
  x4c_ike_a2e_transport_udp,

  /* draft-ietf-ipsec-nat-t-ike-01.txt */
  x4c_ike_a2e_01_tunnel = 61443,         
  x4c_ike_a2e_01_transport,              

  /* draft-ietf-ipsec-nat-t-ike-03.txt */
  x4c_ike_a2e_03_tunnel = 61443,
  x4c_ike_a2e_03_transport,

  /* draft-ietf-ipsec-nat-t-ike-05.txt */
  x4c_ike_a2e_05_tunnel = 3,
  x4c_ike_a2e_05_transport,

} x4e_ike_a2_encaps;

typedef enum
{
  x4c_ike_a2a_reserved = 0,
  x4c_ike_a2a_hmac_md5_96,
  x4c_ike_a2a_hmac_sha1_96,
  x4c_ike_a2a_des_mac,
  x4c_ike_a2a_kpdk,
  x4c_ike_a2a_sha2_256,
  x4c_ike_a2a_sha2_384,
  x4c_ike_a2a_sha2_512,
  x4c_ike_a2a_ripemd,

} x4e_ike_a2_authentication;

/*
 *  Oakley Group Exponent and Modulus 
 */
extern const uint8 x4v_ike_modp_exp[1];

extern const uint8 x4v_ike_modp768 [96];
extern const uint8 x4v_ike_modp1024[128];
extern const uint8 x4v_ike_modp1536[192];
extern const uint8 x4v_ike_modp2048[256];
extern const uint8 x4v_ike_modp3072[384];
extern const uint8 x4v_ike_modp4096[512];
extern const uint8 x4v_ike_modp6144[768];
extern const uint8 x4v_ike_modp8192[1024];

/*
 *  NAT Traversal types
 */
typedef enum
{
  x4c_ike_natt_none = 0,
  x4c_ike_natt_01   = 0x01,       /* draft-ietf-ipsec-nat-t-ike-01+ */
  x4c_ike_natt_03   = 0x02,       /* draft-ietf-ipsec-nat-t-ike-03+ */
  x4c_ike_natt_05   = 0x04,       /* draft-ietf-ipsec-nat-t-ike-05  */

} x4e_ike_natt;

#endif
