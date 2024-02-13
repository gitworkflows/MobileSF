/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UL_RFC3095_Context_H_
#define	_UL_RFC3095_Context_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <NativeEnumerated.h>
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_RFC3095_Context__ul_mode {
	UL_RFC3095_Context__ul_mode_u	= 0,
	UL_RFC3095_Context__ul_mode_o	= 1,
	UL_RFC3095_Context__ul_mode_r	= 2
} e_UL_RFC3095_Context__ul_mode;

/* UL-RFC3095-Context */
typedef struct UL_RFC3095_Context {
	long	 rfc3095_Context_Identity;
	long	 ul_mode;
	OCTET_STRING_t	 ul_ref_ir;
	unsigned long	*ul_ref_time	/* OPTIONAL */;
	unsigned long	*ul_curr_time	/* OPTIONAL */;
	long	*ul_syn_offset_id	/* OPTIONAL */;
	unsigned long	*ul_syn_slope_ts	/* OPTIONAL */;
	long	*ul_ref_sn_1	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_RFC3095_Context_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_ul_mode_3;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_ul_ref_time_8;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_ul_curr_time_9;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_ul_syn_slope_ts_11;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_UL_RFC3095_Context;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_RFC3095_Context_H_ */
#include <asn_internal.h>
