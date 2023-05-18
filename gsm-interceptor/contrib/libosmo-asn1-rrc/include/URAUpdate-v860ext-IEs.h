/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_URAUpdate_v860ext_IEs_H_
#define	_URAUpdate_v860ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum URAUpdate_v860ext_IEs__supportOfHS_DSCHDRXOperation {
	URAUpdate_v860ext_IEs__supportOfHS_DSCHDRXOperation_true	= 0
} e_URAUpdate_v860ext_IEs__supportOfHS_DSCHDRXOperation;
typedef enum URAUpdate_v860ext_IEs__supportOfCommonEDCH {
	URAUpdate_v860ext_IEs__supportOfCommonEDCH_true	= 0
} e_URAUpdate_v860ext_IEs__supportOfCommonEDCH;
typedef enum URAUpdate_v860ext_IEs__supportOfMACiis {
	URAUpdate_v860ext_IEs__supportOfMACiis_true	= 0
} e_URAUpdate_v860ext_IEs__supportOfMACiis;

/* URAUpdate-v860ext-IEs */
typedef struct URAUpdate_v860ext_IEs {
	long	*supportOfHS_DSCHDRXOperation	/* OPTIONAL */;
	long	*supportOfCommonEDCH	/* OPTIONAL */;
	long	*supportOfMACiis	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} URAUpdate_v860ext_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_supportOfHS_DSCHDRXOperation_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_supportOfCommonEDCH_4;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_supportOfMACiis_6;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_URAUpdate_v860ext_IEs;

#ifdef __cplusplus
}
#endif

#endif	/* _URAUpdate_v860ext_IEs_H_ */
#include <asn_internal.h>
