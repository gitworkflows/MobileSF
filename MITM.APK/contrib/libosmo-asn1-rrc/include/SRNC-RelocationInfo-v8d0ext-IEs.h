/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SRNC_RelocationInfo_v8d0ext_IEs_H_
#define	_SRNC_RelocationInfo_v8d0ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PDCP-ROHC-TargetMode.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SRNC-RelocationInfo-v8d0ext-IEs */
typedef struct SRNC_RelocationInfo_v8d0ext_IEs {
	PDCP_ROHC_TargetMode_t	*pdcp_ROHC_TargetMode	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SRNC_RelocationInfo_v8d0ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SRNC_RelocationInfo_v8d0ext_IEs;

#ifdef __cplusplus
}
#endif

#endif	/* _SRNC_RelocationInfo_v8d0ext_IEs_H_ */
#include <asn_internal.h>
