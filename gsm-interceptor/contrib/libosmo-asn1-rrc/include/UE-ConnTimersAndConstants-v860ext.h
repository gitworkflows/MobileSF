/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UE_ConnTimersAndConstants_v860ext_H_
#define	_UE_ConnTimersAndConstants_v860ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "T-323.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UE-ConnTimersAndConstants-v860ext */
typedef struct UE_ConnTimersAndConstants_v860ext {
	T_323_t	*t_323	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_ConnTimersAndConstants_v860ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_ConnTimersAndConstants_v860ext;

#ifdef __cplusplus
}
#endif

#endif	/* _UE_ConnTimersAndConstants_v860ext_H_ */
#include <asn_internal.h>
