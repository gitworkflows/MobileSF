/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RLC_Capability_v770ext_H_
#define	_RLC_Capability_v770ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RLC-Capability-v770ext */
typedef struct RLC_Capability_v770ext {
	BOOLEAN_t	 supportOfTwoLogicalChannel;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RLC_Capability_v770ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RLC_Capability_v770ext;

#ifdef __cplusplus
}
#endif

#endif	/* _RLC_Capability_v770ext_H_ */
#include <asn_internal.h>
