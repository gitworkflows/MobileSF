/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_InitialDirectTransfer_v3a0ext_H_
#define	_InitialDirectTransfer_v3a0ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "START-Value.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* InitialDirectTransfer-v3a0ext */
typedef struct InitialDirectTransfer_v3a0ext {
	START_Value_t	*start_Value	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InitialDirectTransfer_v3a0ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InitialDirectTransfer_v3a0ext;

#ifdef __cplusplus
}
#endif

#endif	/* _InitialDirectTransfer_v3a0ext_H_ */
#include <asn_internal.h>
