/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_URAUpdate_va40ext_IEs_H_
#define	_URAUpdate_va40ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum URAUpdate_va40ext_IEs__loggedMeasAvailable {
	URAUpdate_va40ext_IEs__loggedMeasAvailable_true	= 0
} e_URAUpdate_va40ext_IEs__loggedMeasAvailable;
typedef enum URAUpdate_va40ext_IEs__loggedANRResultsAvailable {
	URAUpdate_va40ext_IEs__loggedANRResultsAvailable_true	= 0
} e_URAUpdate_va40ext_IEs__loggedANRResultsAvailable;

/* URAUpdate-va40ext-IEs */
typedef struct URAUpdate_va40ext_IEs {
	long	*loggedMeasAvailable	/* OPTIONAL */;
	long	*loggedANRResultsAvailable	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} URAUpdate_va40ext_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_loggedMeasAvailable_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_loggedANRResultsAvailable_4;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_URAUpdate_va40ext_IEs;

#ifdef __cplusplus
}
#endif

#endif	/* _URAUpdate_va40ext_IEs_H_ */
#include <asn_internal.h>
