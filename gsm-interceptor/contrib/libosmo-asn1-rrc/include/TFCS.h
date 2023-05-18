/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_TFCS_H_
#define	_TFCS_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ExplicitTFCS-Configuration.h"
#include "SplitTFCI-Signalling.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TFCS_PR {
	TFCS_PR_NOTHING,	/* No components present */
	TFCS_PR_normalTFCI_Signalling,
	TFCS_PR_dummy
} TFCS_PR;

/* TFCS */
typedef struct TFCS {
	TFCS_PR present;
	union TFCS_u {
		ExplicitTFCS_Configuration_t	 normalTFCI_Signalling;
		SplitTFCI_Signalling_t	 dummy;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TFCS_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TFCS;

#ifdef __cplusplus
}
#endif

#endif	/* _TFCS_H_ */
#include <asn_internal.h>
