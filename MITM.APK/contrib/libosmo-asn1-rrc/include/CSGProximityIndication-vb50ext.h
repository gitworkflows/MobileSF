/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_CSGProximityIndication_vb50ext_H_
#define	_CSGProximityIndication_vb50ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "EARFCNExtension.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CSGProximityIndication-vb50ext */
typedef struct CSGProximityIndication_vb50ext {
	EARFCNExtension_t	*cSGFrequencyInfoEUTRA	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CSGProximityIndication_vb50ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CSGProximityIndication_vb50ext;

#ifdef __cplusplus
}
#endif

#endif	/* _CSGProximityIndication_vb50ext_H_ */
#include <asn_internal.h>
