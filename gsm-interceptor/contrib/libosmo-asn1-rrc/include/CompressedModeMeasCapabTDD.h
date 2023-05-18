/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_CompressedModeMeasCapabTDD_H_
#define	_CompressedModeMeasCapabTDD_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RadioFrequencyBandTDD.h"
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CompressedModeMeasCapabTDD */
typedef struct CompressedModeMeasCapabTDD {
	RadioFrequencyBandTDD_t	 radioFrequencyBandTDD;
	BOOLEAN_t	 dl_MeasurementsTDD;
	BOOLEAN_t	 ul_MeasurementsTDD;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CompressedModeMeasCapabTDD_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CompressedModeMeasCapabTDD;

#ifdef __cplusplus
}
#endif

#endif	/* _CompressedModeMeasCapabTDD_H_ */
#include <asn_internal.h>
