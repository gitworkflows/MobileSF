/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DL_PhysChCapabilityTDD_128_v770ext_H_
#define	_DL_PhysChCapabilityTDD_128_v770ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MultiCarrier-HSDSCH-physical-layer-category.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DL-PhysChCapabilityTDD-128-v770ext */
typedef struct DL_PhysChCapabilityTDD_128_v770ext {
	MultiCarrier_HSDSCH_physical_layer_category_t	*multiCarrier_physical_layer_category	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_PhysChCapabilityTDD_128_v770ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_PhysChCapabilityTDD_128_v770ext;

#ifdef __cplusplus
}
#endif

#endif	/* _DL_PhysChCapabilityTDD_128_v770ext_H_ */
#include <asn_internal.h>
