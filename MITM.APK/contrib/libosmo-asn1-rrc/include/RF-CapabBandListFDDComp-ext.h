/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RF_CapabBandListFDDComp_ext_H_
#define	_RF_CapabBandListFDDComp_ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RF-CapabBandFDDComp.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RF-CapabBandListFDDComp-ext */
typedef struct RF_CapabBandListFDDComp_ext {
	A_SEQUENCE_OF(RF_CapabBandFDDComp_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RF_CapabBandListFDDComp_ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RF_CapabBandListFDDComp_ext;

#ifdef __cplusplus
}
#endif

#endif	/* _RF_CapabBandListFDDComp_ext_H_ */
#include <asn_internal.h>
