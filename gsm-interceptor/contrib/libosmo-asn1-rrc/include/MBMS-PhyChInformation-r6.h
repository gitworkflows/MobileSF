/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMS_PhyChInformation_r6_H_
#define	_MBMS_PhyChInformation_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMS-CommonPhyChIdentity.h"
#include "SecondaryCCPCHInfo-MBMS-r6.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MBMS-PhyChInformation-r6 */
typedef struct MBMS_PhyChInformation_r6 {
	MBMS_CommonPhyChIdentity_t	 mbms_CommonPhyChIdentity;
	SecondaryCCPCHInfo_MBMS_r6_t	 secondaryCCPCHInfo_MBMS;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_PhyChInformation_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_PhyChInformation_r6;

#ifdef __cplusplus
}
#endif

#endif	/* _MBMS_PhyChInformation_r6_H_ */
#include <asn_internal.h>
