/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMS_TrCHInformation_Curr_H_
#define	_MBMS_TrCHInformation_Curr_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMS-CommonTrChIdentity.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_PTM_RBInformation_CList;
struct MBMS_MSCH_ConfigurationInfo_r6;

/* MBMS-TrCHInformation-Curr */
typedef struct MBMS_TrCHInformation_Curr {
	MBMS_CommonTrChIdentity_t	 transpCh_Info;
	struct MBMS_PTM_RBInformation_CList	*rbInformation	/* OPTIONAL */;
	struct MBMS_MSCH_ConfigurationInfo_r6	*msch_ConfigurationInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_TrCHInformation_Curr_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_TrCHInformation_Curr;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MBMS-PTM-RBInformation-CList.h"
#include "MBMS-MSCH-ConfigurationInfo-r6.h"

#endif	/* _MBMS_TrCHInformation_Curr_H_ */
#include <asn_internal.h>
