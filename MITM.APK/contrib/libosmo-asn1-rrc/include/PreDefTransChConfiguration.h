/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_PreDefTransChConfiguration_H_
#define	_PreDefTransChConfiguration_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UL-CommonTransChInfo.h"
#include "UL-AddReconfTransChInfoList.h"
#include "DL-CommonTransChInfo.h"
#include "DL-AddReconfTransChInfoList.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PreDefTransChConfiguration */
typedef struct PreDefTransChConfiguration {
	UL_CommonTransChInfo_t	 ul_CommonTransChInfo;
	UL_AddReconfTransChInfoList_t	 ul_AddReconfTrChInfoList;
	DL_CommonTransChInfo_t	 dl_CommonTransChInfo;
	DL_AddReconfTransChInfoList_t	 dl_TrChInfoList;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PreDefTransChConfiguration_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PreDefTransChConfiguration;

#ifdef __cplusplus
}
#endif

#endif	/* _PreDefTransChConfiguration_H_ */
#include <asn_internal.h>
