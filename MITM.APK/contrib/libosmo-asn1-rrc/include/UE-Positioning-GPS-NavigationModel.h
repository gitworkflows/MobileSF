/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UE_Positioning_GPS_NavigationModel_H_
#define	_UE_Positioning_GPS_NavigationModel_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NavigationModelSatInfoList.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UE-Positioning-GPS-NavigationModel */
typedef struct UE_Positioning_GPS_NavigationModel {
	NavigationModelSatInfoList_t	 navigationModelSatInfoList;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_GPS_NavigationModel_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_GPS_NavigationModel;

#ifdef __cplusplus
}
#endif

#endif	/* _UE_Positioning_GPS_NavigationModel_H_ */
#include <asn_internal.h>
