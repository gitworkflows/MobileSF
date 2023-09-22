/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_Common_E_DCH_MAC_d_Flow_Info_ConcurrentTTI_H_
#define	_Common_E_DCH_MAC_d_Flow_Info_ConcurrentTTI_H_


#include <asn_application.h>

/* Including external dependencies */
#include "E-DCH-MAC-d-FlowIdentity.h"
#include "E-DCH-MAC-d-FlowPowerOffset.h"
#include "E-DCH-MAC-d-FlowMaxRetrans.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Common-E-DCH-MAC-d-Flow-Info-ConcurrentTTI */
typedef struct Common_E_DCH_MAC_d_Flow_Info_ConcurrentTTI {
	E_DCH_MAC_d_FlowIdentity_t	 mac_d_FlowIdentity;
	E_DCH_MAC_d_FlowPowerOffset_t	*mac_d_FlowPowerOffset	/* OPTIONAL */;
	E_DCH_MAC_d_FlowMaxRetrans_t	*mac_d_FlowMaxRetrans	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Common_E_DCH_MAC_d_Flow_Info_ConcurrentTTI_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Common_E_DCH_MAC_d_Flow_Info_ConcurrentTTI;

#ifdef __cplusplus
}
#endif

#endif	/* _Common_E_DCH_MAC_d_Flow_Info_ConcurrentTTI_H_ */
#include <asn_internal.h>
