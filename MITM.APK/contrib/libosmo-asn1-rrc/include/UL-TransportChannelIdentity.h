/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UL_TransportChannelIdentity_H_
#define	_UL_TransportChannelIdentity_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UL-TrCH-Type.h"
#include "TransportChannelIdentity.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UL-TransportChannelIdentity */
typedef struct UL_TransportChannelIdentity {
	UL_TrCH_Type_t	 ul_TransportChannelType;
	TransportChannelIdentity_t	 ul_TransportChannelIdentity;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_TransportChannelIdentity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_TransportChannelIdentity;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_TransportChannelIdentity_H_ */
#include <asn_internal.h>
