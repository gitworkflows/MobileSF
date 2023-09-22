/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_E_AGCH_Individual_H_
#define	_E_AGCH_Individual_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "DL-TS-ChannelisationCode.h"
#include "MidambleShiftAndBurstType-EDCH.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* E-AGCH-Individual */
typedef struct E_AGCH_Individual {
	long	 tS_number;
	DL_TS_ChannelisationCode_t	 channelisation_code;
	MidambleShiftAndBurstType_EDCH_t	 midambleShiftAndBurstType;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_AGCH_Individual_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E_AGCH_Individual;

#ifdef __cplusplus
}
#endif

#endif	/* _E_AGCH_Individual_H_ */
#include <asn_internal.h>
