/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_ProtocolErrorIndicatorWithMoreInfo_H_
#define	_ProtocolErrorIndicatorWithMoreInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "RRC-TransactionIdentifier.h"
#include "ProtocolErrorInformation.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ProtocolErrorIndicatorWithMoreInfo_PR {
	ProtocolErrorIndicatorWithMoreInfo_PR_NOTHING,	/* No components present */
	ProtocolErrorIndicatorWithMoreInfo_PR_noError,
	ProtocolErrorIndicatorWithMoreInfo_PR_errorOccurred
} ProtocolErrorIndicatorWithMoreInfo_PR;

/* ProtocolErrorIndicatorWithMoreInfo */
typedef struct ProtocolErrorIndicatorWithMoreInfo {
	ProtocolErrorIndicatorWithMoreInfo_PR present;
	union ProtocolErrorIndicatorWithMoreInfo_u {
		NULL_t	 noError;
		struct ProtocolErrorIndicatorWithMoreInfo__errorOccurred {
			RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
			ProtocolErrorInformation_t	 protocolErrorInformation;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} errorOccurred;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolErrorIndicatorWithMoreInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ProtocolErrorIndicatorWithMoreInfo;

#ifdef __cplusplus
}
#endif

#endif	/* _ProtocolErrorIndicatorWithMoreInfo_H_ */
#include <asn_internal.h>
