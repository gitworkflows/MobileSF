/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_LoggingAbsoluteThreshold_H_
#define	_LoggingAbsoluteThreshold_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RSCPforANR.h"
#include "Ec-N0forANR.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LoggingAbsoluteThreshold_PR {
	LoggingAbsoluteThreshold_PR_NOTHING,	/* No components present */
	LoggingAbsoluteThreshold_PR_rscpforANR,
	LoggingAbsoluteThreshold_PR_ec_N0forANR
} LoggingAbsoluteThreshold_PR;

/* LoggingAbsoluteThreshold */
typedef struct LoggingAbsoluteThreshold {
	LoggingAbsoluteThreshold_PR present;
	union LoggingAbsoluteThreshold_u {
		RSCPforANR_t	 rscpforANR;
		Ec_N0forANR_t	 ec_N0forANR;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LoggingAbsoluteThreshold_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LoggingAbsoluteThreshold;

#ifdef __cplusplus
}
#endif

#endif	/* _LoggingAbsoluteThreshold_H_ */
#include <asn_internal.h>
