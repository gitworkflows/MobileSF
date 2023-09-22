/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MeasuredResultsOnRACHinterFreq_H_
#define	_MeasuredResultsOnRACHinterFreq_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "InterFreqRACHRepCellsList.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MeasuredResultsOnRACHinterFreq */
typedef struct MeasuredResultsOnRACHinterFreq {
	long	 interFreqCellIndication_SIB11;
	long	 interFreqCellIndication_SIB12;
	InterFreqRACHRepCellsList_t	 interFreqRACHRepCellsList;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasuredResultsOnRACHinterFreq_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasuredResultsOnRACHinterFreq;

#ifdef __cplusplus
}
#endif

#endif	/* _MeasuredResultsOnRACHinterFreq_H_ */
#include <asn_internal.h>
