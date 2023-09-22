/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMS_L1CombiningSchedule_H_
#define	_MBMS_L1CombiningSchedule_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMS-L1CombiningSchedule-32.h"
#include "MBMS-L1CombiningSchedule-64.h"
#include "MBMS-L1CombiningSchedule-128.h"
#include "MBMS-L1CombiningSchedule-256.h"
#include "MBMS-L1CombiningSchedule-512.h"
#include "MBMS-L1CombiningSchedule-1024.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MBMS_L1CombiningSchedule_PR {
	MBMS_L1CombiningSchedule_PR_NOTHING,	/* No components present */
	MBMS_L1CombiningSchedule_PR_cycleLength_32,
	MBMS_L1CombiningSchedule_PR_cycleLength_64,
	MBMS_L1CombiningSchedule_PR_cycleLength_128,
	MBMS_L1CombiningSchedule_PR_cycleLength_256,
	MBMS_L1CombiningSchedule_PR_cycleLength_512,
	MBMS_L1CombiningSchedule_PR_cycleLength_1024
} MBMS_L1CombiningSchedule_PR;

/* MBMS-L1CombiningSchedule */
typedef struct MBMS_L1CombiningSchedule {
	MBMS_L1CombiningSchedule_PR present;
	union MBMS_L1CombiningSchedule_u {
		MBMS_L1CombiningSchedule_32_t	 cycleLength_32;
		MBMS_L1CombiningSchedule_64_t	 cycleLength_64;
		MBMS_L1CombiningSchedule_128_t	 cycleLength_128;
		MBMS_L1CombiningSchedule_256_t	 cycleLength_256;
		MBMS_L1CombiningSchedule_512_t	 cycleLength_512;
		MBMS_L1CombiningSchedule_1024_t	 cycleLength_1024;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_L1CombiningSchedule_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_L1CombiningSchedule;

#ifdef __cplusplus
}
#endif

#endif	/* _MBMS_L1CombiningSchedule_H_ */
#include <asn_internal.h>
