/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_HS_SICH_Configuration_TDD384_H_
#define	_HS_SICH_Configuration_TDD384_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TimeslotNumber.h"
#include "DL-TS-ChannelisationCode.h"
#include "MidambleConfigurationBurstType1and3.h"
#include <NULL.h>
#include "MidambleShiftLong.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HS_SICH_Configuration_TDD384__midambleAllocationMode_PR {
	HS_SICH_Configuration_TDD384__midambleAllocationMode_PR_NOTHING,	/* No components present */
	HS_SICH_Configuration_TDD384__midambleAllocationMode_PR_defaultMidamble,
	HS_SICH_Configuration_TDD384__midambleAllocationMode_PR_ueSpecificMidamble
} HS_SICH_Configuration_TDD384__midambleAllocationMode_PR;

/* HS-SICH-Configuration-TDD384 */
typedef struct HS_SICH_Configuration_TDD384 {
	TimeslotNumber_t	 timeslotNumber;
	DL_TS_ChannelisationCode_t	 channelisationCode;
	struct HS_SICH_Configuration_TDD384__midambleAllocationMode {
		HS_SICH_Configuration_TDD384__midambleAllocationMode_PR present;
		union HS_SICH_Configuration_TDD384__midambleAllocationMode_u {
			NULL_t	 defaultMidamble;
			struct HS_SICH_Configuration_TDD384__midambleAllocationMode__ueSpecificMidamble {
				MidambleShiftLong_t	 midambleShift;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} ueSpecificMidamble;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} midambleAllocationMode;
	MidambleConfigurationBurstType1and3_t	 midambleconfiguration;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HS_SICH_Configuration_TDD384_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HS_SICH_Configuration_TDD384;

#ifdef __cplusplus
}
#endif

#endif	/* _HS_SICH_Configuration_TDD384_H_ */
#include <asn_internal.h>
