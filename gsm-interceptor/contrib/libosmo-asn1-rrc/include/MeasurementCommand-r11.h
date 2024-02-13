/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MeasurementCommand_r11_H_
#define	_MeasurementCommand_r11_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementType-r11.h"
#include <NULL.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MeasurementCommand_r11_PR {
	MeasurementCommand_r11_PR_NOTHING,	/* No components present */
	MeasurementCommand_r11_PR_setup,
	MeasurementCommand_r11_PR_modify,
	MeasurementCommand_r11_PR_release
} MeasurementCommand_r11_PR;

/* Forward declarations */
struct MeasurementType_r11;

/* MeasurementCommand-r11 */
typedef struct MeasurementCommand_r11 {
	MeasurementCommand_r11_PR present;
	union MeasurementCommand_r11_u {
		MeasurementType_r11_t	 setup;
		struct MeasurementCommand_r11__modify {
			struct MeasurementType_r11	*measurementType	/* OPTIONAL */;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} modify;
		NULL_t	 release;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementCommand_r11_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementCommand_r11;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MeasurementType-r11.h"

#endif	/* _MeasurementCommand_r11_H_ */
#include <asn_internal.h>
