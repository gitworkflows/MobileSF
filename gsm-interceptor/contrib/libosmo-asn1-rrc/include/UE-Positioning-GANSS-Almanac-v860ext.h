/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UE_Positioning_GANSS_Almanac_v860ext_H_
#define	_UE_Positioning_GANSS_Almanac_v860ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ALM_NAVKeplerianSet;
struct ALM_ReducedKeplerianSet;
struct ALM_MidiAlmanacSet;
struct ALM_GlonassAlmanacSet;
struct ALM_ECEFsbasAlmanacSet;

/* UE-Positioning-GANSS-Almanac-v860ext */
typedef struct UE_Positioning_GANSS_Almanac_v860ext {
	struct ALM_NAVKeplerianSet	*alm_keplerianNAVAlmanac	/* OPTIONAL */;
	struct ALM_ReducedKeplerianSet	*alm_keplerianReducedAlmanac	/* OPTIONAL */;
	struct ALM_MidiAlmanacSet	*alm_keplerianMidiAlmanac	/* OPTIONAL */;
	struct ALM_GlonassAlmanacSet	*alm_keplerianGLONASS	/* OPTIONAL */;
	struct ALM_ECEFsbasAlmanacSet	*alm_ecefSBASAlmanac	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_GANSS_Almanac_v860ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_GANSS_Almanac_v860ext;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ALM-NAVKeplerianSet.h"
#include "ALM-ReducedKeplerianSet.h"
#include "ALM-MidiAlmanacSet.h"
#include "ALM-GlonassAlmanacSet.h"
#include "ALM-ECEFsbasAlmanacSet.h"

#endif	/* _UE_Positioning_GANSS_Almanac_v860ext_H_ */
#include <asn_internal.h>
