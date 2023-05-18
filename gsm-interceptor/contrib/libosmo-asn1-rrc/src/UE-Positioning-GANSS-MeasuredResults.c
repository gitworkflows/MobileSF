/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UE-Positioning-GANSS-MeasuredResults.h"

static asn_per_constraints_t asn_PER_type_referenceTime_constr_2 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_referenceTime_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_GANSS_MeasuredResults__referenceTime, choice.utran_GANSSReferenceTimeResult),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTRAN_GANSSReferenceTime,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"utran-GANSSReferenceTimeResult"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_GANSS_MeasuredResults__referenceTime, choice.ganssReferenceTimeOnly),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GANSSReferenceTimeOnly,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ganssReferenceTimeOnly"
		},
};
static asn_TYPE_tag2member_t asn_MAP_referenceTime_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* utran-GANSSReferenceTimeResult at 18934 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ganssReferenceTimeOnly at 18936 */
};
static asn_CHOICE_specifics_t asn_SPC_referenceTime_specs_2 = {
	sizeof(struct UE_Positioning_GANSS_MeasuredResults__referenceTime),
	offsetof(struct UE_Positioning_GANSS_MeasuredResults__referenceTime, _asn_ctx),
	offsetof(struct UE_Positioning_GANSS_MeasuredResults__referenceTime, present),
	sizeof(((struct UE_Positioning_GANSS_MeasuredResults__referenceTime *)0)->present),
	asn_MAP_referenceTime_tag2el_2,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_referenceTime_2 = {
	"referenceTime",
	"referenceTime",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	CHOICE_decode_uper,
	CHOICE_encode_uper,
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_referenceTime_constr_2,
	asn_MBR_referenceTime_2,
	2,	/* Elements count */
	&asn_SPC_referenceTime_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_UE_Positioning_GANSS_MeasuredResults_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_GANSS_MeasuredResults, referenceTime),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_referenceTime_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"referenceTime"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_GANSS_MeasuredResults, ganssGenericMeasurementInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GANSSGenericMeasurementInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ganssGenericMeasurementInfo"
		},
};
static ber_tlv_tag_t asn_DEF_UE_Positioning_GANSS_MeasuredResults_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_UE_Positioning_GANSS_MeasuredResults_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* referenceTime at 18934 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ganssGenericMeasurementInfo at 18938 */
};
static asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_GANSS_MeasuredResults_specs_1 = {
	sizeof(struct UE_Positioning_GANSS_MeasuredResults),
	offsetof(struct UE_Positioning_GANSS_MeasuredResults, _asn_ctx),
	asn_MAP_UE_Positioning_GANSS_MeasuredResults_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_UE_Positioning_GANSS_MeasuredResults = {
	"UE-Positioning-GANSS-MeasuredResults",
	"UE-Positioning-GANSS-MeasuredResults",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_UE_Positioning_GANSS_MeasuredResults_tags_1,
	sizeof(asn_DEF_UE_Positioning_GANSS_MeasuredResults_tags_1)
		/sizeof(asn_DEF_UE_Positioning_GANSS_MeasuredResults_tags_1[0]), /* 1 */
	asn_DEF_UE_Positioning_GANSS_MeasuredResults_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_Positioning_GANSS_MeasuredResults_tags_1)
		/sizeof(asn_DEF_UE_Positioning_GANSS_MeasuredResults_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_UE_Positioning_GANSS_MeasuredResults_1,
	2,	/* Elements count */
	&asn_SPC_UE_Positioning_GANSS_MeasuredResults_specs_1	/* Additional specs */
};

