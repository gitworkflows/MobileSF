/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UL-TransChCapability.h"

static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_6 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_tdd_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability__modeSpecificInfo__tdd, maxSimultaneousCCTrCH_Count),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxSimultaneousCCTrCH_Count,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxSimultaneousCCTrCH-Count"
		},
};
static ber_tlv_tag_t asn_DEF_tdd_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* maxSimultaneousCCTrCH-Count at 3397 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_8 = {
	sizeof(struct UL_TransChCapability__modeSpecificInfo__tdd),
	offsetof(struct UL_TransChCapability__modeSpecificInfo__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_8,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_8 = {
	"tdd",
	"tdd",
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
	asn_DEF_tdd_tags_8,
	sizeof(asn_DEF_tdd_tags_8)
		/sizeof(asn_DEF_tdd_tags_8[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_8,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_8)
		/sizeof(asn_DEF_tdd_tags_8[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd_8,
	1,	/* Elements count */
	&asn_SPC_tdd_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_6[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd"
		},
};
static asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd at 3394 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd at 3397 */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_6 = {
	sizeof(struct UL_TransChCapability__modeSpecificInfo),
	offsetof(struct UL_TransChCapability__modeSpecificInfo, _asn_ctx),
	offsetof(struct UL_TransChCapability__modeSpecificInfo, present),
	sizeof(((struct UL_TransChCapability__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_6,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_6 = {
	"modeSpecificInfo",
	"modeSpecificInfo",
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
	&asn_PER_type_modeSpecificInfo_constr_6,
	asn_MBR_modeSpecificInfo_6,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_UL_TransChCapability_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability, maxNoBitsTransmitted),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxNoBits,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxNoBitsTransmitted"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability, maxConvCodeBitsTransmitted),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxNoBits,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxConvCodeBitsTransmitted"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability, turboEncodingSupport),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_TurboSupport,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"turboEncodingSupport"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability, maxSimultaneousTransChs),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxSimultaneousTransChsUL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxSimultaneousTransChs"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modeSpecificInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability, maxTransmittedBlocks),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxTransportBlocksUL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxTransmittedBlocks"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability, maxNumberOfTFC),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxNumberOfTFC_UL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxNumberOfTFC"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransChCapability, maxNumberOfTF),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxNumberOfTF,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxNumberOfTF"
		},
};
static ber_tlv_tag_t asn_DEF_UL_TransChCapability_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_UL_TransChCapability_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* maxNoBitsTransmitted at 3389 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* maxConvCodeBitsTransmitted at 3390 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* turboEncodingSupport at 3391 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* maxSimultaneousTransChs at 3392 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* modeSpecificInfo at 3394 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* maxTransmittedBlocks at 3399 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* maxNumberOfTFC at 3400 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 } /* maxNumberOfTF at 3402 */
};
static asn_SEQUENCE_specifics_t asn_SPC_UL_TransChCapability_specs_1 = {
	sizeof(struct UL_TransChCapability),
	offsetof(struct UL_TransChCapability, _asn_ctx),
	asn_MAP_UL_TransChCapability_tag2el_1,
	8,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_UL_TransChCapability = {
	"UL-TransChCapability",
	"UL-TransChCapability",
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
	asn_DEF_UL_TransChCapability_tags_1,
	sizeof(asn_DEF_UL_TransChCapability_tags_1)
		/sizeof(asn_DEF_UL_TransChCapability_tags_1[0]), /* 1 */
	asn_DEF_UL_TransChCapability_tags_1,	/* Same as above */
	sizeof(asn_DEF_UL_TransChCapability_tags_1)
		/sizeof(asn_DEF_UL_TransChCapability_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_UL_TransChCapability_1,
	8,	/* Elements count */
	&asn_SPC_UL_TransChCapability_specs_1	/* Additional specs */
};

