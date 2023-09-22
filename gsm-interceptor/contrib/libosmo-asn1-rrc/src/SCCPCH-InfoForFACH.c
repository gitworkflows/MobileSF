/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "SCCPCH-InfoForFACH.h"

static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_4 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH__modeSpecificInfo__fdd, fach_PCH_InformationList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FACH_PCH_InformationList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fach-PCH-InformationList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH__modeSpecificInfo__fdd, sib_ReferenceListFACH),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SIB_ReferenceListFACH,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sib-ReferenceListFACH"
		},
};
static ber_tlv_tag_t asn_DEF_fdd_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fach-PCH-InformationList at 10936 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* sib-ReferenceListFACH at 10938 */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_5 = {
	sizeof(struct SCCPCH_InfoForFACH__modeSpecificInfo__fdd),
	offsetof(struct SCCPCH_InfoForFACH__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_5,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_5 = {
	"fdd",
	"fdd",
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
	asn_DEF_fdd_tags_5,
	sizeof(asn_DEF_fdd_tags_5)
		/sizeof(asn_DEF_fdd_tags_5[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_5,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_5)
		/sizeof(asn_DEF_fdd_tags_5[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_fdd_5,
	2,	/* Elements count */
	&asn_SPC_fdd_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH__modeSpecificInfo__tdd, fach_PCH_InformationList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FACH_PCH_InformationList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fach-PCH-InformationList"
		},
};
static ber_tlv_tag_t asn_DEF_tdd_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* fach-PCH-InformationList at 10941 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_8 = {
	sizeof(struct SCCPCH_InfoForFACH__modeSpecificInfo__tdd),
	offsetof(struct SCCPCH_InfoForFACH__modeSpecificInfo__tdd, _asn_ctx),
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

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd"
		},
};
static asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd at 10936 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd at 10941 */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_4 = {
	sizeof(struct SCCPCH_InfoForFACH__modeSpecificInfo),
	offsetof(struct SCCPCH_InfoForFACH__modeSpecificInfo, _asn_ctx),
	offsetof(struct SCCPCH_InfoForFACH__modeSpecificInfo, present),
	sizeof(((struct SCCPCH_InfoForFACH__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_4,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_4 = {
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
	&asn_PER_type_modeSpecificInfo_constr_4,
	asn_MBR_modeSpecificInfo_4,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_SCCPCH_InfoForFACH_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH, secondaryCCPCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SecondaryCCPCH_Info,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"secondaryCCPCH-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH, tfcs),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_TFCS,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tfcs"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modeSpecificInfo"
		},
};
static ber_tlv_tag_t asn_DEF_SCCPCH_InfoForFACH_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_SCCPCH_InfoForFACH_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* secondaryCCPCH-Info at 10932 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tfcs at 10933 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* modeSpecificInfo at 10938 */
};
static asn_SEQUENCE_specifics_t asn_SPC_SCCPCH_InfoForFACH_specs_1 = {
	sizeof(struct SCCPCH_InfoForFACH),
	offsetof(struct SCCPCH_InfoForFACH, _asn_ctx),
	asn_MAP_SCCPCH_InfoForFACH_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_SCCPCH_InfoForFACH = {
	"SCCPCH-InfoForFACH",
	"SCCPCH-InfoForFACH",
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
	asn_DEF_SCCPCH_InfoForFACH_tags_1,
	sizeof(asn_DEF_SCCPCH_InfoForFACH_tags_1)
		/sizeof(asn_DEF_SCCPCH_InfoForFACH_tags_1[0]), /* 1 */
	asn_DEF_SCCPCH_InfoForFACH_tags_1,	/* Same as above */
	sizeof(asn_DEF_SCCPCH_InfoForFACH_tags_1)
		/sizeof(asn_DEF_SCCPCH_InfoForFACH_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_SCCPCH_InfoForFACH_1,
	3,	/* Elements count */
	&asn_SPC_SCCPCH_InfoForFACH_specs_1	/* Additional specs */
};

