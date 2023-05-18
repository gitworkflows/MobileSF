/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "RL-AdditionInformation-r6.h"

static asn_per_constraints_t asn_PER_type_dl_dpchInfo_constr_4 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_dl_dpchInfo_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RL_AdditionInformation_r6__dl_dpchInfo, choice.dl_DPCH_InfoPerRL),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_DL_DPCH_InfoPerRL_r5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-DPCH-InfoPerRL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RL_AdditionInformation_r6__dl_dpchInfo, choice.dl_FDPCH_InfoPerRL),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_FDPCH_InfoPerRL_r6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-FDPCH-InfoPerRL"
		},
};
static asn_TYPE_tag2member_t asn_MAP_dl_dpchInfo_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-DPCH-InfoPerRL at 10766 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dl-FDPCH-InfoPerRL at 10768 */
};
static asn_CHOICE_specifics_t asn_SPC_dl_dpchInfo_specs_4 = {
	sizeof(struct RL_AdditionInformation_r6__dl_dpchInfo),
	offsetof(struct RL_AdditionInformation_r6__dl_dpchInfo, _asn_ctx),
	offsetof(struct RL_AdditionInformation_r6__dl_dpchInfo, present),
	sizeof(((struct RL_AdditionInformation_r6__dl_dpchInfo *)0)->present),
	asn_MAP_dl_dpchInfo_tag2el_4,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_dl_dpchInfo_4 = {
	"dl-dpchInfo",
	"dl-dpchInfo",
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
	&asn_PER_type_dl_dpchInfo_constr_4,
	asn_MBR_dl_dpchInfo_4,
	2,	/* Elements count */
	&asn_SPC_dl_dpchInfo_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_RL_AdditionInformation_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RL_AdditionInformation_r6, primaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"primaryCPICH-Info"
		},
	{ ATF_POINTER, 1, offsetof(struct RL_AdditionInformation_r6, cell_Id),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cell-Id"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RL_AdditionInformation_r6, dl_dpchInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_dl_dpchInfo_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-dpchInfo"
		},
	{ ATF_POINTER, 2, offsetof(struct RL_AdditionInformation_r6, e_HICH_Information),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_HICH_Information,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-HICH-Information"
		},
	{ ATF_POINTER, 1, offsetof(struct RL_AdditionInformation_r6, e_RGCH_Information),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_RGCH_Information,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-RGCH-Information"
		},
};
static int asn_MAP_RL_AdditionInformation_r6_oms_1[] = { 1, 3, 4 };
static ber_tlv_tag_t asn_DEF_RL_AdditionInformation_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_RL_AdditionInformation_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* primaryCPICH-Info at 10763 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cell-Id at 10764 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* dl-dpchInfo at 10766 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* e-HICH-Information at 10769 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* e-RGCH-Information at 10770 */
};
static asn_SEQUENCE_specifics_t asn_SPC_RL_AdditionInformation_r6_specs_1 = {
	sizeof(struct RL_AdditionInformation_r6),
	offsetof(struct RL_AdditionInformation_r6, _asn_ctx),
	asn_MAP_RL_AdditionInformation_r6_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_RL_AdditionInformation_r6_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RL_AdditionInformation_r6 = {
	"RL-AdditionInformation-r6",
	"RL-AdditionInformation-r6",
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
	asn_DEF_RL_AdditionInformation_r6_tags_1,
	sizeof(asn_DEF_RL_AdditionInformation_r6_tags_1)
		/sizeof(asn_DEF_RL_AdditionInformation_r6_tags_1[0]), /* 1 */
	asn_DEF_RL_AdditionInformation_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_RL_AdditionInformation_r6_tags_1)
		/sizeof(asn_DEF_RL_AdditionInformation_r6_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RL_AdditionInformation_r6_1,
	5,	/* Elements count */
	&asn_SPC_RL_AdditionInformation_r6_specs_1	/* Additional specs */
};

