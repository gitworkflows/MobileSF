/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "NewInterRATCell-B.h"

static asn_per_constraints_t asn_PER_type_technologySpecificInfo_constr_3 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_gsm_4[] = {
	{ ATF_POINTER, 1, offsetof(struct NewInterRATCell_B__technologySpecificInfo__gsm, cellSelectionReselectionInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellSelectReselectInfoSIB_11_12,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cellSelectionReselectionInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B__technologySpecificInfo__gsm, interRATCellIndividualOffset),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATCellIndividualOffset,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATCellIndividualOffset"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B__technologySpecificInfo__gsm, bsic),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BSIC,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"bsic"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B__technologySpecificInfo__gsm, frequency_band),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Frequency_Band,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"frequency-band"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B__technologySpecificInfo__gsm, bcch_ARFCN),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BCCH_ARFCN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"bcch-ARFCN"
		},
	{ ATF_POINTER, 1, offsetof(struct NewInterRATCell_B__technologySpecificInfo__gsm, dummy),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dummy"
		},
};
static int asn_MAP_gsm_oms_4[] = { 0, 5 };
static ber_tlv_tag_t asn_DEF_gsm_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_gsm_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cellSelectionReselectionInfo at 17502 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* interRATCellIndividualOffset at 17503 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* bsic at 17504 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* frequency-band at 17505 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* bcch-ARFCN at 17506 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* dummy at 17509 */
};
static asn_SEQUENCE_specifics_t asn_SPC_gsm_specs_4 = {
	sizeof(struct NewInterRATCell_B__technologySpecificInfo__gsm),
	offsetof(struct NewInterRATCell_B__technologySpecificInfo__gsm, _asn_ctx),
	asn_MAP_gsm_tag2el_4,
	6,	/* Count of tags in the map */
	asn_MAP_gsm_oms_4,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_gsm_4 = {
	"gsm",
	"gsm",
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
	asn_DEF_gsm_tags_4,
	sizeof(asn_DEF_gsm_tags_4)
		/sizeof(asn_DEF_gsm_tags_4[0]) - 1, /* 1 */
	asn_DEF_gsm_tags_4,	/* Same as above */
	sizeof(asn_DEF_gsm_tags_4)
		/sizeof(asn_DEF_gsm_tags_4[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_gsm_4,
	6,	/* Elements count */
	&asn_SPC_gsm_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_is_2000_11[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B__technologySpecificInfo__is_2000, is_2000SpecificMeasInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IS_2000SpecificMeasInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"is-2000SpecificMeasInfo"
		},
};
static ber_tlv_tag_t asn_DEF_is_2000_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_is_2000_tag2el_11[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* is-2000SpecificMeasInfo at 17513 */
};
static asn_SEQUENCE_specifics_t asn_SPC_is_2000_specs_11 = {
	sizeof(struct NewInterRATCell_B__technologySpecificInfo__is_2000),
	offsetof(struct NewInterRATCell_B__technologySpecificInfo__is_2000, _asn_ctx),
	asn_MAP_is_2000_tag2el_11,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_is_2000_11 = {
	"is-2000",
	"is-2000",
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
	asn_DEF_is_2000_tags_11,
	sizeof(asn_DEF_is_2000_tags_11)
		/sizeof(asn_DEF_is_2000_tags_11[0]) - 1, /* 1 */
	asn_DEF_is_2000_tags_11,	/* Same as above */
	sizeof(asn_DEF_is_2000_tags_11)
		/sizeof(asn_DEF_is_2000_tags_11[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_is_2000_11,
	1,	/* Elements count */
	&asn_SPC_is_2000_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_technologySpecificInfo_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B__technologySpecificInfo, choice.gsm),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_gsm_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"gsm"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B__technologySpecificInfo, choice.is_2000),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_is_2000_11,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"is-2000"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B__technologySpecificInfo, choice.absent),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"absent"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B__technologySpecificInfo, choice.spare1),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"spare1"
		},
};
static asn_TYPE_tag2member_t asn_MAP_technologySpecificInfo_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* gsm at 17502 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* is-2000 at 17513 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* absent at 17518 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* spare1 at 17519 */
};
static asn_CHOICE_specifics_t asn_SPC_technologySpecificInfo_specs_3 = {
	sizeof(struct NewInterRATCell_B__technologySpecificInfo),
	offsetof(struct NewInterRATCell_B__technologySpecificInfo, _asn_ctx),
	offsetof(struct NewInterRATCell_B__technologySpecificInfo, present),
	sizeof(((struct NewInterRATCell_B__technologySpecificInfo *)0)->present),
	asn_MAP_technologySpecificInfo_tag2el_3,
	4,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_technologySpecificInfo_3 = {
	"technologySpecificInfo",
	"technologySpecificInfo",
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
	&asn_PER_type_technologySpecificInfo_constr_3,
	asn_MBR_technologySpecificInfo_3,
	4,	/* Elements count */
	&asn_SPC_technologySpecificInfo_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_NewInterRATCell_B_1[] = {
	{ ATF_POINTER, 1, offsetof(struct NewInterRATCell_B, interRATCellID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATCellID,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATCellID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterRATCell_B, technologySpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_technologySpecificInfo_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"technologySpecificInfo"
		},
};
static int asn_MAP_NewInterRATCell_B_oms_1[] = { 0 };
static ber_tlv_tag_t asn_DEF_NewInterRATCell_B_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_NewInterRATCell_B_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* interRATCellID at 17499 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* technologySpecificInfo at 17510 */
};
static asn_SEQUENCE_specifics_t asn_SPC_NewInterRATCell_B_specs_1 = {
	sizeof(struct NewInterRATCell_B),
	offsetof(struct NewInterRATCell_B, _asn_ctx),
	asn_MAP_NewInterRATCell_B_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_NewInterRATCell_B_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_NewInterRATCell_B = {
	"NewInterRATCell-B",
	"NewInterRATCell-B",
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
	asn_DEF_NewInterRATCell_B_tags_1,
	sizeof(asn_DEF_NewInterRATCell_B_tags_1)
		/sizeof(asn_DEF_NewInterRATCell_B_tags_1[0]), /* 1 */
	asn_DEF_NewInterRATCell_B_tags_1,	/* Same as above */
	sizeof(asn_DEF_NewInterRATCell_B_tags_1)
		/sizeof(asn_DEF_NewInterRATCell_B_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_NewInterRATCell_B_1,
	2,	/* Elements count */
	&asn_SPC_NewInterRATCell_B_specs_1	/* Additional specs */
};

