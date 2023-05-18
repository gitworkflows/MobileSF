/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "MidambleShiftAndBurstType-EDCH.h"

static asn_per_constraints_t asn_PER_type_midambleAllocationMode_constr_5 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_midambleAllocationMode_constr_12 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_burstType_constr_2 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_ueSpecificMidamble_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode__ueSpecificMidamble, midambleShift),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftLong,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleShift"
		},
};
static ber_tlv_tag_t asn_DEF_ueSpecificMidamble_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_ueSpecificMidamble_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* midambleShift at 9597 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ueSpecificMidamble_specs_8 = {
	sizeof(struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode__ueSpecificMidamble),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode__ueSpecificMidamble, _asn_ctx),
	asn_MAP_ueSpecificMidamble_tag2el_8,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ueSpecificMidamble_8 = {
	"ueSpecificMidamble",
	"ueSpecificMidamble",
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
	asn_DEF_ueSpecificMidamble_tags_8,
	sizeof(asn_DEF_ueSpecificMidamble_tags_8)
		/sizeof(asn_DEF_ueSpecificMidamble_tags_8[0]) - 1, /* 1 */
	asn_DEF_ueSpecificMidamble_tags_8,	/* Same as above */
	sizeof(asn_DEF_ueSpecificMidamble_tags_8)
		/sizeof(asn_DEF_ueSpecificMidamble_tags_8[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_ueSpecificMidamble_8,
	1,	/* Elements count */
	&asn_SPC_ueSpecificMidamble_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_midambleAllocationMode_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode, choice.defaultMidamble),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"defaultMidamble"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode, choice.commonMidamble),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"commonMidamble"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode, choice.ueSpecificMidamble),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_ueSpecificMidamble_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueSpecificMidamble"
		},
};
static asn_TYPE_tag2member_t asn_MAP_midambleAllocationMode_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* defaultMidamble at 9593 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* commonMidamble at 9594 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* ueSpecificMidamble at 9597 */
};
static asn_CHOICE_specifics_t asn_SPC_midambleAllocationMode_specs_5 = {
	sizeof(struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode, _asn_ctx),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode, present),
	sizeof(((struct MidambleShiftAndBurstType_EDCH__burstType__type1__midambleAllocationMode *)0)->present),
	asn_MAP_midambleAllocationMode_tag2el_5,
	3,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_midambleAllocationMode_5 = {
	"midambleAllocationMode",
	"midambleAllocationMode",
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
	&asn_PER_type_midambleAllocationMode_constr_5,
	asn_MBR_midambleAllocationMode_5,
	3,	/* Elements count */
	&asn_SPC_midambleAllocationMode_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_type1_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1, midambleConfigurationBurstType1),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleConfigurationBurstType1,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleConfigurationBurstType1"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1, midambleAllocationMode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_midambleAllocationMode_5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleAllocationMode"
		},
};
static ber_tlv_tag_t asn_DEF_type1_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_type1_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* midambleConfigurationBurstType1 at 9591 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* midambleAllocationMode at 9593 */
};
static asn_SEQUENCE_specifics_t asn_SPC_type1_specs_3 = {
	sizeof(struct MidambleShiftAndBurstType_EDCH__burstType__type1),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type1, _asn_ctx),
	asn_MAP_type1_tag2el_3,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_type1_3 = {
	"type1",
	"type1",
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
	asn_DEF_type1_tags_3,
	sizeof(asn_DEF_type1_tags_3)
		/sizeof(asn_DEF_type1_tags_3[0]) - 1, /* 1 */
	asn_DEF_type1_tags_3,	/* Same as above */
	sizeof(asn_DEF_type1_tags_3)
		/sizeof(asn_DEF_type1_tags_3[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_type1_3,
	2,	/* Elements count */
	&asn_SPC_type1_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_ueSpecificMidamble_15[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode__ueSpecificMidamble, midambleShift),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftShort,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleShift"
		},
};
static ber_tlv_tag_t asn_DEF_ueSpecificMidamble_tags_15[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_ueSpecificMidamble_tag2el_15[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* midambleShift at 9607 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ueSpecificMidamble_specs_15 = {
	sizeof(struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode__ueSpecificMidamble),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode__ueSpecificMidamble, _asn_ctx),
	asn_MAP_ueSpecificMidamble_tag2el_15,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ueSpecificMidamble_15 = {
	"ueSpecificMidamble",
	"ueSpecificMidamble",
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
	asn_DEF_ueSpecificMidamble_tags_15,
	sizeof(asn_DEF_ueSpecificMidamble_tags_15)
		/sizeof(asn_DEF_ueSpecificMidamble_tags_15[0]) - 1, /* 1 */
	asn_DEF_ueSpecificMidamble_tags_15,	/* Same as above */
	sizeof(asn_DEF_ueSpecificMidamble_tags_15)
		/sizeof(asn_DEF_ueSpecificMidamble_tags_15[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_ueSpecificMidamble_15,
	1,	/* Elements count */
	&asn_SPC_ueSpecificMidamble_specs_15	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_midambleAllocationMode_12[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode, choice.defaultMidamble),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"defaultMidamble"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode, choice.commonMidamble),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"commonMidamble"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode, choice.ueSpecificMidamble),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_ueSpecificMidamble_15,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueSpecificMidamble"
		},
};
static asn_TYPE_tag2member_t asn_MAP_midambleAllocationMode_tag2el_12[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* defaultMidamble at 9603 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* commonMidamble at 9604 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* ueSpecificMidamble at 9607 */
};
static asn_CHOICE_specifics_t asn_SPC_midambleAllocationMode_specs_12 = {
	sizeof(struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode, _asn_ctx),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode, present),
	sizeof(((struct MidambleShiftAndBurstType_EDCH__burstType__type2__midambleAllocationMode *)0)->present),
	asn_MAP_midambleAllocationMode_tag2el_12,
	3,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_midambleAllocationMode_12 = {
	"midambleAllocationMode",
	"midambleAllocationMode",
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
	&asn_PER_type_midambleAllocationMode_constr_12,
	asn_MBR_midambleAllocationMode_12,
	3,	/* Elements count */
	&asn_SPC_midambleAllocationMode_specs_12	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_type2_10[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2, midambleConfigurationBurstType2),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleConfigurationBurstType2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleConfigurationBurstType2"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2, midambleAllocationMode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_midambleAllocationMode_12,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleAllocationMode"
		},
};
static ber_tlv_tag_t asn_DEF_type2_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_type2_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* midambleConfigurationBurstType2 at 9601 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* midambleAllocationMode at 9603 */
};
static asn_SEQUENCE_specifics_t asn_SPC_type2_specs_10 = {
	sizeof(struct MidambleShiftAndBurstType_EDCH__burstType__type2),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType__type2, _asn_ctx),
	asn_MAP_type2_tag2el_10,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_type2_10 = {
	"type2",
	"type2",
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
	asn_DEF_type2_tags_10,
	sizeof(asn_DEF_type2_tags_10)
		/sizeof(asn_DEF_type2_tags_10[0]) - 1, /* 1 */
	asn_DEF_type2_tags_10,	/* Same as above */
	sizeof(asn_DEF_type2_tags_10)
		/sizeof(asn_DEF_type2_tags_10[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_type2_10,
	2,	/* Elements count */
	&asn_SPC_type2_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_burstType_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType, choice.type1),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_type1_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"type1"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH__burstType, choice.type2),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_type2_10,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"type2"
		},
};
static asn_TYPE_tag2member_t asn_MAP_burstType_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* type1 at 9591 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* type2 at 9601 */
};
static asn_CHOICE_specifics_t asn_SPC_burstType_specs_2 = {
	sizeof(struct MidambleShiftAndBurstType_EDCH__burstType),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType, _asn_ctx),
	offsetof(struct MidambleShiftAndBurstType_EDCH__burstType, present),
	sizeof(((struct MidambleShiftAndBurstType_EDCH__burstType *)0)->present),
	asn_MAP_burstType_tag2el_2,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_burstType_2 = {
	"burstType",
	"burstType",
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
	&asn_PER_type_burstType_constr_2,
	asn_MBR_burstType_2,
	2,	/* Elements count */
	&asn_SPC_burstType_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_MidambleShiftAndBurstType_EDCH_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MidambleShiftAndBurstType_EDCH, burstType),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_burstType_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"burstType"
		},
};
static ber_tlv_tag_t asn_DEF_MidambleShiftAndBurstType_EDCH_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_MidambleShiftAndBurstType_EDCH_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* burstType at 9599 */
};
static asn_SEQUENCE_specifics_t asn_SPC_MidambleShiftAndBurstType_EDCH_specs_1 = {
	sizeof(struct MidambleShiftAndBurstType_EDCH),
	offsetof(struct MidambleShiftAndBurstType_EDCH, _asn_ctx),
	asn_MAP_MidambleShiftAndBurstType_EDCH_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_MidambleShiftAndBurstType_EDCH = {
	"MidambleShiftAndBurstType-EDCH",
	"MidambleShiftAndBurstType-EDCH",
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
	asn_DEF_MidambleShiftAndBurstType_EDCH_tags_1,
	sizeof(asn_DEF_MidambleShiftAndBurstType_EDCH_tags_1)
		/sizeof(asn_DEF_MidambleShiftAndBurstType_EDCH_tags_1[0]), /* 1 */
	asn_DEF_MidambleShiftAndBurstType_EDCH_tags_1,	/* Same as above */
	sizeof(asn_DEF_MidambleShiftAndBurstType_EDCH_tags_1)
		/sizeof(asn_DEF_MidambleShiftAndBurstType_EDCH_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_MidambleShiftAndBurstType_EDCH_1,
	1,	/* Elements count */
	&asn_SPC_MidambleShiftAndBurstType_EDCH_specs_1	/* Additional specs */
};

