/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "HS-SICH-Configuration-TDD128-r6.h"

static int
memb_midambleConfiguration_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 8)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_type_midambleAllocationMode_constr_4 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_midambleConfiguration_constr_8 = {
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (1..8) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_ueSpecificMidamble_6[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD128_r6__midambleAllocationMode__ueSpecificMidamble, midambleShift),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftLong,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleShift"
		},
};
static ber_tlv_tag_t asn_DEF_ueSpecificMidamble_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_ueSpecificMidamble_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* midambleShift at 9172 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ueSpecificMidamble_specs_6 = {
	sizeof(struct HS_SICH_Configuration_TDD128_r6__midambleAllocationMode__ueSpecificMidamble),
	offsetof(struct HS_SICH_Configuration_TDD128_r6__midambleAllocationMode__ueSpecificMidamble, _asn_ctx),
	asn_MAP_ueSpecificMidamble_tag2el_6,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ueSpecificMidamble_6 = {
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
	asn_DEF_ueSpecificMidamble_tags_6,
	sizeof(asn_DEF_ueSpecificMidamble_tags_6)
		/sizeof(asn_DEF_ueSpecificMidamble_tags_6[0]) - 1, /* 1 */
	asn_DEF_ueSpecificMidamble_tags_6,	/* Same as above */
	sizeof(asn_DEF_ueSpecificMidamble_tags_6)
		/sizeof(asn_DEF_ueSpecificMidamble_tags_6[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_ueSpecificMidamble_6,
	1,	/* Elements count */
	&asn_SPC_ueSpecificMidamble_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_midambleAllocationMode_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD128_r6__midambleAllocationMode, choice.defaultMidamble),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"defaultMidamble"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD128_r6__midambleAllocationMode, choice.ueSpecificMidamble),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_ueSpecificMidamble_6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueSpecificMidamble"
		},
};
static asn_TYPE_tag2member_t asn_MAP_midambleAllocationMode_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* defaultMidamble at 9169 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ueSpecificMidamble at 9172 */
};
static asn_CHOICE_specifics_t asn_SPC_midambleAllocationMode_specs_4 = {
	sizeof(struct HS_SICH_Configuration_TDD128_r6__midambleAllocationMode),
	offsetof(struct HS_SICH_Configuration_TDD128_r6__midambleAllocationMode, _asn_ctx),
	offsetof(struct HS_SICH_Configuration_TDD128_r6__midambleAllocationMode, present),
	sizeof(((struct HS_SICH_Configuration_TDD128_r6__midambleAllocationMode *)0)->present),
	asn_MAP_midambleAllocationMode_tag2el_4,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_midambleAllocationMode_4 = {
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
	&asn_PER_type_midambleAllocationMode_constr_4,
	asn_MBR_midambleAllocationMode_4,
	2,	/* Elements count */
	&asn_SPC_midambleAllocationMode_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_HS_SICH_Configuration_TDD128_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD128_r6, timeslotNumber),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber_LCR_r4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeslotNumber"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD128_r6, channelisationCode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HS_ChannelisationCode_LCR,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"channelisationCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD128_r6, midambleAllocationMode),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_midambleAllocationMode_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleAllocationMode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD128_r6, midambleConfiguration),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_midambleConfiguration_constraint_1,
		&asn_PER_memb_midambleConfiguration_constr_8,
		0,
		"midambleConfiguration"
		},
};
static ber_tlv_tag_t asn_DEF_HS_SICH_Configuration_TDD128_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_HS_SICH_Configuration_TDD128_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeslotNumber at 9166 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* channelisationCode at 9167 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* midambleAllocationMode at 9169 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* midambleConfiguration at 9175 */
};
static asn_SEQUENCE_specifics_t asn_SPC_HS_SICH_Configuration_TDD128_r6_specs_1 = {
	sizeof(struct HS_SICH_Configuration_TDD128_r6),
	offsetof(struct HS_SICH_Configuration_TDD128_r6, _asn_ctx),
	asn_MAP_HS_SICH_Configuration_TDD128_r6_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_HS_SICH_Configuration_TDD128_r6 = {
	"HS-SICH-Configuration-TDD128-r6",
	"HS-SICH-Configuration-TDD128-r6",
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
	asn_DEF_HS_SICH_Configuration_TDD128_r6_tags_1,
	sizeof(asn_DEF_HS_SICH_Configuration_TDD128_r6_tags_1)
		/sizeof(asn_DEF_HS_SICH_Configuration_TDD128_r6_tags_1[0]), /* 1 */
	asn_DEF_HS_SICH_Configuration_TDD128_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_HS_SICH_Configuration_TDD128_r6_tags_1)
		/sizeof(asn_DEF_HS_SICH_Configuration_TDD128_r6_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_HS_SICH_Configuration_TDD128_r6_1,
	4,	/* Elements count */
	&asn_SPC_HS_SICH_Configuration_TDD128_r6_specs_1	/* Additional specs */
};

