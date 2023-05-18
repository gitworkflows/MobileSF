/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "HS-SCCH-Info.h"

static int
memb_hS_SCCHChannelisationCodeInfo_constraint_3(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 4)) {
		/* Perform validation of the inner elements */
		return td->check_constraints(td, sptr, ctfailcb, app_key);
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_nack_ack_power_offset_constraint_8(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -7 && value <= 8)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_hS_SCCH_SetConfiguration_constraint_8(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 4)) {
		/* Perform validation of the inner elements */
		return td->check_constraints(td, sptr, ctfailcb, app_key);
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_tdd128_constraint_7(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 4)) {
		/* Perform validation of the inner elements */
		return td->check_constraints(td, sptr, ctfailcb, app_key);
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_type_hS_SCCHChannelisationCodeInfo_constr_4 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (SIZE(1..4)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_hS_SCCHChannelisationCodeInfo_constr_4 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (SIZE(1..4)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_hS_SCCH_SetConfiguration_constr_11 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (SIZE(1..4)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_nack_ack_power_offset_constr_9 = {
	{ APC_CONSTRAINED,	 4,  4, -7,  8 }	/* (-7..8) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_hS_SCCH_SetConfiguration_constr_11 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (SIZE(1..4)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_tdd128_constr_13 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (SIZE(1..4)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_tdd128_constr_13 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (SIZE(1..4)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_tdd_constr_7 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_2 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_hS_SCCHChannelisationCodeInfo_4[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_HS_SCCH_Codes,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_hS_SCCHChannelisationCodeInfo_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_hS_SCCHChannelisationCodeInfo_specs_4 = {
	sizeof(struct HS_SCCH_Info__modeSpecificInfo__fdd__hS_SCCHChannelisationCodeInfo),
	offsetof(struct HS_SCCH_Info__modeSpecificInfo__fdd__hS_SCCHChannelisationCodeInfo, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_hS_SCCHChannelisationCodeInfo_4 = {
	"hS-SCCHChannelisationCodeInfo",
	"hS-SCCHChannelisationCodeInfo",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	SEQUENCE_OF_decode_uper,
	SEQUENCE_OF_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_hS_SCCHChannelisationCodeInfo_tags_4,
	sizeof(asn_DEF_hS_SCCHChannelisationCodeInfo_tags_4)
		/sizeof(asn_DEF_hS_SCCHChannelisationCodeInfo_tags_4[0]) - 1, /* 1 */
	asn_DEF_hS_SCCHChannelisationCodeInfo_tags_4,	/* Same as above */
	sizeof(asn_DEF_hS_SCCHChannelisationCodeInfo_tags_4)
		/sizeof(asn_DEF_hS_SCCHChannelisationCodeInfo_tags_4[0]), /* 2 */
	&asn_PER_type_hS_SCCHChannelisationCodeInfo_constr_4,
	asn_MBR_hS_SCCHChannelisationCodeInfo_4,
	1,	/* Single element */
	&asn_SPC_hS_SCCHChannelisationCodeInfo_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_fdd_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SCCH_Info__modeSpecificInfo__fdd, hS_SCCHChannelisationCodeInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_hS_SCCHChannelisationCodeInfo_4,
		memb_hS_SCCHChannelisationCodeInfo_constraint_3,
		&asn_PER_memb_hS_SCCHChannelisationCodeInfo_constr_4,
		0,
		"hS-SCCHChannelisationCodeInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct HS_SCCH_Info__modeSpecificInfo__fdd, dl_ScramblingCode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SecondaryScramblingCode,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-ScramblingCode"
		},
};
static int asn_MAP_fdd_oms_3[] = { 1 };
static ber_tlv_tag_t asn_DEF_fdd_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* hS-SCCHChannelisationCodeInfo at 8918 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dl-ScramblingCode at 8919 */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_3 = {
	sizeof(struct HS_SCCH_Info__modeSpecificInfo__fdd),
	offsetof(struct HS_SCCH_Info__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_3,
	2,	/* Count of tags in the map */
	asn_MAP_fdd_oms_3,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_3 = {
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
	asn_DEF_fdd_tags_3,
	sizeof(asn_DEF_fdd_tags_3)
		/sizeof(asn_DEF_fdd_tags_3[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_3,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_3)
		/sizeof(asn_DEF_fdd_tags_3[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_fdd_3,
	2,	/* Elements count */
	&asn_SPC_fdd_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_hS_SCCH_SetConfiguration_11[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_HS_SCCH_TDD384,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_hS_SCCH_SetConfiguration_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_hS_SCCH_SetConfiguration_specs_11 = {
	sizeof(struct HS_SCCH_Info__modeSpecificInfo__tdd__tdd384__hS_SCCH_SetConfiguration),
	offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd__tdd384__hS_SCCH_SetConfiguration, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_hS_SCCH_SetConfiguration_11 = {
	"hS-SCCH-SetConfiguration",
	"hS-SCCH-SetConfiguration",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	SEQUENCE_OF_decode_uper,
	SEQUENCE_OF_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_hS_SCCH_SetConfiguration_tags_11,
	sizeof(asn_DEF_hS_SCCH_SetConfiguration_tags_11)
		/sizeof(asn_DEF_hS_SCCH_SetConfiguration_tags_11[0]) - 1, /* 1 */
	asn_DEF_hS_SCCH_SetConfiguration_tags_11,	/* Same as above */
	sizeof(asn_DEF_hS_SCCH_SetConfiguration_tags_11)
		/sizeof(asn_DEF_hS_SCCH_SetConfiguration_tags_11[0]), /* 2 */
	&asn_PER_type_hS_SCCH_SetConfiguration_constr_11,
	asn_MBR_hS_SCCH_SetConfiguration_11,
	1,	/* Single element */
	&asn_SPC_hS_SCCH_SetConfiguration_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd384_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd__tdd384, nack_ack_power_offset),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_nack_ack_power_offset_constraint_8,
		&asn_PER_memb_nack_ack_power_offset_constr_9,
		0,
		"nack-ack-power-offset"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd__tdd384, hs_SICH_PowerControl_Info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HS_SICH_Power_Control_Info_TDD384,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"hs-SICH-PowerControl-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd__tdd384, hS_SCCH_SetConfiguration),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_hS_SCCH_SetConfiguration_11,
		memb_hS_SCCH_SetConfiguration_constraint_8,
		&asn_PER_memb_hS_SCCH_SetConfiguration_constr_11,
		0,
		"hS-SCCH-SetConfiguration"
		},
};
static ber_tlv_tag_t asn_DEF_tdd384_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd384_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* nack-ack-power-offset at 8923 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* hs-SICH-PowerControl-Info at 8924 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* hS-SCCH-SetConfiguration at 8927 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd384_specs_8 = {
	sizeof(struct HS_SCCH_Info__modeSpecificInfo__tdd__tdd384),
	offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd__tdd384, _asn_ctx),
	asn_MAP_tdd384_tag2el_8,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd384_8 = {
	"tdd384",
	"tdd384",
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
	asn_DEF_tdd384_tags_8,
	sizeof(asn_DEF_tdd384_tags_8)
		/sizeof(asn_DEF_tdd384_tags_8[0]) - 1, /* 1 */
	asn_DEF_tdd384_tags_8,	/* Same as above */
	sizeof(asn_DEF_tdd384_tags_8)
		/sizeof(asn_DEF_tdd384_tags_8[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd384_8,
	3,	/* Elements count */
	&asn_SPC_tdd384_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd128_13[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_HS_SCCH_TDD128,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_tdd128_tags_13[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_tdd128_specs_13 = {
	sizeof(struct HS_SCCH_Info__modeSpecificInfo__tdd__tdd128),
	offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd__tdd128, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd128_13 = {
	"tdd128",
	"tdd128",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	SEQUENCE_OF_decode_uper,
	SEQUENCE_OF_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_tdd128_tags_13,
	sizeof(asn_DEF_tdd128_tags_13)
		/sizeof(asn_DEF_tdd128_tags_13[0]) - 1, /* 1 */
	asn_DEF_tdd128_tags_13,	/* Same as above */
	sizeof(asn_DEF_tdd128_tags_13)
		/sizeof(asn_DEF_tdd128_tags_13[0]), /* 2 */
	&asn_PER_type_tdd128_constr_13,
	asn_MBR_tdd128_13,
	1,	/* Single element */
	&asn_SPC_tdd128_specs_13	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_7[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd, choice.tdd384),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_tdd384_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd384"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd, choice.tdd128),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd128_13,
		memb_tdd128_constraint_7,
		&asn_PER_memb_tdd128_constr_13,
		0,
		"tdd128"
		},
};
static asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_7[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tdd384 at 8923 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd128 at 8930 */
};
static asn_CHOICE_specifics_t asn_SPC_tdd_specs_7 = {
	sizeof(struct HS_SCCH_Info__modeSpecificInfo__tdd),
	offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd, _asn_ctx),
	offsetof(struct HS_SCCH_Info__modeSpecificInfo__tdd, present),
	sizeof(((struct HS_SCCH_Info__modeSpecificInfo__tdd *)0)->present),
	asn_MAP_tdd_tag2el_7,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_7 = {
	"tdd",
	"tdd",
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
	&asn_PER_type_tdd_constr_7,
	asn_MBR_tdd_7,
	2,	/* Elements count */
	&asn_SPC_tdd_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SCCH_Info__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SCCH_Info__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_tdd_7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd"
		},
};
static asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd at 8918 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd at 8927 */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_2 = {
	sizeof(struct HS_SCCH_Info__modeSpecificInfo),
	offsetof(struct HS_SCCH_Info__modeSpecificInfo, _asn_ctx),
	offsetof(struct HS_SCCH_Info__modeSpecificInfo, present),
	sizeof(((struct HS_SCCH_Info__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_2,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_2 = {
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
	&asn_PER_type_modeSpecificInfo_constr_2,
	asn_MBR_modeSpecificInfo_2,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_HS_SCCH_Info_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SCCH_Info, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modeSpecificInfo"
		},
};
static ber_tlv_tag_t asn_DEF_HS_SCCH_Info_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_HS_SCCH_Info_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* modeSpecificInfo at 8920 */
};
static asn_SEQUENCE_specifics_t asn_SPC_HS_SCCH_Info_specs_1 = {
	sizeof(struct HS_SCCH_Info),
	offsetof(struct HS_SCCH_Info, _asn_ctx),
	asn_MAP_HS_SCCH_Info_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_HS_SCCH_Info = {
	"HS-SCCH-Info",
	"HS-SCCH-Info",
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
	asn_DEF_HS_SCCH_Info_tags_1,
	sizeof(asn_DEF_HS_SCCH_Info_tags_1)
		/sizeof(asn_DEF_HS_SCCH_Info_tags_1[0]), /* 1 */
	asn_DEF_HS_SCCH_Info_tags_1,	/* Same as above */
	sizeof(asn_DEF_HS_SCCH_Info_tags_1)
		/sizeof(asn_DEF_HS_SCCH_Info_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_HS_SCCH_Info_1,
	1,	/* Elements count */
	&asn_SPC_HS_SCCH_Info_specs_1	/* Additional specs */
};

