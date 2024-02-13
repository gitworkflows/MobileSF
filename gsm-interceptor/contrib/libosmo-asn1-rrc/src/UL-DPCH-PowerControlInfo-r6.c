/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UL-DPCH-PowerControlInfo-r6.h"

static asn_per_constraints_t asn_PER_type_tddOption_constr_16 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_ul_OL_PC_Signalling_constr_13 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_UL_DPCH_PowerControlInfo_r6_constr_1 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__fdd, dpcch_PowerOffset),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DPCCH_PowerOffset,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dpcch-PowerOffset"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__fdd, pc_Preamble),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PC_Preamble,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pc-Preamble"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__fdd, sRB_delay),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SRB_delay,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sRB-delay"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__fdd, powerControlAlgorithm),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_PowerControlAlgorithm,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"powerControlAlgorithm"
		},
	{ ATF_POINTER, 3, offsetof(struct UL_DPCH_PowerControlInfo_r6__fdd, deltaACK),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DeltaACK,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"deltaACK"
		},
	{ ATF_POINTER, 2, offsetof(struct UL_DPCH_PowerControlInfo_r6__fdd, deltaNACK),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DeltaNACK,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"deltaNACK"
		},
	{ ATF_POINTER, 1, offsetof(struct UL_DPCH_PowerControlInfo_r6__fdd, ack_NACK_repetition_factor),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ACK_NACK_repetitionFactor,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ack-NACK-repetition-factor"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__fdd, harq_Preamble_Mode),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HARQ_Preamble_Mode,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"harq-Preamble-Mode"
		},
};
static int asn_MAP_fdd_oms_2[] = { 4, 5, 6 };
static ber_tlv_tag_t asn_DEF_fdd_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dpcch-PowerOffset at 12360 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* pc-Preamble at 12361 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* sRB-delay at 12362 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* powerControlAlgorithm at 12364 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* deltaACK at 12365 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* deltaNACK at 12366 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* ack-NACK-repetition-factor at 12367 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 } /* harq-Preamble-Mode at 12369 */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_2 = {
	sizeof(struct UL_DPCH_PowerControlInfo_r6__fdd),
	offsetof(struct UL_DPCH_PowerControlInfo_r6__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_2,
	8,	/* Count of tags in the map */
	asn_MAP_fdd_oms_2,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_2 = {
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
	asn_DEF_fdd_tags_2,
	sizeof(asn_DEF_fdd_tags_2)
		/sizeof(asn_DEF_fdd_tags_2[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_2,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_2)
		/sizeof(asn_DEF_fdd_tags_2[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_fdd_2,
	8,	/* Elements count */
	&asn_SPC_fdd_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd384_17[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd384, individualTS_InterferenceList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IndividualTS_InterferenceList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"individualTS-InterferenceList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd384, dpch_ConstantValue),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ConstantValue,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dpch-ConstantValue"
		},
};
static ber_tlv_tag_t asn_DEF_tdd384_tags_17[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd384_tag2el_17[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* individualTS-InterferenceList at 12379 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dpch-ConstantValue at 12381 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd384_specs_17 = {
	sizeof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd384),
	offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd384, _asn_ctx),
	asn_MAP_tdd384_tag2el_17,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd384_17 = {
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
	asn_DEF_tdd384_tags_17,
	sizeof(asn_DEF_tdd384_tags_17)
		/sizeof(asn_DEF_tdd384_tags_17[0]) - 1, /* 1 */
	asn_DEF_tdd384_tags_17,	/* Same as above */
	sizeof(asn_DEF_tdd384_tags_17)
		/sizeof(asn_DEF_tdd384_tags_17[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd384_17,
	2,	/* Elements count */
	&asn_SPC_tdd384_specs_17	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd128_20[] = {
	{ ATF_POINTER, 1, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd128, beaconPLEst),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BEACON_PL_Est,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"beaconPLEst"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd128, tpc_StepSize),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TPC_StepSizeTDD,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tpc-StepSize"
		},
};
static int asn_MAP_tdd128_oms_20[] = { 0 };
static ber_tlv_tag_t asn_DEF_tdd128_tags_20[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd128_tag2el_20[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* beaconPLEst at 12383 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tpc-StepSize at 12385 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd128_specs_20 = {
	sizeof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd128),
	offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd128, _asn_ctx),
	asn_MAP_tdd128_tag2el_20,
	2,	/* Count of tags in the map */
	asn_MAP_tdd128_oms_20,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd128_20 = {
	"tdd128",
	"tdd128",
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
	asn_DEF_tdd128_tags_20,
	sizeof(asn_DEF_tdd128_tags_20)
		/sizeof(asn_DEF_tdd128_tags_20[0]) - 1, /* 1 */
	asn_DEF_tdd128_tags_20,	/* Same as above */
	sizeof(asn_DEF_tdd128_tags_20)
		/sizeof(asn_DEF_tdd128_tags_20[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd128_20,
	2,	/* Elements count */
	&asn_SPC_tdd128_specs_20	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tddOption_16[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption, choice.tdd384),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_tdd384_17,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd384"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption, choice.tdd128),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd128_20,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd128"
		},
};
static asn_TYPE_tag2member_t asn_MAP_tddOption_tag2el_16[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tdd384 at 12379 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd128 at 12383 */
};
static asn_CHOICE_specifics_t asn_SPC_tddOption_specs_16 = {
	sizeof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption),
	offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption, _asn_ctx),
	offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption, present),
	sizeof(((struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption *)0)->present),
	asn_MAP_tddOption_tag2el_16,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tddOption_16 = {
	"tddOption",
	"tddOption",
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
	&asn_PER_type_tddOption_constr_16,
	asn_MBR_tddOption_16,
	2,	/* Elements count */
	&asn_SPC_tddOption_specs_16	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_individuallySignalled_15[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled, tddOption),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_tddOption_16,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tddOption"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled, primaryCCPCH_TX_Power),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCCPCH_TX_Power,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"primaryCCPCH-TX-Power"
		},
};
static ber_tlv_tag_t asn_DEF_individuallySignalled_tags_15[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_individuallySignalled_tag2el_15[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tddOption at 12381 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* primaryCCPCH-TX-Power at 12388 */
};
static asn_SEQUENCE_specifics_t asn_SPC_individuallySignalled_specs_15 = {
	sizeof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled),
	offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling__individuallySignalled, _asn_ctx),
	asn_MAP_individuallySignalled_tag2el_15,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_individuallySignalled_15 = {
	"individuallySignalled",
	"individuallySignalled",
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
	asn_DEF_individuallySignalled_tags_15,
	sizeof(asn_DEF_individuallySignalled_tags_15)
		/sizeof(asn_DEF_individuallySignalled_tags_15[0]) - 1, /* 1 */
	asn_DEF_individuallySignalled_tags_15,	/* Same as above */
	sizeof(asn_DEF_individuallySignalled_tags_15)
		/sizeof(asn_DEF_individuallySignalled_tags_15[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_individuallySignalled_15,
	2,	/* Elements count */
	&asn_SPC_individuallySignalled_specs_15	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_ul_OL_PC_Signalling_13[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling, choice.broadcast_UL_OL_PC_info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"broadcast-UL-OL-PC-info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling, choice.individuallySignalled),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_individuallySignalled_15,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"individuallySignalled"
		},
};
static asn_TYPE_tag2member_t asn_MAP_ul_OL_PC_Signalling_tag2el_13[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* broadcast-UL-OL-PC-info at 12375 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* individuallySignalled at 12386 */
};
static asn_CHOICE_specifics_t asn_SPC_ul_OL_PC_Signalling_specs_13 = {
	sizeof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling),
	offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling, _asn_ctx),
	offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling, present),
	sizeof(((struct UL_DPCH_PowerControlInfo_r6__tdd__ul_OL_PC_Signalling *)0)->present),
	asn_MAP_ul_OL_PC_Signalling_tag2el_13,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ul_OL_PC_Signalling_13 = {
	"ul-OL-PC-Signalling",
	"ul-OL-PC-Signalling",
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
	&asn_PER_type_ul_OL_PC_Signalling_constr_13,
	asn_MBR_ul_OL_PC_Signalling_13,
	2,	/* Elements count */
	&asn_SPC_ul_OL_PC_Signalling_specs_13	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_11[] = {
	{ ATF_POINTER, 1, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd, ul_TargetSIR),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_TargetSIR,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ul-TargetSIR"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd, ul_OL_PC_Signalling),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ul_OL_PC_Signalling_13,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ul-OL-PC-Signalling"
		},
};
static int asn_MAP_tdd_oms_11[] = { 0 };
static ber_tlv_tag_t asn_DEF_tdd_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_11[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ul-TargetSIR at 12373 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ul-OL-PC-Signalling at 12375 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_11 = {
	sizeof(struct UL_DPCH_PowerControlInfo_r6__tdd),
	offsetof(struct UL_DPCH_PowerControlInfo_r6__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_11,
	2,	/* Count of tags in the map */
	asn_MAP_tdd_oms_11,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_11 = {
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
	asn_DEF_tdd_tags_11,
	sizeof(asn_DEF_tdd_tags_11)
		/sizeof(asn_DEF_tdd_tags_11[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_11,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_11)
		/sizeof(asn_DEF_tdd_tags_11[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd_11,
	2,	/* Elements count */
	&asn_SPC_tdd_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_UL_DPCH_PowerControlInfo_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_DPCH_PowerControlInfo_r6, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_11,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd"
		},
};
static asn_TYPE_tag2member_t asn_MAP_UL_DPCH_PowerControlInfo_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd at 12360 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd at 12373 */
};
static asn_CHOICE_specifics_t asn_SPC_UL_DPCH_PowerControlInfo_r6_specs_1 = {
	sizeof(struct UL_DPCH_PowerControlInfo_r6),
	offsetof(struct UL_DPCH_PowerControlInfo_r6, _asn_ctx),
	offsetof(struct UL_DPCH_PowerControlInfo_r6, present),
	sizeof(((struct UL_DPCH_PowerControlInfo_r6 *)0)->present),
	asn_MAP_UL_DPCH_PowerControlInfo_r6_tag2el_1,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_UL_DPCH_PowerControlInfo_r6 = {
	"UL-DPCH-PowerControlInfo-r6",
	"UL-DPCH-PowerControlInfo-r6",
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
	&asn_PER_type_UL_DPCH_PowerControlInfo_r6_constr_1,
	asn_MBR_UL_DPCH_PowerControlInfo_r6_1,
	2,	/* Elements count */
	&asn_SPC_UL_DPCH_PowerControlInfo_r6_specs_1	/* Additional specs */
};

