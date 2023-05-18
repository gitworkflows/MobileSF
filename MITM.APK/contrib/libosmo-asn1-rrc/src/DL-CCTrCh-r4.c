/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "DL-CCTrCh-r4.h"

static asn_per_constraints_t asn_PER_type_tddOption_constr_5 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static int asn_DFL_2_set_1(int set_value, void **sptr) {
	TFCS_IdentityPlain_t *st = *sptr;
	
	if(!st) {
		if(!set_value) return -1;	/* Not a default value */
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	if(set_value) {
		/* Install default value 1 */
		*st = 1;
		return 0;
	} else {
		/* Test default value 1 */
		return (*st == 1);
	}
}
static asn_TYPE_member_t asn_MBR_tdd384_6[] = {
	{ ATF_POINTER, 1, offsetof(struct DL_CCTrCh_r4__tddOption__tdd384, dl_CCTrCH_TimeslotsCodes),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DownlinkTimeslotsCodes,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-CCTrCH-TimeslotsCodes"
		},
};
static int asn_MAP_tdd384_oms_6[] = { 0 };
static ber_tlv_tag_t asn_DEF_tdd384_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd384_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* dl-CCTrCH-TimeslotsCodes at 6633 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd384_specs_6 = {
	sizeof(struct DL_CCTrCh_r4__tddOption__tdd384),
	offsetof(struct DL_CCTrCh_r4__tddOption__tdd384, _asn_ctx),
	asn_MAP_tdd384_tag2el_6,
	1,	/* Count of tags in the map */
	asn_MAP_tdd384_oms_6,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd384_6 = {
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
	asn_DEF_tdd384_tags_6,
	sizeof(asn_DEF_tdd384_tags_6)
		/sizeof(asn_DEF_tdd384_tags_6[0]) - 1, /* 1 */
	asn_DEF_tdd384_tags_6,	/* Same as above */
	sizeof(asn_DEF_tdd384_tags_6)
		/sizeof(asn_DEF_tdd384_tags_6[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd384_6,
	1,	/* Elements count */
	&asn_SPC_tdd384_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd128_8[] = {
	{ ATF_POINTER, 1, offsetof(struct DL_CCTrCh_r4__tddOption__tdd128, dl_CCTrCH_TimeslotsCodes),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DownlinkTimeslotsCodes_LCR_r4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-CCTrCH-TimeslotsCodes"
		},
};
static int asn_MAP_tdd128_oms_8[] = { 0 };
static ber_tlv_tag_t asn_DEF_tdd128_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd128_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* dl-CCTrCH-TimeslotsCodes at 6636 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd128_specs_8 = {
	sizeof(struct DL_CCTrCh_r4__tddOption__tdd128),
	offsetof(struct DL_CCTrCh_r4__tddOption__tdd128, _asn_ctx),
	asn_MAP_tdd128_tag2el_8,
	1,	/* Count of tags in the map */
	asn_MAP_tdd128_oms_8,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd128_8 = {
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
	asn_DEF_tdd128_tags_8,
	sizeof(asn_DEF_tdd128_tags_8)
		/sizeof(asn_DEF_tdd128_tags_8[0]) - 1, /* 1 */
	asn_DEF_tdd128_tags_8,	/* Same as above */
	sizeof(asn_DEF_tdd128_tags_8)
		/sizeof(asn_DEF_tdd128_tags_8[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd128_8,
	1,	/* Elements count */
	&asn_SPC_tdd128_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tddOption_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CCTrCh_r4__tddOption, choice.tdd384),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_tdd384_6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd384"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CCTrCh_r4__tddOption, choice.tdd128),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd128_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd128"
		},
};
static asn_TYPE_tag2member_t asn_MAP_tddOption_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tdd384 at 6633 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd128 at 6636 */
};
static asn_CHOICE_specifics_t asn_SPC_tddOption_specs_5 = {
	sizeof(struct DL_CCTrCh_r4__tddOption),
	offsetof(struct DL_CCTrCh_r4__tddOption, _asn_ctx),
	offsetof(struct DL_CCTrCh_r4__tddOption, present),
	sizeof(((struct DL_CCTrCh_r4__tddOption *)0)->present),
	asn_MAP_tddOption_tag2el_5,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tddOption_5 = {
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
	&asn_PER_type_tddOption_constr_5,
	asn_MBR_tddOption_5,
	2,	/* Elements count */
	&asn_SPC_tddOption_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_DL_CCTrCh_r4_1[] = {
	{ ATF_POINTER, 1, offsetof(struct DL_CCTrCh_r4, tfcs_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TFCS_IdentityPlain,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		asn_DFL_2_set_1,	/* DEFAULT 1 */
		"tfcs-ID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CCTrCh_r4, timeInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_CCTrCh_r4, commonTimeslotInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CommonTimeslotInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"commonTimeslotInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CCTrCh_r4, tddOption),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_tddOption_5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tddOption"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_CCTrCh_r4, ul_CCTrChTPCList),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_CCTrChTPCList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ul-CCTrChTPCList"
		},
};
static int asn_MAP_DL_CCTrCh_r4_oms_1[] = { 0, 2, 4 };
static ber_tlv_tag_t asn_DEF_DL_CCTrCh_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_DL_CCTrCh_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tfcs-ID at 6628 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* timeInfo at 6629 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* commonTimeslotInfo at 6630 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* tddOption at 6634 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* ul-CCTrChTPCList at 6639 */
};
static asn_SEQUENCE_specifics_t asn_SPC_DL_CCTrCh_r4_specs_1 = {
	sizeof(struct DL_CCTrCh_r4),
	offsetof(struct DL_CCTrCh_r4, _asn_ctx),
	asn_MAP_DL_CCTrCh_r4_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_DL_CCTrCh_r4_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_DL_CCTrCh_r4 = {
	"DL-CCTrCh-r4",
	"DL-CCTrCh-r4",
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
	asn_DEF_DL_CCTrCh_r4_tags_1,
	sizeof(asn_DEF_DL_CCTrCh_r4_tags_1)
		/sizeof(asn_DEF_DL_CCTrCh_r4_tags_1[0]), /* 1 */
	asn_DEF_DL_CCTrCh_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_CCTrCh_r4_tags_1)
		/sizeof(asn_DEF_DL_CCTrCh_r4_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_DL_CCTrCh_r4_1,
	5,	/* Elements count */
	&asn_SPC_DL_CCTrCh_r4_specs_1	/* Additional specs */
};

