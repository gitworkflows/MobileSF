/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "DL-TS-ChannelisationCodesShort-VHCR.h"

static int
memb_bitmap_constraint_2(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 32)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_bitmap_constr_6 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  32,  32 }	/* (SIZE(32..32)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_codesRepresentation_constr_2 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_consecutive_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation__consecutive, firstChannelisationCode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_TS_ChannelisationCode_VHCR,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"firstChannelisationCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation__consecutive, lastChannelisationCode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_TS_ChannelisationCode_VHCR,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"lastChannelisationCode"
		},
};
static ber_tlv_tag_t asn_DEF_consecutive_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_consecutive_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* firstChannelisationCode at 7732 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* lastChannelisationCode at 7734 */
};
static asn_SEQUENCE_specifics_t asn_SPC_consecutive_specs_3 = {
	sizeof(struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation__consecutive),
	offsetof(struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation__consecutive, _asn_ctx),
	asn_MAP_consecutive_tag2el_3,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_consecutive_3 = {
	"consecutive",
	"consecutive",
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
	asn_DEF_consecutive_tags_3,
	sizeof(asn_DEF_consecutive_tags_3)
		/sizeof(asn_DEF_consecutive_tags_3[0]) - 1, /* 1 */
	asn_DEF_consecutive_tags_3,	/* Same as above */
	sizeof(asn_DEF_consecutive_tags_3)
		/sizeof(asn_DEF_consecutive_tags_3[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_consecutive_3,
	2,	/* Elements count */
	&asn_SPC_consecutive_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_codesRepresentation_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation, choice.consecutive),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_consecutive_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"consecutive"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation, choice.bitmap),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		memb_bitmap_constraint_2,
		&asn_PER_memb_bitmap_constr_6,
		0,
		"bitmap"
		},
};
static asn_TYPE_tag2member_t asn_MAP_codesRepresentation_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* consecutive at 7732 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* bitmap at 7736 */
};
static asn_CHOICE_specifics_t asn_SPC_codesRepresentation_specs_2 = {
	sizeof(struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation),
	offsetof(struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation, _asn_ctx),
	offsetof(struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation, present),
	sizeof(((struct DL_TS_ChannelisationCodesShort_VHCR__codesRepresentation *)0)->present),
	asn_MAP_codesRepresentation_tag2el_2,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_codesRepresentation_2 = {
	"codesRepresentation",
	"codesRepresentation",
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
	&asn_PER_type_codesRepresentation_constr_2,
	asn_MBR_codesRepresentation_2,
	2,	/* Elements count */
	&asn_SPC_codesRepresentation_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_DL_TS_ChannelisationCodesShort_VHCR_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TS_ChannelisationCodesShort_VHCR, codesRepresentation),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_codesRepresentation_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"codesRepresentation"
		},
};
static ber_tlv_tag_t asn_DEF_DL_TS_ChannelisationCodesShort_VHCR_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_DL_TS_ChannelisationCodesShort_VHCR_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* codesRepresentation at 7734 */
};
static asn_SEQUENCE_specifics_t asn_SPC_DL_TS_ChannelisationCodesShort_VHCR_specs_1 = {
	sizeof(struct DL_TS_ChannelisationCodesShort_VHCR),
	offsetof(struct DL_TS_ChannelisationCodesShort_VHCR, _asn_ctx),
	asn_MAP_DL_TS_ChannelisationCodesShort_VHCR_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_DL_TS_ChannelisationCodesShort_VHCR = {
	"DL-TS-ChannelisationCodesShort-VHCR",
	"DL-TS-ChannelisationCodesShort-VHCR",
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
	asn_DEF_DL_TS_ChannelisationCodesShort_VHCR_tags_1,
	sizeof(asn_DEF_DL_TS_ChannelisationCodesShort_VHCR_tags_1)
		/sizeof(asn_DEF_DL_TS_ChannelisationCodesShort_VHCR_tags_1[0]), /* 1 */
	asn_DEF_DL_TS_ChannelisationCodesShort_VHCR_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_TS_ChannelisationCodesShort_VHCR_tags_1)
		/sizeof(asn_DEF_DL_TS_ChannelisationCodesShort_VHCR_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_DL_TS_ChannelisationCodesShort_VHCR_1,
	1,	/* Elements count */
	&asn_SPC_DL_TS_ChannelisationCodesShort_VHCR_specs_1	/* Additional specs */
};

