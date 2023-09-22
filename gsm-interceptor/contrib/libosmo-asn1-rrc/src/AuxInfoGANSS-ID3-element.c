/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "AuxInfoGANSS-ID3-element.h"

static int
memb_svID_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 63)) {
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
memb_signalsAvailable_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
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
	
	if((size == 8)) {
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
memb_channelNumber_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -7 && value <= 13)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_svID_constr_2 = {
	{ APC_CONSTRAINED,	 6,  6,  0,  63 }	/* (0..63) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_signalsAvailable_constr_3 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  8,  8 }	/* (SIZE(8..8)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_channelNumber_constr_4 = {
	{ APC_CONSTRAINED,	 5,  5, -7,  13 }	/* (-7..13) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_AuxInfoGANSS_ID3_element_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AuxInfoGANSS_ID3_element, svID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_svID_constraint_1,
		&asn_PER_memb_svID_constr_2,
		0,
		"svID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AuxInfoGANSS_ID3_element, signalsAvailable),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		memb_signalsAvailable_constraint_1,
		&asn_PER_memb_signalsAvailable_constr_3,
		0,
		"signalsAvailable"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AuxInfoGANSS_ID3_element, channelNumber),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_channelNumber_constraint_1,
		&asn_PER_memb_channelNumber_constr_4,
		0,
		"channelNumber"
		},
};
static ber_tlv_tag_t asn_DEF_AuxInfoGANSS_ID3_element_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_AuxInfoGANSS_ID3_element_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* svID at 12984 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* signalsAvailable at 12985 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* channelNumber at 12986 */
};
static asn_SEQUENCE_specifics_t asn_SPC_AuxInfoGANSS_ID3_element_specs_1 = {
	sizeof(struct AuxInfoGANSS_ID3_element),
	offsetof(struct AuxInfoGANSS_ID3_element, _asn_ctx),
	asn_MAP_AuxInfoGANSS_ID3_element_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_AuxInfoGANSS_ID3_element = {
	"AuxInfoGANSS-ID3-element",
	"AuxInfoGANSS-ID3-element",
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
	asn_DEF_AuxInfoGANSS_ID3_element_tags_1,
	sizeof(asn_DEF_AuxInfoGANSS_ID3_element_tags_1)
		/sizeof(asn_DEF_AuxInfoGANSS_ID3_element_tags_1[0]), /* 1 */
	asn_DEF_AuxInfoGANSS_ID3_element_tags_1,	/* Same as above */
	sizeof(asn_DEF_AuxInfoGANSS_ID3_element_tags_1)
		/sizeof(asn_DEF_AuxInfoGANSS_ID3_element_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_AuxInfoGANSS_ID3_element_1,
	3,	/* Elements count */
	&asn_SPC_AuxInfoGANSS_ID3_element_specs_1	/* Additional specs */
};

