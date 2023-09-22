/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "CBS-DRX-Level1Information.h"

static int
memb_ctch_AllocationPeriod_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 256)) {
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
memb_cbs_FrameOffset_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 255)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_ctch_AllocationPeriod_constr_2 = {
	{ APC_CONSTRAINED,	 8,  8,  1,  256 }	/* (1..256) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_cbs_FrameOffset_constr_3 = {
	{ APC_CONSTRAINED,	 8,  8,  0,  255 }	/* (0..255) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_CBS_DRX_Level1Information_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CBS_DRX_Level1Information, ctch_AllocationPeriod),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_ctch_AllocationPeriod_constraint_1,
		&asn_PER_memb_ctch_AllocationPeriod_constr_2,
		0,
		"ctch-AllocationPeriod"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CBS_DRX_Level1Information, cbs_FrameOffset),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_cbs_FrameOffset_constraint_1,
		&asn_PER_memb_cbs_FrameOffset_constr_3,
		0,
		"cbs-FrameOffset"
		},
};
static ber_tlv_tag_t asn_DEF_CBS_DRX_Level1Information_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_CBS_DRX_Level1Information_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ctch-AllocationPeriod at 20067 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* cbs-FrameOffset at 20068 */
};
static asn_SEQUENCE_specifics_t asn_SPC_CBS_DRX_Level1Information_specs_1 = {
	sizeof(struct CBS_DRX_Level1Information),
	offsetof(struct CBS_DRX_Level1Information, _asn_ctx),
	asn_MAP_CBS_DRX_Level1Information_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_CBS_DRX_Level1Information = {
	"CBS-DRX-Level1Information",
	"CBS-DRX-Level1Information",
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
	asn_DEF_CBS_DRX_Level1Information_tags_1,
	sizeof(asn_DEF_CBS_DRX_Level1Information_tags_1)
		/sizeof(asn_DEF_CBS_DRX_Level1Information_tags_1[0]), /* 1 */
	asn_DEF_CBS_DRX_Level1Information_tags_1,	/* Same as above */
	sizeof(asn_DEF_CBS_DRX_Level1Information_tags_1)
		/sizeof(asn_DEF_CBS_DRX_Level1Information_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_CBS_DRX_Level1Information_1,
	2,	/* Elements count */
	&asn_SPC_CBS_DRX_Level1Information_specs_1	/* Additional specs */
};

