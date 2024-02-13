/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "ReqDataBitAssistance.h"

static int
memb_NativeInteger_constraint_4(asn_TYPE_descriptor_t *td, const void *sptr,
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
memb_ganssDataBitInterval_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 15)) {
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
memb_ganssSatelliteInfo_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
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
	
	if((size >= 1 && size <= 64)) {
		/* Perform validation of the inner elements */
		return td->check_constraints(td, sptr, ctfailcb, app_key);
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_Member_constr_5 = {
	{ APC_CONSTRAINED,	 6,  6,  0,  63 }	/* (0..63) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_ganssSatelliteInfo_constr_4 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 6,  6,  1,  64 }	/* (SIZE(1..64)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_ganssDataBitInterval_constr_3 = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_ganssSatelliteInfo_constr_4 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 6,  6,  1,  64 }	/* (SIZE(1..64)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_ganssSatelliteInfo_4[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_NativeInteger,
		memb_NativeInteger_constraint_4,
		&asn_PER_memb_Member_constr_5,
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_ganssSatelliteInfo_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_ganssSatelliteInfo_specs_4 = {
	sizeof(struct ReqDataBitAssistance__ganssSatelliteInfo),
	offsetof(struct ReqDataBitAssistance__ganssSatelliteInfo, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ganssSatelliteInfo_4 = {
	"ganssSatelliteInfo",
	"ganssSatelliteInfo",
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
	asn_DEF_ganssSatelliteInfo_tags_4,
	sizeof(asn_DEF_ganssSatelliteInfo_tags_4)
		/sizeof(asn_DEF_ganssSatelliteInfo_tags_4[0]) - 1, /* 1 */
	asn_DEF_ganssSatelliteInfo_tags_4,	/* Same as above */
	sizeof(asn_DEF_ganssSatelliteInfo_tags_4)
		/sizeof(asn_DEF_ganssSatelliteInfo_tags_4[0]), /* 2 */
	&asn_PER_type_ganssSatelliteInfo_constr_4,
	asn_MBR_ganssSatelliteInfo_4,
	1,	/* Single element */
	&asn_SPC_ganssSatelliteInfo_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_ReqDataBitAssistance_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ReqDataBitAssistance, ganssSignalID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DGANSS_Sig_Id_Req,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ganssSignalID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ReqDataBitAssistance, ganssDataBitInterval),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_ganssDataBitInterval_constraint_1,
		&asn_PER_memb_ganssDataBitInterval_constr_3,
		0,
		"ganssDataBitInterval"
		},
	{ ATF_POINTER, 1, offsetof(struct ReqDataBitAssistance, ganssSatelliteInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_ganssSatelliteInfo_4,
		memb_ganssSatelliteInfo_constraint_1,
		&asn_PER_memb_ganssSatelliteInfo_constr_4,
		0,
		"ganssSatelliteInfo"
		},
};
static int asn_MAP_ReqDataBitAssistance_oms_1[] = { 2 };
static ber_tlv_tag_t asn_DEF_ReqDataBitAssistance_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_ReqDataBitAssistance_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ganssSignalID at 18036 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ganssDataBitInterval at 18037 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* ganssSatelliteInfo at 18038 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ReqDataBitAssistance_specs_1 = {
	sizeof(struct ReqDataBitAssistance),
	offsetof(struct ReqDataBitAssistance, _asn_ctx),
	asn_MAP_ReqDataBitAssistance_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_ReqDataBitAssistance_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_ReqDataBitAssistance = {
	"ReqDataBitAssistance",
	"ReqDataBitAssistance",
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
	asn_DEF_ReqDataBitAssistance_tags_1,
	sizeof(asn_DEF_ReqDataBitAssistance_tags_1)
		/sizeof(asn_DEF_ReqDataBitAssistance_tags_1[0]), /* 1 */
	asn_DEF_ReqDataBitAssistance_tags_1,	/* Same as above */
	sizeof(asn_DEF_ReqDataBitAssistance_tags_1)
		/sizeof(asn_DEF_ReqDataBitAssistance_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_ReqDataBitAssistance_1,
	3,	/* Elements count */
	&asn_SPC_ReqDataBitAssistance_specs_1	/* Additional specs */
};

