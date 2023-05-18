/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "E-PUCH-Info-MulticarrierEDCH-TDD128.h"

static int
memb_e_PUCH_TS_ConfigurationList_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
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
	
	if((size >= 1 && size <= 5)) {
		/* Perform validation of the inner elements */
		return td->check_constraints(td, sptr, ctfailcb, app_key);
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_type_e_PUCH_TS_ConfigurationList_constr_2 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  5 }	/* (SIZE(1..5)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_e_PUCH_TS_ConfigurationList_constr_2 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  5 }	/* (SIZE(1..5)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_e_PUCH_TS_ConfigurationList_2[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_E_PUCH_TS_Slots_LCR,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_e_PUCH_TS_ConfigurationList_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_e_PUCH_TS_ConfigurationList_specs_2 = {
	sizeof(struct E_PUCH_Info_MulticarrierEDCH_TDD128__e_PUCH_TS_ConfigurationList),
	offsetof(struct E_PUCH_Info_MulticarrierEDCH_TDD128__e_PUCH_TS_ConfigurationList, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_e_PUCH_TS_ConfigurationList_2 = {
	"e-PUCH-TS-ConfigurationList",
	"e-PUCH-TS-ConfigurationList",
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
	asn_DEF_e_PUCH_TS_ConfigurationList_tags_2,
	sizeof(asn_DEF_e_PUCH_TS_ConfigurationList_tags_2)
		/sizeof(asn_DEF_e_PUCH_TS_ConfigurationList_tags_2[0]) - 1, /* 1 */
	asn_DEF_e_PUCH_TS_ConfigurationList_tags_2,	/* Same as above */
	sizeof(asn_DEF_e_PUCH_TS_ConfigurationList_tags_2)
		/sizeof(asn_DEF_e_PUCH_TS_ConfigurationList_tags_2[0]), /* 2 */
	&asn_PER_type_e_PUCH_TS_ConfigurationList_constr_2,
	asn_MBR_e_PUCH_TS_ConfigurationList_2,
	1,	/* Single element */
	&asn_SPC_e_PUCH_TS_ConfigurationList_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_E_PUCH_Info_MulticarrierEDCH_TDD128_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E_PUCH_Info_MulticarrierEDCH_TDD128, e_PUCH_TS_ConfigurationList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_e_PUCH_TS_ConfigurationList_2,
		memb_e_PUCH_TS_ConfigurationList_constraint_1,
		&asn_PER_memb_e_PUCH_TS_ConfigurationList_constr_2,
		0,
		"e-PUCH-TS-ConfigurationList"
		},
};
static ber_tlv_tag_t asn_DEF_E_PUCH_Info_MulticarrierEDCH_TDD128_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_E_PUCH_Info_MulticarrierEDCH_TDD128_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* e-PUCH-TS-ConfigurationList at 8536 */
};
static asn_SEQUENCE_specifics_t asn_SPC_E_PUCH_Info_MulticarrierEDCH_TDD128_specs_1 = {
	sizeof(struct E_PUCH_Info_MulticarrierEDCH_TDD128),
	offsetof(struct E_PUCH_Info_MulticarrierEDCH_TDD128, _asn_ctx),
	asn_MAP_E_PUCH_Info_MulticarrierEDCH_TDD128_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_E_PUCH_Info_MulticarrierEDCH_TDD128 = {
	"E-PUCH-Info-MulticarrierEDCH-TDD128",
	"E-PUCH-Info-MulticarrierEDCH-TDD128",
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
	asn_DEF_E_PUCH_Info_MulticarrierEDCH_TDD128_tags_1,
	sizeof(asn_DEF_E_PUCH_Info_MulticarrierEDCH_TDD128_tags_1)
		/sizeof(asn_DEF_E_PUCH_Info_MulticarrierEDCH_TDD128_tags_1[0]), /* 1 */
	asn_DEF_E_PUCH_Info_MulticarrierEDCH_TDD128_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_PUCH_Info_MulticarrierEDCH_TDD128_tags_1)
		/sizeof(asn_DEF_E_PUCH_Info_MulticarrierEDCH_TDD128_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_E_PUCH_Info_MulticarrierEDCH_TDD128_1,
	1,	/* Elements count */
	&asn_SPC_E_PUCH_Info_MulticarrierEDCH_TDD128_specs_1	/* Additional specs */
};

