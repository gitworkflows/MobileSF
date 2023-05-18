/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "E-DCH-ReconfigurationInfo-r7.h"

static int
memb_e_DCH_RL_InfoOtherCellList_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
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

static asn_per_constraints_t asn_PER_type_e_DCH_RL_InfoOtherCellList_constr_3 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (SIZE(1..4)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_e_DCH_RL_InfoOtherCellList_constr_3 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (SIZE(1..4)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_e_DCH_RL_InfoOtherCellList_3[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_E_DCH_RL_InfoOtherCell,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_e_DCH_RL_InfoOtherCellList_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_e_DCH_RL_InfoOtherCellList_specs_3 = {
	sizeof(struct E_DCH_ReconfigurationInfo_r7__e_DCH_RL_InfoOtherCellList),
	offsetof(struct E_DCH_ReconfigurationInfo_r7__e_DCH_RL_InfoOtherCellList, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_e_DCH_RL_InfoOtherCellList_3 = {
	"e-DCH-RL-InfoOtherCellList",
	"e-DCH-RL-InfoOtherCellList",
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
	asn_DEF_e_DCH_RL_InfoOtherCellList_tags_3,
	sizeof(asn_DEF_e_DCH_RL_InfoOtherCellList_tags_3)
		/sizeof(asn_DEF_e_DCH_RL_InfoOtherCellList_tags_3[0]) - 1, /* 1 */
	asn_DEF_e_DCH_RL_InfoOtherCellList_tags_3,	/* Same as above */
	sizeof(asn_DEF_e_DCH_RL_InfoOtherCellList_tags_3)
		/sizeof(asn_DEF_e_DCH_RL_InfoOtherCellList_tags_3[0]), /* 2 */
	&asn_PER_type_e_DCH_RL_InfoOtherCellList_constr_3,
	asn_MBR_e_DCH_RL_InfoOtherCellList_3,
	1,	/* Single element */
	&asn_SPC_e_DCH_RL_InfoOtherCellList_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_E_DCH_ReconfigurationInfo_r7_1[] = {
	{ ATF_POINTER, 2, offsetof(struct E_DCH_ReconfigurationInfo_r7, e_DCH_RL_InfoNewServingCell),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DCH_RL_InfoNewServingCell_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-DCH-RL-InfoNewServingCell"
		},
	{ ATF_POINTER, 1, offsetof(struct E_DCH_ReconfigurationInfo_r7, e_DCH_RL_InfoOtherCellList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_e_DCH_RL_InfoOtherCellList_3,
		memb_e_DCH_RL_InfoOtherCellList_constraint_1,
		&asn_PER_memb_e_DCH_RL_InfoOtherCellList_constr_3,
		0,
		"e-DCH-RL-InfoOtherCellList"
		},
};
static int asn_MAP_E_DCH_ReconfigurationInfo_r7_oms_1[] = { 0, 1 };
static ber_tlv_tag_t asn_DEF_E_DCH_ReconfigurationInfo_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_E_DCH_ReconfigurationInfo_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-DCH-RL-InfoNewServingCell at 8167 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* e-DCH-RL-InfoOtherCellList at 8169 */
};
static asn_SEQUENCE_specifics_t asn_SPC_E_DCH_ReconfigurationInfo_r7_specs_1 = {
	sizeof(struct E_DCH_ReconfigurationInfo_r7),
	offsetof(struct E_DCH_ReconfigurationInfo_r7, _asn_ctx),
	asn_MAP_E_DCH_ReconfigurationInfo_r7_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_E_DCH_ReconfigurationInfo_r7_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_E_DCH_ReconfigurationInfo_r7 = {
	"E-DCH-ReconfigurationInfo-r7",
	"E-DCH-ReconfigurationInfo-r7",
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
	asn_DEF_E_DCH_ReconfigurationInfo_r7_tags_1,
	sizeof(asn_DEF_E_DCH_ReconfigurationInfo_r7_tags_1)
		/sizeof(asn_DEF_E_DCH_ReconfigurationInfo_r7_tags_1[0]), /* 1 */
	asn_DEF_E_DCH_ReconfigurationInfo_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_DCH_ReconfigurationInfo_r7_tags_1)
		/sizeof(asn_DEF_E_DCH_ReconfigurationInfo_r7_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_E_DCH_ReconfigurationInfo_r7_1,
	2,	/* Elements count */
	&asn_SPC_E_DCH_ReconfigurationInfo_r7_specs_1	/* Additional specs */
};

