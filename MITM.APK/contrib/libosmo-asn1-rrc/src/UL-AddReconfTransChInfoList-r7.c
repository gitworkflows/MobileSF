/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UL-AddReconfTransChInfoList-r7.h"

static asn_per_constraints_t asn_PER_type_UL_AddReconfTransChInfoList_r7_constr_1 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 5,  5,  1,  32 }	/* (SIZE(1..32)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_UL_AddReconfTransChInfoList_r7_1[] = {
	{ ATF_POINTER, 0, 0,
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_UL_AddReconfTransChInformation_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_UL_AddReconfTransChInfoList_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_UL_AddReconfTransChInfoList_r7_specs_1 = {
	sizeof(struct UL_AddReconfTransChInfoList_r7),
	offsetof(struct UL_AddReconfTransChInfoList_r7, _asn_ctx),
	2,	/* XER encoding is XMLValueList */
};
asn_TYPE_descriptor_t asn_DEF_UL_AddReconfTransChInfoList_r7 = {
	"UL-AddReconfTransChInfoList-r7",
	"UL-AddReconfTransChInfoList-r7",
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
	asn_DEF_UL_AddReconfTransChInfoList_r7_tags_1,
	sizeof(asn_DEF_UL_AddReconfTransChInfoList_r7_tags_1)
		/sizeof(asn_DEF_UL_AddReconfTransChInfoList_r7_tags_1[0]), /* 1 */
	asn_DEF_UL_AddReconfTransChInfoList_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_UL_AddReconfTransChInfoList_r7_tags_1)
		/sizeof(asn_DEF_UL_AddReconfTransChInfoList_r7_tags_1[0]), /* 1 */
	&asn_PER_type_UL_AddReconfTransChInfoList_r7_constr_1,
	asn_MBR_UL_AddReconfTransChInfoList_r7_1,
	1,	/* Single element */
	&asn_SPC_UL_AddReconfTransChInfoList_r7_specs_1	/* Additional specs */
};

