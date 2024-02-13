/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UE-Positioning-GANSS-AssistanceData-va40ext.h"

static asn_TYPE_member_t asn_MBR_UE_Positioning_GANSS_AssistanceData_va40ext_1[] = {
	{ ATF_POINTER, 2, offsetof(struct UE_Positioning_GANSS_AssistanceData_va40ext, ue_positioning_GANSS_ReferenceTime),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_GANSS_ReferenceTime_va40ext,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ue-positioning-GANSS-ReferenceTime"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_Positioning_GANSS_AssistanceData_va40ext, ganssGenericDataList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GANSSGenericDataList_va40ext,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ganssGenericDataList"
		},
};
static int asn_MAP_UE_Positioning_GANSS_AssistanceData_va40ext_oms_1[] = { 0, 1 };
static ber_tlv_tag_t asn_DEF_UE_Positioning_GANSS_AssistanceData_va40ext_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_UE_Positioning_GANSS_AssistanceData_va40ext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ue-positioning-GANSS-ReferenceTime at 18860 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ganssGenericDataList at 18861 */
};
static asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_GANSS_AssistanceData_va40ext_specs_1 = {
	sizeof(struct UE_Positioning_GANSS_AssistanceData_va40ext),
	offsetof(struct UE_Positioning_GANSS_AssistanceData_va40ext, _asn_ctx),
	asn_MAP_UE_Positioning_GANSS_AssistanceData_va40ext_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_UE_Positioning_GANSS_AssistanceData_va40ext_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_UE_Positioning_GANSS_AssistanceData_va40ext = {
	"UE-Positioning-GANSS-AssistanceData-va40ext",
	"UE-Positioning-GANSS-AssistanceData-va40ext",
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
	asn_DEF_UE_Positioning_GANSS_AssistanceData_va40ext_tags_1,
	sizeof(asn_DEF_UE_Positioning_GANSS_AssistanceData_va40ext_tags_1)
		/sizeof(asn_DEF_UE_Positioning_GANSS_AssistanceData_va40ext_tags_1[0]), /* 1 */
	asn_DEF_UE_Positioning_GANSS_AssistanceData_va40ext_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_Positioning_GANSS_AssistanceData_va40ext_tags_1)
		/sizeof(asn_DEF_UE_Positioning_GANSS_AssistanceData_va40ext_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_UE_Positioning_GANSS_AssistanceData_va40ext_1,
	2,	/* Elements count */
	&asn_SPC_UE_Positioning_GANSS_AssistanceData_va40ext_specs_1	/* Additional specs */
};

