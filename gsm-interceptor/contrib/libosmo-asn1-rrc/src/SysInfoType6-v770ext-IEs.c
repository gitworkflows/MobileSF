/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "SysInfoType6-v770ext-IEs.h"

static asn_TYPE_member_t asn_MBR_tdd768SpecificInfo_2[] = {
	{ ATF_POINTER, 3, offsetof(struct SysInfoType6_v770ext_IEs__tdd768SpecificInfo, pusch_SysInfoList_SFN),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PUSCH_SysInfoList_SFN_VHCR,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pusch-SysInfoList-SFN"
		},
	{ ATF_POINTER, 2, offsetof(struct SysInfoType6_v770ext_IEs__tdd768SpecificInfo, pdsch_SysInfoList_SFN),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PDSCH_SysInfoList_VHCR_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pdsch-SysInfoList-SFN"
		},
	{ ATF_POINTER, 1, offsetof(struct SysInfoType6_v770ext_IEs__tdd768SpecificInfo, prach_SystemInformationList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PRACH_SystemInformationList_VHCR_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"prach-SystemInformationList"
		},
};
static int asn_MAP_tdd768SpecificInfo_oms_2[] = { 0, 1, 2 };
static ber_tlv_tag_t asn_DEF_tdd768SpecificInfo_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd768SpecificInfo_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* pusch-SysInfoList-SFN at 21122 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* pdsch-SysInfoList-SFN at 21123 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* prach-SystemInformationList at 21128 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd768SpecificInfo_specs_2 = {
	sizeof(struct SysInfoType6_v770ext_IEs__tdd768SpecificInfo),
	offsetof(struct SysInfoType6_v770ext_IEs__tdd768SpecificInfo, _asn_ctx),
	asn_MAP_tdd768SpecificInfo_tag2el_2,
	3,	/* Count of tags in the map */
	asn_MAP_tdd768SpecificInfo_oms_2,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd768SpecificInfo_2 = {
	"tdd768SpecificInfo",
	"tdd768SpecificInfo",
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
	asn_DEF_tdd768SpecificInfo_tags_2,
	sizeof(asn_DEF_tdd768SpecificInfo_tags_2)
		/sizeof(asn_DEF_tdd768SpecificInfo_tags_2[0]) - 1, /* 1 */
	asn_DEF_tdd768SpecificInfo_tags_2,	/* Same as above */
	sizeof(asn_DEF_tdd768SpecificInfo_tags_2)
		/sizeof(asn_DEF_tdd768SpecificInfo_tags_2[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd768SpecificInfo_2,
	3,	/* Elements count */
	&asn_SPC_tdd768SpecificInfo_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_SysInfoType6_v770ext_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct SysInfoType6_v770ext_IEs, tdd768SpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_tdd768SpecificInfo_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd768SpecificInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct SysInfoType6_v770ext_IEs, sccpch_SystemInformationList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SCCPCH_SystemInformationList_HCR_VHCR_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sccpch-SystemInformationList"
		},
};
static int asn_MAP_SysInfoType6_v770ext_IEs_oms_1[] = { 0, 1 };
static ber_tlv_tag_t asn_DEF_SysInfoType6_v770ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_SysInfoType6_v770ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tdd768SpecificInfo at 21122 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* sccpch-SystemInformationList at 21133 */
};
static asn_SEQUENCE_specifics_t asn_SPC_SysInfoType6_v770ext_IEs_specs_1 = {
	sizeof(struct SysInfoType6_v770ext_IEs),
	offsetof(struct SysInfoType6_v770ext_IEs, _asn_ctx),
	asn_MAP_SysInfoType6_v770ext_IEs_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_SysInfoType6_v770ext_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_SysInfoType6_v770ext_IEs = {
	"SysInfoType6-v770ext-IEs",
	"SysInfoType6-v770ext-IEs",
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
	asn_DEF_SysInfoType6_v770ext_IEs_tags_1,
	sizeof(asn_DEF_SysInfoType6_v770ext_IEs_tags_1)
		/sizeof(asn_DEF_SysInfoType6_v770ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_SysInfoType6_v770ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_SysInfoType6_v770ext_IEs_tags_1)
		/sizeof(asn_DEF_SysInfoType6_v770ext_IEs_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_SysInfoType6_v770ext_IEs_1,
	2,	/* Elements count */
	&asn_SPC_SysInfoType6_v770ext_IEs_specs_1	/* Additional specs */
};

