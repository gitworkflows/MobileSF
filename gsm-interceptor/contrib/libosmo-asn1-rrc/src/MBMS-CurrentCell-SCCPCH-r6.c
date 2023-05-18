/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "MBMS-CurrentCell-SCCPCH-r6.h"

static asn_TYPE_member_t asn_MBR_MBMS_CurrentCell_SCCPCH_r6_1[] = {
	{ ATF_POINTER, 1, offsetof(struct MBMS_CurrentCell_SCCPCH_r6, sccpchIdentity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_SCCPCHIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sccpchIdentity"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_CurrentCell_SCCPCH_r6, secondaryCCPCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_CommonPhyChIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"secondaryCCPCH-Info"
		},
	{ ATF_POINTER, 2, offsetof(struct MBMS_CurrentCell_SCCPCH_r6, softComb_TimingOffset),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_SoftComb_TimingOffset,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"softComb-TimingOffset"
		},
	{ ATF_POINTER, 1, offsetof(struct MBMS_CurrentCell_SCCPCH_r6, transpCh_InfoCommonForAllTrCh),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_CommonCCTrChIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"transpCh-InfoCommonForAllTrCh"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_CurrentCell_SCCPCH_r6, transpCHInformation),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_TrCHInformation_CurrList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"transpCHInformation"
		},
};
static int asn_MAP_MBMS_CurrentCell_SCCPCH_r6_oms_1[] = { 0, 2, 3 };
static ber_tlv_tag_t asn_DEF_MBMS_CurrentCell_SCCPCH_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_MBMS_CurrentCell_SCCPCH_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* sccpchIdentity at 21974 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* secondaryCCPCH-Info at 21975 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* softComb-TimingOffset at 21976 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* transpCh-InfoCommonForAllTrCh at 21979 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* transpCHInformation at 21981 */
};
static asn_SEQUENCE_specifics_t asn_SPC_MBMS_CurrentCell_SCCPCH_r6_specs_1 = {
	sizeof(struct MBMS_CurrentCell_SCCPCH_r6),
	offsetof(struct MBMS_CurrentCell_SCCPCH_r6, _asn_ctx),
	asn_MAP_MBMS_CurrentCell_SCCPCH_r6_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_MBMS_CurrentCell_SCCPCH_r6_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_MBMS_CurrentCell_SCCPCH_r6 = {
	"MBMS-CurrentCell-SCCPCH-r6",
	"MBMS-CurrentCell-SCCPCH-r6",
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
	asn_DEF_MBMS_CurrentCell_SCCPCH_r6_tags_1,
	sizeof(asn_DEF_MBMS_CurrentCell_SCCPCH_r6_tags_1)
		/sizeof(asn_DEF_MBMS_CurrentCell_SCCPCH_r6_tags_1[0]), /* 1 */
	asn_DEF_MBMS_CurrentCell_SCCPCH_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBMS_CurrentCell_SCCPCH_r6_tags_1)
		/sizeof(asn_DEF_MBMS_CurrentCell_SCCPCH_r6_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_MBMS_CurrentCell_SCCPCH_r6_1,
	5,	/* Elements count */
	&asn_SPC_MBMS_CurrentCell_SCCPCH_r6_specs_1	/* Additional specs */
};

