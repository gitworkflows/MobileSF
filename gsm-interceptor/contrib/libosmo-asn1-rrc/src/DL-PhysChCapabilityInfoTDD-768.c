/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "DL-PhysChCapabilityInfoTDD-768.h"

static asn_TYPE_member_t asn_MBR_DL_PhysChCapabilityInfoTDD_768_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityInfoTDD_768, maxTS_PerFrame),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxTS_PerFrame,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxTS-PerFrame"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityInfoTDD_768, maxPhysChPerFrame),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxPhysChPerFrame_768,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxPhysChPerFrame"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityInfoTDD_768, minimumSF),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MinimumSF_DL_768,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"minimumSF"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityInfoTDD_768, supportOfPDSCH),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"supportOfPDSCH"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityInfoTDD_768, maxPhysChPerTS),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxPhysChPerTS_768,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxPhysChPerTS"
		},
};
static ber_tlv_tag_t asn_DEF_DL_PhysChCapabilityInfoTDD_768_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_DL_PhysChCapabilityInfoTDD_768_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* maxTS-PerFrame at 1112 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* maxPhysChPerFrame at 1113 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* minimumSF at 1114 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* supportOfPDSCH at 1115 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* maxPhysChPerTS at 1117 */
};
static asn_SEQUENCE_specifics_t asn_SPC_DL_PhysChCapabilityInfoTDD_768_specs_1 = {
	sizeof(struct DL_PhysChCapabilityInfoTDD_768),
	offsetof(struct DL_PhysChCapabilityInfoTDD_768, _asn_ctx),
	asn_MAP_DL_PhysChCapabilityInfoTDD_768_tag2el_1,
	5,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_DL_PhysChCapabilityInfoTDD_768 = {
	"DL-PhysChCapabilityInfoTDD-768",
	"DL-PhysChCapabilityInfoTDD-768",
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
	asn_DEF_DL_PhysChCapabilityInfoTDD_768_tags_1,
	sizeof(asn_DEF_DL_PhysChCapabilityInfoTDD_768_tags_1)
		/sizeof(asn_DEF_DL_PhysChCapabilityInfoTDD_768_tags_1[0]), /* 1 */
	asn_DEF_DL_PhysChCapabilityInfoTDD_768_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_PhysChCapabilityInfoTDD_768_tags_1)
		/sizeof(asn_DEF_DL_PhysChCapabilityInfoTDD_768_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_DL_PhysChCapabilityInfoTDD_768_1,
	5,	/* Elements count */
	&asn_SPC_DL_PhysChCapabilityInfoTDD_768_specs_1	/* Additional specs */
};

