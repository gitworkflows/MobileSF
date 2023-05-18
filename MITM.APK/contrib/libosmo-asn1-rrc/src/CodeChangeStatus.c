/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "CodeChangeStatus.h"

static asn_TYPE_member_t asn_MBR_CodeChangeStatus_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CodeChangeStatus, primaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"primaryCPICH-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CodeChangeStatus, scramblingCodeChange),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ScramblingCodeChange,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"scramblingCodeChange"
		},
};
static ber_tlv_tag_t asn_DEF_CodeChangeStatus_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_CodeChangeStatus_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* primaryCPICH-Info at 730 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* scramblingCodeChange at 732 */
};
static asn_SEQUENCE_specifics_t asn_SPC_CodeChangeStatus_specs_1 = {
	sizeof(struct CodeChangeStatus),
	offsetof(struct CodeChangeStatus, _asn_ctx),
	asn_MAP_CodeChangeStatus_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_CodeChangeStatus = {
	"CodeChangeStatus",
	"CodeChangeStatus",
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
	asn_DEF_CodeChangeStatus_tags_1,
	sizeof(asn_DEF_CodeChangeStatus_tags_1)
		/sizeof(asn_DEF_CodeChangeStatus_tags_1[0]), /* 1 */
	asn_DEF_CodeChangeStatus_tags_1,	/* Same as above */
	sizeof(asn_DEF_CodeChangeStatus_tags_1)
		/sizeof(asn_DEF_CodeChangeStatus_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_CodeChangeStatus_1,
	2,	/* Elements count */
	&asn_SPC_CodeChangeStatus_specs_1	/* Additional specs */
};

