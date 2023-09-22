/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "HandoverFromUTRANCommand-EUTRA-r11-IEs.h"

static asn_TYPE_member_t asn_MBR_HandoverFromUTRANCommand_EUTRA_r11_IEs_1[] = {
	{ ATF_POINTER, 3, offsetof(struct HandoverFromUTRANCommand_EUTRA_r11_IEs, rsr_vcc_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RSR_VCC_Info,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rsr-vcc-Info"
		},
	{ ATF_POINTER, 2, offsetof(struct HandoverFromUTRANCommand_EUTRA_r11_IEs, activationTime),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ActivationTime,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"activationTime"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverFromUTRANCommand_EUTRA_r11_IEs, toHandoverRAB_Info),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RAB_InformationList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"toHandoverRAB-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_EUTRA_r11_IEs, eutra_Message),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"eutra-Message"
		},
};
static int asn_MAP_HandoverFromUTRANCommand_EUTRA_r11_IEs_oms_1[] = { 0, 1, 2 };
static ber_tlv_tag_t asn_DEF_HandoverFromUTRANCommand_EUTRA_r11_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_HandoverFromUTRANCommand_EUTRA_r11_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rsr-vcc-Info at 3458 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* activationTime at 3459 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* toHandoverRAB-Info at 3461 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* eutra-Message at 3463 */
};
static asn_SEQUENCE_specifics_t asn_SPC_HandoverFromUTRANCommand_EUTRA_r11_IEs_specs_1 = {
	sizeof(struct HandoverFromUTRANCommand_EUTRA_r11_IEs),
	offsetof(struct HandoverFromUTRANCommand_EUTRA_r11_IEs, _asn_ctx),
	asn_MAP_HandoverFromUTRANCommand_EUTRA_r11_IEs_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_HandoverFromUTRANCommand_EUTRA_r11_IEs_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_HandoverFromUTRANCommand_EUTRA_r11_IEs = {
	"HandoverFromUTRANCommand-EUTRA-r11-IEs",
	"HandoverFromUTRANCommand-EUTRA-r11-IEs",
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
	asn_DEF_HandoverFromUTRANCommand_EUTRA_r11_IEs_tags_1,
	sizeof(asn_DEF_HandoverFromUTRANCommand_EUTRA_r11_IEs_tags_1)
		/sizeof(asn_DEF_HandoverFromUTRANCommand_EUTRA_r11_IEs_tags_1[0]), /* 1 */
	asn_DEF_HandoverFromUTRANCommand_EUTRA_r11_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_HandoverFromUTRANCommand_EUTRA_r11_IEs_tags_1)
		/sizeof(asn_DEF_HandoverFromUTRANCommand_EUTRA_r11_IEs_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_HandoverFromUTRANCommand_EUTRA_r11_IEs_1,
	4,	/* Elements count */
	&asn_SPC_HandoverFromUTRANCommand_EUTRA_r11_IEs_specs_1	/* Additional specs */
};

