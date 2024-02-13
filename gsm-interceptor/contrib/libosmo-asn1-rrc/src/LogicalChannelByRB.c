/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "LogicalChannelByRB.h"

static int
memb_logChOfRb_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 1)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_logChOfRb_constr_3 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_LogicalChannelByRB_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelByRB, rb_Identity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_Identity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rb-Identity"
		},
	{ ATF_POINTER, 1, offsetof(struct LogicalChannelByRB, logChOfRb),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_logChOfRb_constraint_1,
		&asn_PER_memb_logChOfRb_constr_3,
		0,
		"logChOfRb"
		},
};
static int asn_MAP_LogicalChannelByRB_oms_1[] = { 1 };
static ber_tlv_tag_t asn_DEF_LogicalChannelByRB_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_LogicalChannelByRB_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rb-Identity at 5409 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* logChOfRb at 5410 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LogicalChannelByRB_specs_1 = {
	sizeof(struct LogicalChannelByRB),
	offsetof(struct LogicalChannelByRB, _asn_ctx),
	asn_MAP_LogicalChannelByRB_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_LogicalChannelByRB_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_LogicalChannelByRB = {
	"LogicalChannelByRB",
	"LogicalChannelByRB",
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
	asn_DEF_LogicalChannelByRB_tags_1,
	sizeof(asn_DEF_LogicalChannelByRB_tags_1)
		/sizeof(asn_DEF_LogicalChannelByRB_tags_1[0]), /* 1 */
	asn_DEF_LogicalChannelByRB_tags_1,	/* Same as above */
	sizeof(asn_DEF_LogicalChannelByRB_tags_1)
		/sizeof(asn_DEF_LogicalChannelByRB_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_LogicalChannelByRB_1,
	2,	/* Elements count */
	&asn_SPC_LogicalChannelByRB_specs_1	/* Additional specs */
};

