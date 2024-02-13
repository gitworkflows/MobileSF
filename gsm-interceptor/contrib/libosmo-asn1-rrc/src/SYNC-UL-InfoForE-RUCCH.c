/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "SYNC-UL-InfoForE-RUCCH.h"

static int
max_SYNC_UL_Transmissions_4_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	/* Replace with underlying type checker */
	td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
	return td->check_constraints(td, sptr, ctfailcb, app_key);
}

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static void
max_SYNC_UL_Transmissions_4_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
	td->free_struct    = asn_DEF_NativeEnumerated.free_struct;
	td->print_struct   = asn_DEF_NativeEnumerated.print_struct;
	td->ber_decoder    = asn_DEF_NativeEnumerated.ber_decoder;
	td->der_encoder    = asn_DEF_NativeEnumerated.der_encoder;
	td->xer_decoder    = asn_DEF_NativeEnumerated.xer_decoder;
	td->xer_encoder    = asn_DEF_NativeEnumerated.xer_encoder;
	td->uper_decoder   = asn_DEF_NativeEnumerated.uper_decoder;
	td->uper_encoder   = asn_DEF_NativeEnumerated.uper_encoder;
	if(!td->per_constraints)
		td->per_constraints = asn_DEF_NativeEnumerated.per_constraints;
	td->elements       = asn_DEF_NativeEnumerated.elements;
	td->elements_count = asn_DEF_NativeEnumerated.elements_count;
     /* td->specifics      = asn_DEF_NativeEnumerated.specifics;	// Defined explicitly */
}

static void
max_SYNC_UL_Transmissions_4_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	max_SYNC_UL_Transmissions_4_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
max_SYNC_UL_Transmissions_4_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	max_SYNC_UL_Transmissions_4_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
max_SYNC_UL_Transmissions_4_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	max_SYNC_UL_Transmissions_4_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
max_SYNC_UL_Transmissions_4_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	max_SYNC_UL_Transmissions_4_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
max_SYNC_UL_Transmissions_4_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	max_SYNC_UL_Transmissions_4_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
max_SYNC_UL_Transmissions_4_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	max_SYNC_UL_Transmissions_4_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
max_SYNC_UL_Transmissions_4_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	max_SYNC_UL_Transmissions_4_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
max_SYNC_UL_Transmissions_4_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	max_SYNC_UL_Transmissions_4_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static int
memb_prxUpPCHdes_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 62)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_powerRampStep_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 3)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_mmax_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 32)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_type_max_SYNC_UL_Transmissions_constr_4 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_prxUpPCHdes_constr_2 = {
	{ APC_CONSTRAINED,	 6,  6,  0,  62 }	/* (0..62) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_powerRampStep_constr_3 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_mmax_constr_10 = {
	{ APC_CONSTRAINED,	 5,  5,  1,  32 }	/* (1..32) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_INTEGER_enum_map_t asn_MAP_max_SYNC_UL_Transmissions_value2enum_4[] = {
	{ 0,	3,	"tr1" },
	{ 1,	3,	"tr2" },
	{ 2,	3,	"tr4" },
	{ 3,	3,	"tr8" }
};
static unsigned int asn_MAP_max_SYNC_UL_Transmissions_enum2value_4[] = {
	0,	/* tr1(0) */
	1,	/* tr2(1) */
	2,	/* tr4(2) */
	3	/* tr8(3) */
};
static asn_INTEGER_specifics_t asn_SPC_max_SYNC_UL_Transmissions_specs_4 = {
	asn_MAP_max_SYNC_UL_Transmissions_value2enum_4,	/* "tag" => N; sorted by tag */
	asn_MAP_max_SYNC_UL_Transmissions_enum2value_4,	/* N => "tag"; sorted by N */
	4,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_max_SYNC_UL_Transmissions_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_max_SYNC_UL_Transmissions_4 = {
	"max-SYNC-UL-Transmissions",
	"max-SYNC-UL-Transmissions",
	max_SYNC_UL_Transmissions_4_free,
	max_SYNC_UL_Transmissions_4_print,
	max_SYNC_UL_Transmissions_4_constraint,
	max_SYNC_UL_Transmissions_4_decode_ber,
	max_SYNC_UL_Transmissions_4_encode_der,
	max_SYNC_UL_Transmissions_4_decode_xer,
	max_SYNC_UL_Transmissions_4_encode_xer,
	max_SYNC_UL_Transmissions_4_decode_uper,
	max_SYNC_UL_Transmissions_4_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_max_SYNC_UL_Transmissions_tags_4,
	sizeof(asn_DEF_max_SYNC_UL_Transmissions_tags_4)
		/sizeof(asn_DEF_max_SYNC_UL_Transmissions_tags_4[0]) - 1, /* 1 */
	asn_DEF_max_SYNC_UL_Transmissions_tags_4,	/* Same as above */
	sizeof(asn_DEF_max_SYNC_UL_Transmissions_tags_4)
		/sizeof(asn_DEF_max_SYNC_UL_Transmissions_tags_4[0]), /* 2 */
	&asn_PER_type_max_SYNC_UL_Transmissions_constr_4,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_max_SYNC_UL_Transmissions_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_SYNC_UL_InfoForE_RUCCH_1[] = {
	{ ATF_POINTER, 3, offsetof(struct SYNC_UL_InfoForE_RUCCH, prxUpPCHdes),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_prxUpPCHdes_constraint_1,
		&asn_PER_memb_prxUpPCHdes_constr_2,
		0,
		"prxUpPCHdes"
		},
	{ ATF_POINTER, 2, offsetof(struct SYNC_UL_InfoForE_RUCCH, powerRampStep),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_powerRampStep_constraint_1,
		&asn_PER_memb_powerRampStep_constr_3,
		0,
		"powerRampStep"
		},
	{ ATF_POINTER, 1, offsetof(struct SYNC_UL_InfoForE_RUCCH, max_SYNC_UL_Transmissions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_max_SYNC_UL_Transmissions_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"max-SYNC-UL-Transmissions"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SYNC_UL_InfoForE_RUCCH, e_RUCCH_Sync_UL_Codes_Bitmap),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Sync_UL_Codes_Bitmap,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-RUCCH-Sync-UL-Codes-Bitmap"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SYNC_UL_InfoForE_RUCCH, mmax),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_mmax_constraint_1,
		&asn_PER_memb_mmax_constr_10,
		0,
		"mmax"
		},
};
static int asn_MAP_SYNC_UL_InfoForE_RUCCH_oms_1[] = { 0, 1, 2 };
static ber_tlv_tag_t asn_DEF_SYNC_UL_InfoForE_RUCCH_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_SYNC_UL_InfoForE_RUCCH_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* prxUpPCHdes at 11396 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* powerRampStep at 11397 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* max-SYNC-UL-Transmissions at 11398 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* e-RUCCH-Sync-UL-Codes-Bitmap at 11399 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* mmax at 11400 */
};
static asn_SEQUENCE_specifics_t asn_SPC_SYNC_UL_InfoForE_RUCCH_specs_1 = {
	sizeof(struct SYNC_UL_InfoForE_RUCCH),
	offsetof(struct SYNC_UL_InfoForE_RUCCH, _asn_ctx),
	asn_MAP_SYNC_UL_InfoForE_RUCCH_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_SYNC_UL_InfoForE_RUCCH_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_SYNC_UL_InfoForE_RUCCH = {
	"SYNC-UL-InfoForE-RUCCH",
	"SYNC-UL-InfoForE-RUCCH",
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
	asn_DEF_SYNC_UL_InfoForE_RUCCH_tags_1,
	sizeof(asn_DEF_SYNC_UL_InfoForE_RUCCH_tags_1)
		/sizeof(asn_DEF_SYNC_UL_InfoForE_RUCCH_tags_1[0]), /* 1 */
	asn_DEF_SYNC_UL_InfoForE_RUCCH_tags_1,	/* Same as above */
	sizeof(asn_DEF_SYNC_UL_InfoForE_RUCCH_tags_1)
		/sizeof(asn_DEF_SYNC_UL_InfoForE_RUCCH_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_SYNC_UL_InfoForE_RUCCH_1,
	5,	/* Elements count */
	&asn_SPC_SYNC_UL_InfoForE_RUCCH_specs_1	/* Additional specs */
};

