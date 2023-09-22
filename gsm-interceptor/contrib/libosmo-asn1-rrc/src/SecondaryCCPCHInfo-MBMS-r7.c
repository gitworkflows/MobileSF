/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "SecondaryCCPCHInfo-MBMS-r7.h"

static int
memb_mod16QAM_constraint_8(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -11 && value <= 4)) {
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
modulation_14_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
modulation_14_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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
modulation_14_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	modulation_14_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
modulation_14_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	modulation_14_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
modulation_14_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	modulation_14_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
modulation_14_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	modulation_14_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
modulation_14_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	modulation_14_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
modulation_14_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	modulation_14_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
modulation_14_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	modulation_14_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
modulation_14_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	modulation_14_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static int
modulation_20_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
modulation_20_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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
modulation_20_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	modulation_20_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
modulation_20_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	modulation_20_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
modulation_20_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	modulation_20_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
modulation_20_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	modulation_20_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
modulation_20_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	modulation_20_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
modulation_20_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	modulation_20_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
modulation_20_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	modulation_20_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
modulation_20_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	modulation_20_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static int
modulation_27_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
modulation_27_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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
modulation_27_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	modulation_27_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
modulation_27_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	modulation_27_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
modulation_27_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	modulation_27_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
modulation_27_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	modulation_27_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
modulation_27_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	modulation_27_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
modulation_27_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	modulation_27_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
modulation_27_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	modulation_27_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
modulation_27_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	modulation_27_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static asn_per_constraints_t asn_PER_memb_mod16QAM_constr_10 = {
	{ APC_CONSTRAINED,	 4,  4, -11,  4 }	/* (-11..4) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_modulation_constr_8 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_modulation_constr_14 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_modulation_constr_20 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_modulation_constr_27 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_2 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static int asn_DFL_7_set_0(int set_value, void **sptr) {
	TimingOffset_t *st = *sptr;
	
	if(!st) {
		if(!set_value) return -1;	/* Not a default value */
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	if(set_value) {
		/* Install default value 0 */
		*st = 0;
		return 0;
	} else {
		/* Test default value 0 */
		return (*st == 0);
	}
}
static asn_TYPE_member_t asn_MBR_modulation_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation, choice.modQPSK),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modQPSK"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation, choice.mod16QAM),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_mod16QAM_constraint_8,
		&asn_PER_memb_mod16QAM_constr_10,
		0,
		"mod16QAM"
		},
};
static asn_TYPE_tag2member_t asn_MAP_modulation_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* modQPSK at 11152 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* mod16QAM at 11154 */
};
static asn_CHOICE_specifics_t asn_SPC_modulation_specs_8 = {
	sizeof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation),
	offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation, _asn_ctx),
	offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation, present),
	sizeof(((struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation *)0)->present),
	asn_MAP_modulation_tag2el_8,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modulation_8 = {
	"modulation",
	"modulation",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	CHOICE_decode_uper,
	CHOICE_encode_uper,
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_modulation_constr_8,
	asn_MBR_modulation_8,
	2,	/* Elements count */
	&asn_SPC_modulation_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_fdd_3[] = {
	{ ATF_POINTER, 1, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd, secondaryScramblingCode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SecondaryScramblingCode,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"secondaryScramblingCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd, sttd_Indicator),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sttd-Indicator"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd, sf_AndCodeNumber),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_SF256_AndCodeNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sf-AndCodeNumber"
		},
	{ ATF_NOFLAGS, 2, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd, timingOffset),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimingOffset,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		asn_DFL_7_set_0,	/* DEFAULT 0 */
		"timingOffset"
		},
	{ ATF_POINTER, 1, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd, modulation),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modulation_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modulation"
		},
};
static int asn_MAP_fdd_oms_3[] = { 0, 3, 4 };
static ber_tlv_tag_t asn_DEF_fdd_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* secondaryScramblingCode at 11144 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* sttd-Indicator at 11147 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* sf-AndCodeNumber at 11148 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* timingOffset at 11150 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* modulation at 11152 */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_3 = {
	sizeof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd),
	offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_3,
	5,	/* Count of tags in the map */
	asn_MAP_fdd_oms_3,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_3 = {
	"fdd",
	"fdd",
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
	asn_DEF_fdd_tags_3,
	sizeof(asn_DEF_fdd_tags_3)
		/sizeof(asn_DEF_fdd_tags_3[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_3,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_3)
		/sizeof(asn_DEF_fdd_tags_3[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_fdd_3,
	5,	/* Elements count */
	&asn_SPC_fdd_specs_3	/* Additional specs */
};

static asn_INTEGER_enum_map_t asn_MAP_modulation_value2enum_14[] = {
	{ 0,	7,	"modQPSK" },
	{ 1,	8,	"mod16QAM" }
};
static unsigned int asn_MAP_modulation_enum2value_14[] = {
	1,	/* mod16QAM(1) */
	0	/* modQPSK(0) */
};
static asn_INTEGER_specifics_t asn_SPC_modulation_specs_14 = {
	asn_MAP_modulation_value2enum_14,	/* "tag" => N; sorted by tag */
	asn_MAP_modulation_enum2value_14,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_modulation_tags_14[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modulation_14 = {
	"modulation",
	"modulation",
	modulation_14_free,
	modulation_14_print,
	modulation_14_constraint,
	modulation_14_decode_ber,
	modulation_14_encode_der,
	modulation_14_decode_xer,
	modulation_14_encode_xer,
	modulation_14_decode_uper,
	modulation_14_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_modulation_tags_14,
	sizeof(asn_DEF_modulation_tags_14)
		/sizeof(asn_DEF_modulation_tags_14[0]) - 1, /* 1 */
	asn_DEF_modulation_tags_14,	/* Same as above */
	sizeof(asn_DEF_modulation_tags_14)
		/sizeof(asn_DEF_modulation_tags_14[0]), /* 2 */
	&asn_PER_type_modulation_constr_14,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_modulation_specs_14	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd384_11[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384, commonTimeslotInfoMBMS),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CommonTimeslotInfoMBMS,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"commonTimeslotInfoMBMS"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384, downlinkTimeslotsCodes),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DownlinkTimeslotsCodes_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"downlinkTimeslotsCodes"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384, modulation),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_modulation_14,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modulation"
		},
};
static ber_tlv_tag_t asn_DEF_tdd384_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd384_tag2el_11[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* commonTimeslotInfoMBMS at 11158 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* downlinkTimeslotsCodes at 11159 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* modulation at 11160 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd384_specs_11 = {
	sizeof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384),
	offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384, _asn_ctx),
	asn_MAP_tdd384_tag2el_11,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd384_11 = {
	"tdd384",
	"tdd384",
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
	asn_DEF_tdd384_tags_11,
	sizeof(asn_DEF_tdd384_tags_11)
		/sizeof(asn_DEF_tdd384_tags_11[0]) - 1, /* 1 */
	asn_DEF_tdd384_tags_11,	/* Same as above */
	sizeof(asn_DEF_tdd384_tags_11)
		/sizeof(asn_DEF_tdd384_tags_11[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd384_11,
	3,	/* Elements count */
	&asn_SPC_tdd384_specs_11	/* Additional specs */
};

static asn_INTEGER_enum_map_t asn_MAP_modulation_value2enum_20[] = {
	{ 0,	7,	"modQPSK" },
	{ 1,	8,	"mod16QAM" }
};
static unsigned int asn_MAP_modulation_enum2value_20[] = {
	1,	/* mod16QAM(1) */
	0	/* modQPSK(0) */
};
static asn_INTEGER_specifics_t asn_SPC_modulation_specs_20 = {
	asn_MAP_modulation_value2enum_20,	/* "tag" => N; sorted by tag */
	asn_MAP_modulation_enum2value_20,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_modulation_tags_20[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modulation_20 = {
	"modulation",
	"modulation",
	modulation_20_free,
	modulation_20_print,
	modulation_20_constraint,
	modulation_20_decode_ber,
	modulation_20_encode_der,
	modulation_20_decode_xer,
	modulation_20_encode_xer,
	modulation_20_decode_uper,
	modulation_20_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_modulation_tags_20,
	sizeof(asn_DEF_modulation_tags_20)
		/sizeof(asn_DEF_modulation_tags_20[0]) - 1, /* 1 */
	asn_DEF_modulation_tags_20,	/* Same as above */
	sizeof(asn_DEF_modulation_tags_20)
		/sizeof(asn_DEF_modulation_tags_20[0]), /* 2 */
	&asn_PER_type_modulation_constr_20,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_modulation_specs_20	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd768_17[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768, commonTimeslotInfoMBMS),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CommonTimeslotInfoMBMS,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"commonTimeslotInfoMBMS"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768, downlinkTimeslotsCodes),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DownlinkTimeslotsCodes_VHCR,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"downlinkTimeslotsCodes"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768, modulation),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_modulation_20,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modulation"
		},
};
static ber_tlv_tag_t asn_DEF_tdd768_tags_17[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd768_tag2el_17[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* commonTimeslotInfoMBMS at 11163 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* downlinkTimeslotsCodes at 11164 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* modulation at 11165 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd768_specs_17 = {
	sizeof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768),
	offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768, _asn_ctx),
	asn_MAP_tdd768_tag2el_17,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd768_17 = {
	"tdd768",
	"tdd768",
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
	asn_DEF_tdd768_tags_17,
	sizeof(asn_DEF_tdd768_tags_17)
		/sizeof(asn_DEF_tdd768_tags_17[0]) - 1, /* 1 */
	asn_DEF_tdd768_tags_17,	/* Same as above */
	sizeof(asn_DEF_tdd768_tags_17)
		/sizeof(asn_DEF_tdd768_tags_17[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd768_17,
	3,	/* Elements count */
	&asn_SPC_tdd768_specs_17	/* Additional specs */
};

static asn_INTEGER_enum_map_t asn_MAP_modulation_value2enum_27[] = {
	{ 0,	7,	"modQPSK" },
	{ 1,	8,	"mod16QAM" }
};
static unsigned int asn_MAP_modulation_enum2value_27[] = {
	1,	/* mod16QAM(1) */
	0	/* modQPSK(0) */
};
static asn_INTEGER_specifics_t asn_SPC_modulation_specs_27 = {
	asn_MAP_modulation_value2enum_27,	/* "tag" => N; sorted by tag */
	asn_MAP_modulation_enum2value_27,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_modulation_tags_27[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modulation_27 = {
	"modulation",
	"modulation",
	modulation_27_free,
	modulation_27_print,
	modulation_27_constraint,
	modulation_27_decode_ber,
	modulation_27_encode_der,
	modulation_27_decode_xer,
	modulation_27_encode_xer,
	modulation_27_decode_uper,
	modulation_27_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_modulation_tags_27,
	sizeof(asn_DEF_modulation_tags_27)
		/sizeof(asn_DEF_modulation_tags_27[0]) - 1, /* 1 */
	asn_DEF_modulation_tags_27,	/* Same as above */
	sizeof(asn_DEF_modulation_tags_27)
		/sizeof(asn_DEF_modulation_tags_27[0]), /* 2 */
	&asn_PER_type_modulation_constr_27,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_modulation_specs_27	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd128_23[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128, commonTimeslotInfoMBMS),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CommonTimeslotInfoMBMS,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"commonTimeslotInfoMBMS"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128, downlinkTimeslotsCodes),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DownlinkTimeslotsCodes_LCR_r4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"downlinkTimeslotsCodes"
		},
	{ ATF_POINTER, 1, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128, mbsfnSpecialTimeSlot),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeSlotLCR_ext,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mbsfnSpecialTimeSlot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128, modulation),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_modulation_27,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modulation"
		},
};
static int asn_MAP_tdd128_oms_23[] = { 2 };
static ber_tlv_tag_t asn_DEF_tdd128_tags_23[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd128_tag2el_23[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* commonTimeslotInfoMBMS at 11168 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* downlinkTimeslotsCodes at 11169 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* mbsfnSpecialTimeSlot at 11170 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* modulation at 11171 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd128_specs_23 = {
	sizeof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128),
	offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128, _asn_ctx),
	asn_MAP_tdd128_tag2el_23,
	4,	/* Count of tags in the map */
	asn_MAP_tdd128_oms_23,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd128_23 = {
	"tdd128",
	"tdd128",
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
	asn_DEF_tdd128_tags_23,
	sizeof(asn_DEF_tdd128_tags_23)
		/sizeof(asn_DEF_tdd128_tags_23[0]) - 1, /* 1 */
	asn_DEF_tdd128_tags_23,	/* Same as above */
	sizeof(asn_DEF_tdd128_tags_23)
		/sizeof(asn_DEF_tdd128_tags_23[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd128_23,
	4,	/* Elements count */
	&asn_SPC_tdd128_specs_23	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo, choice.tdd384),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd384_11,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd384"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo, choice.tdd768),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_tdd768_17,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd768"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo, choice.tdd128),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		0,
		&asn_DEF_tdd128_23,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd128"
		},
};
static asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd at 11144 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tdd384 at 11158 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* tdd768 at 11163 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* tdd128 at 11168 */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_2 = {
	sizeof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo),
	offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo, _asn_ctx),
	offsetof(struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo, present),
	sizeof(((struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_2,
	4,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_2 = {
	"modeSpecificInfo",
	"modeSpecificInfo",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	CHOICE_decode_uper,
	CHOICE_encode_uper,
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_modeSpecificInfo_constr_2,
	asn_MBR_modeSpecificInfo_2,
	4,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_SecondaryCCPCHInfo_MBMS_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SecondaryCCPCHInfo_MBMS_r7, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modeSpecificInfo"
		},
};
static ber_tlv_tag_t asn_DEF_SecondaryCCPCHInfo_MBMS_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_SecondaryCCPCHInfo_MBMS_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* modeSpecificInfo at 11156 */
};
static asn_SEQUENCE_specifics_t asn_SPC_SecondaryCCPCHInfo_MBMS_r7_specs_1 = {
	sizeof(struct SecondaryCCPCHInfo_MBMS_r7),
	offsetof(struct SecondaryCCPCHInfo_MBMS_r7, _asn_ctx),
	asn_MAP_SecondaryCCPCHInfo_MBMS_r7_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_SecondaryCCPCHInfo_MBMS_r7 = {
	"SecondaryCCPCHInfo-MBMS-r7",
	"SecondaryCCPCHInfo-MBMS-r7",
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
	asn_DEF_SecondaryCCPCHInfo_MBMS_r7_tags_1,
	sizeof(asn_DEF_SecondaryCCPCHInfo_MBMS_r7_tags_1)
		/sizeof(asn_DEF_SecondaryCCPCHInfo_MBMS_r7_tags_1[0]), /* 1 */
	asn_DEF_SecondaryCCPCHInfo_MBMS_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_SecondaryCCPCHInfo_MBMS_r7_tags_1)
		/sizeof(asn_DEF_SecondaryCCPCHInfo_MBMS_r7_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_SecondaryCCPCHInfo_MBMS_r7_1,
	1,	/* Elements count */
	&asn_SPC_SecondaryCCPCHInfo_MBMS_r7_specs_1	/* Additional specs */
};

