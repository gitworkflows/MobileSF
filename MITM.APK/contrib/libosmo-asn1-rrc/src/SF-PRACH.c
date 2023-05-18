/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "SF-PRACH.h"

int
SF_PRACH_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
SF_PRACH_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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

void
SF_PRACH_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	SF_PRACH_1_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

int
SF_PRACH_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	SF_PRACH_1_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

asn_dec_rval_t
SF_PRACH_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	SF_PRACH_1_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

asn_enc_rval_t
SF_PRACH_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	SF_PRACH_1_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

asn_dec_rval_t
SF_PRACH_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	SF_PRACH_1_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

asn_enc_rval_t
SF_PRACH_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	SF_PRACH_1_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

asn_dec_rval_t
SF_PRACH_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	SF_PRACH_1_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

asn_enc_rval_t
SF_PRACH_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	SF_PRACH_1_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static asn_per_constraints_t asn_PER_type_SF_PRACH_constr_1 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_INTEGER_enum_map_t asn_MAP_SF_PRACH_value2enum_1[] = {
	{ 0,	6,	"sfpr32" },
	{ 1,	6,	"sfpr64" },
	{ 2,	7,	"sfpr128" },
	{ 3,	7,	"sfpr256" }
};
static unsigned int asn_MAP_SF_PRACH_enum2value_1[] = {
	2,	/* sfpr128(2) */
	3,	/* sfpr256(3) */
	0,	/* sfpr32(0) */
	1	/* sfpr64(1) */
};
static asn_INTEGER_specifics_t asn_SPC_SF_PRACH_specs_1 = {
	asn_MAP_SF_PRACH_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_SF_PRACH_enum2value_1,	/* N => "tag"; sorted by N */
	4,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_SF_PRACH_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_SF_PRACH = {
	"SF-PRACH",
	"SF-PRACH",
	SF_PRACH_free,
	SF_PRACH_print,
	SF_PRACH_constraint,
	SF_PRACH_decode_ber,
	SF_PRACH_encode_der,
	SF_PRACH_decode_xer,
	SF_PRACH_encode_xer,
	SF_PRACH_decode_uper,
	SF_PRACH_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_SF_PRACH_tags_1,
	sizeof(asn_DEF_SF_PRACH_tags_1)
		/sizeof(asn_DEF_SF_PRACH_tags_1[0]), /* 1 */
	asn_DEF_SF_PRACH_tags_1,	/* Same as above */
	sizeof(asn_DEF_SF_PRACH_tags_1)
		/sizeof(asn_DEF_SF_PRACH_tags_1[0]), /* 1 */
	&asn_PER_type_SF_PRACH_constr_1,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_SF_PRACH_specs_1	/* Additional specs */
};

