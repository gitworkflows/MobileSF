/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "CD-AccessSlotSubchannel.h"

int
CD_AccessSlotSubchannel_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 11)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using NativeInteger,
 * so here we adjust the DEF accordingly.
 */
static void
CD_AccessSlotSubchannel_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
	td->free_struct    = asn_DEF_NativeInteger.free_struct;
	td->print_struct   = asn_DEF_NativeInteger.print_struct;
	td->ber_decoder    = asn_DEF_NativeInteger.ber_decoder;
	td->der_encoder    = asn_DEF_NativeInteger.der_encoder;
	td->xer_decoder    = asn_DEF_NativeInteger.xer_decoder;
	td->xer_encoder    = asn_DEF_NativeInteger.xer_encoder;
	td->uper_decoder   = asn_DEF_NativeInteger.uper_decoder;
	td->uper_encoder   = asn_DEF_NativeInteger.uper_encoder;
	if(!td->per_constraints)
		td->per_constraints = asn_DEF_NativeInteger.per_constraints;
	td->elements       = asn_DEF_NativeInteger.elements;
	td->elements_count = asn_DEF_NativeInteger.elements_count;
	td->specifics      = asn_DEF_NativeInteger.specifics;
}

void
CD_AccessSlotSubchannel_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	CD_AccessSlotSubchannel_1_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

int
CD_AccessSlotSubchannel_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	CD_AccessSlotSubchannel_1_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

asn_dec_rval_t
CD_AccessSlotSubchannel_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	CD_AccessSlotSubchannel_1_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

asn_enc_rval_t
CD_AccessSlotSubchannel_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	CD_AccessSlotSubchannel_1_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

asn_dec_rval_t
CD_AccessSlotSubchannel_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	CD_AccessSlotSubchannel_1_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

asn_enc_rval_t
CD_AccessSlotSubchannel_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	CD_AccessSlotSubchannel_1_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

asn_dec_rval_t
CD_AccessSlotSubchannel_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	CD_AccessSlotSubchannel_1_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

asn_enc_rval_t
CD_AccessSlotSubchannel_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	CD_AccessSlotSubchannel_1_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static asn_per_constraints_t asn_PER_type_CD_AccessSlotSubchannel_constr_1 = {
	{ APC_CONSTRAINED,	 4,  4,  0,  11 }	/* (0..11) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static ber_tlv_tag_t asn_DEF_CD_AccessSlotSubchannel_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (2 << 2))
};
asn_TYPE_descriptor_t asn_DEF_CD_AccessSlotSubchannel = {
	"CD-AccessSlotSubchannel",
	"CD-AccessSlotSubchannel",
	CD_AccessSlotSubchannel_free,
	CD_AccessSlotSubchannel_print,
	CD_AccessSlotSubchannel_constraint,
	CD_AccessSlotSubchannel_decode_ber,
	CD_AccessSlotSubchannel_encode_der,
	CD_AccessSlotSubchannel_decode_xer,
	CD_AccessSlotSubchannel_encode_xer,
	CD_AccessSlotSubchannel_decode_uper,
	CD_AccessSlotSubchannel_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_CD_AccessSlotSubchannel_tags_1,
	sizeof(asn_DEF_CD_AccessSlotSubchannel_tags_1)
		/sizeof(asn_DEF_CD_AccessSlotSubchannel_tags_1[0]), /* 1 */
	asn_DEF_CD_AccessSlotSubchannel_tags_1,	/* Same as above */
	sizeof(asn_DEF_CD_AccessSlotSubchannel_tags_1)
		/sizeof(asn_DEF_CD_AccessSlotSubchannel_tags_1[0]), /* 1 */
	&asn_PER_type_CD_AccessSlotSubchannel_constr_1,
	0, 0,	/* No members */
	0	/* No specifics */
};

