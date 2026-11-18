/* Which frame clause forms the Frama-C kernel accepts in a function contract.
   Each function carries one form; clause_forms.log is the kernel's answer (annot-error kept as a
   warning so that every function is typed). The `refused_*` functions carry the forms the frame
   skeleton projected before the fix; the `accepted_*` ones the forms it projects now. */
struct tcp { unsigned short t_id; };
struct ctx { int slave; void *backend_data; };

/*@ assigns dst + (0 .. n - 1) \from n; */
void refused_address_set_in_assigns(char *dst, const char *src, int n)
{
    int i;
    for (i = 0; i < n; i++) dst[i] = src[i];
}

/*@ assigns *eaten \from buf + (0 .. 1), len; */
void refused_address_set_after_from(unsigned short *buf, int len, unsigned short *eaten)
{
    *eaten = (unsigned short)(buf[0] + buf[1] + len);
}

/*@ assigns *(dest + i) \from idx, nb_bits; */
void refused_loop_index(unsigned char *dest, int idx, unsigned int nb_bits)
{
    unsigned int i;
    for (i = idx; i < idx + nb_bits; i++) dest[i] = 0;
}

/*@ assigns ctx_tcp->t_id \from \nothing; */
void refused_local_alias(struct ctx *ctx)
{
    struct tcp *ctx_tcp = ctx->backend_data;
    ctx_tcp->t_id = 0;
}

/*@ requires \separated(dst + (0 .. n - 1), src + (0 .. n - 1));
    assigns *(dst + (0 .. n - 1)) \from *(src + (0 .. n - 1)), n; */
void accepted_copy_loop(char *dst, const char *src, int n)
{
    int i;
    for (i = 0; i < n; i++) dst[i] = src[i];
}

/*@ requires \separated(buf + (0 .. 1), eaten);
    assigns *eaten \from *(buf + (0 .. 1)), len; */
void accepted_parse_value(unsigned short *buf, int len, unsigned short *eaten)
{
    *eaten = (unsigned short)(buf[0] + buf[1] + len);
}

/*@ assigns *(req + 0);
    assigns *(req + 7) \from function; */
void accepted_location_without_from(unsigned char *req, int function)
{
    req[0] = 1;
    req[7] = (unsigned char)function;
}

/*@ assigns ((struct tcp *)ctx->backend_data)->t_id \from \nothing; */
void accepted_alias_over_the_formal(struct ctx *ctx)
{
    struct tcp *ctx_tcp = ctx->backend_data;
    ctx_tcp->t_id = 0;
}

/*@ assigns dest[idx .. idx + nb_bits - 1]; */
void accepted_range_over_the_formals(unsigned char *dest, int idx, unsigned int nb_bits)
{
    unsigned int i;
    for (i = idx; i < idx + nb_bits; i++) dest[i] = 0;
}
