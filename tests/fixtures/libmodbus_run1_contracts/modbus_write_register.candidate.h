/*@
  requires ctx_shape: ctx == \null || \valid(ctx);
  terminates \true;
  exits \false;
  assigns *ctx \from coil_addr, status;
  ensures status: \result >= -1;
*/
MODBUS_API int modbus_write_bit(modbus_t *ctx, int coil_addr, int status);
/*@
  requires ctx_shape: ctx == \null || \valid(ctx);
  terminates \true;
  exits \false;
  ensures null_status: ctx == \null ==> \result == -1;
*/
MODBUS_API int modbus_write_register(modbus_t *ctx, int reg_addr, const uint16_t value);
