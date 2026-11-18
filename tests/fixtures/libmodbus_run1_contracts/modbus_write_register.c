/* Writes a value in one register of the remote device */
int modbus_write_register(modbus_t *ctx, int addr, const uint16_t value)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    return write_single(ctx, MODBUS_FC_WRITE_SINGLE_REGISTER, addr, value);
}
