/* The runtime aborts on the write to an invalid address. With --rt-debug,
   it prints a backtrace that should name write_ptr and main. */
void write_ptr(int *p) { *p = 42; }
int main(void) { write_ptr((int *)0x1000); return 0; }
