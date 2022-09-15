#define f (1<<14)

int int_to_fp(int n);
int fp_to_int_floor(int x);
int fp_to_int_round(int x);
int fp_add_fp(int x, int y);
int fp_sub_fp(int x, int y);
int fp_add_int(int x, int n);
int fp_sub_int(int x, int n);
int fp_mul_fp(int x, int y);
int fp_mul_int(int x, int n);
int fp_div_fp(int x, int y);
int fp_div_int(int x, int n);

int int_to_fp(int n) {
    return n*f;
}
int fp_to_int_floor(int x){
    return x/f;
}
int fp_to_int_round(int x) {
    if x >= 0
        return (x + f/2)/f;
    else
        return (x-f/2)/f;
}
int fp_add_fp(int x, int y) {
    return x+y;
}
int fp_sub_fp(int x, int y) {
    return x-y;
}
int fp_add_int(int x, int n) {
    return x + n*f;
}
int fp_sub_int(int x, int n){
    return x-n*f;
}
int fp_mul_fp(int x, int y) {
    return ((int64_t) x)*y/f;
}
int fp_mul_int(int x, int n){
    return x*n;
}
int fp_div_fp(int x, int y){
    return ((int64_t) x) * f/y;
}
int fp_div_int(int x, int n){
    return x/n;
}