#ifndef PINTOS_FIXED_POINT_H
#define PINTOS_FIXED_POINT_H

#define f_shift (1 << 14)
typedef int fixed_point;

/*
 *  Convert n to fixed point:	                    n * f
 *  Convert x to integer (rounding toward zero):	x / f
 *  Convert x to integer (rounding to nearest):	    (x + f / 2) / f if x >= 0,
 *                                                  (x - f / 2) / f if x <= 0.
 *  Add x and y:	                                x + y
 *  Subtract y from x:	                            x - y
 *  Add x and n:	                                x + n * f
 *  Subtract n from x:	                            x - n * f
 *  Multiply x by y:	                            ((int64_t) x) * y / f
 *  Multiply x by n:	                            x * n
 *  Divide x by y:	                                ((int64_t) x) * f / y
 *  Divide x by n:	                                x / n
 */
#define fixed_pint_convert_int(int_number) ((int_number) * f_shift)
#define fixed_point_floor(fixed_point_number) ((fixed_point_number) / f_shift)
#define fixed_point_round(fixed_point_number) ((fixed_point_number < 0) ? ((fixed_point_number - (f_shift >> 1)) / f_shift) : ((fixed_point_number + (f_shift >> 1)) / f_shift))
#define fixed_point_add(fixed_point_number_1, fixed_point_number_2) ((fixed_point_number_1) + (fixed_point_number_2))
#define fixed_point_subtract(fixed_point_number_1, fixed_point_number_2) ((fixed_point_number_1) - (fixed_point_number_2))
#define fixed_point_add_integer(fixed_point_number, int_number) ((fixed_point_number) + ((int_number) * f_shift))
#define fixed_point_subtract_integer(fixed_point_number, int_number) ((fixed_point_number) - ((int_number) * f_shift))
#define fixed_point_multiply(fixed_point_number_1, fixed_point_number_2) (((int64_t) (fixed_point_number_1)) * (fixed_point_number_2) / f_shift)
#define fixed_point_multiply_integer(fixed_point_number, int_number) ((fixed_point_number) * (int_number))
#define fixed_point_divide(fixed_point_number_1, fixed_point_number_2) (((int64_t) (fixed_point_number_1)) * f_shift / (fixed_point_number_2))
#define fixed_point_divide_integer(fixed_point_number, int_number) ((fixed_point_number) / (int_number))

#endif //PINTOS_FIXED_POINT_H
