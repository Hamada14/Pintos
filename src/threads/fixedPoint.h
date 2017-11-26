#ifndef FIXEDPOINT_H_INCLUDED

#define FIXEDPOINT_H_INCLUDED
#define FP 1<<14

typedef int fixed_point;

fixed_point int_to_FixedPoint(int n) ;
int fixedPoint_to_floorInt (fixed_point x);
int fixedPoint_to_roundInt (fixed_point x);
fixed_point add_integer(fixed_point x,int n);
fixed_point add_fixed_point(fixed_point x,fixed_point y);
fixed_point sub_integer(fixed_point x,int n);
fixed_point sub_fixed_point(fixed_point x,fixed_point y);
fixed_point mul_integer(fixed_point x,int n);
fixed_point mul_fixed_point(fixed_point x,fixed_point y);
fixed_point div_integer(fixed_point x,int n);
fixed_point div_fixed_point(fixed_point x,fixed_point y);


#endif // FIXEDPOINT_H_INCLUDED
