#include "fixedPoint.h"

/**
  convert integer to fixed point
*/
fixed_point int_to_FixedPoint(int n)
{
  return f*n;
}

/**
convert fixed point to integer (rounding towards zero)
*/
int fixedPoint_to_floorInt (fixed_point x)
{
  return x/f;
}

/**
converting fixed point to integer (rounding to nearest)
*/
int fixedPoint_to_roundInt (fixed_point x)
{
  if (x>=0)
     return (x+f/2)/f ;
  return (x-f/2)/f ;
}

/**
add integer to fixed point x+n
*/
fixed_point add_integer(fixed_point x,int n)
{
  return x+n*f;
}

/**
fixed point addition x+y
*/
fixed_point add_fixed_point(fixed_point x,fixed_point y)
{
  return x+y;
}

/**
subtract integer from fixedpoint x-n
*/
fixed_point sub_integer(fixed_point x,int n)
{
  return x-n*f;
}

/**
fixed point subtraction x-y
*/
fixed_point sub_fixed_point(fixed_point x,fixed_point y)
{
  return x-y;
}

/**
integer and fixed point multiplication x*n
*/
fixed_point mul_integer(fixed_point x,int n)
{
  return x*n;
}

/**
fixed point multiplication x*y
*/
fixed_point mul_fixed_point(fixed_point x,fixed_point y)
{
  return ((int64_t) x)*y /f
}

/**
divide fixed point by integer x/n
*/
fixed_point div_integer(fixed_point x,int n)
{
  return x/n;
}

/**
fixed point division x/y
*/
fixed_point div_fixed_point(fixed_point x,fixed_point y)
{
  return ((int64_t)x)*f/y;
}
