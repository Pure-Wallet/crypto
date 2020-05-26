#ifndef FIELDELEMENT_H
#define FIELDELEMENT_H

#include <stdio.h>
#include <gmp.h>
#include <string>
#include <iostream>
#include "FieldElement.h"

using namespace std;

class Point{

	friend ostream& operator<<( ostream& out, const Point& e );
  	friend istream& operator>>( istream& in, Point& e );

  public:
	Point(mpz_t x, mpz_t y, mpz_t a, mpz_t b);
	Point(FieldElement x, FieldElement y, FieldElement a, FieldElement b);



  private:
	mpz_t x;
	mpz_t y;
	mpz_t a;
	mpz_t b;
	FieldElement x;
	FieldElement y;
	FieldElement a;
	FieldElement b;

};



#endif