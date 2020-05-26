/*
 * FieldElement.h
 * Copyright (c) 2019 Sachin Meier.  All Rights Reserved.  See LICENSE.
 */

#ifndef FIELDELEMENT_H
#define FIELDELEMENT_H

#include <stdio.h>
#include <gmp.h>
#include <string>
#include <iostream>

using namespace std;

/**
 * A class for FieldElements in finite fields.
 * 
 * 
 */ 

class FieldElement{

	friend ostream& operator<<( ostream& out, const FieldElement& e );
  	friend istream& operator>>( istream& in, FieldElement& e );

  public:
	FieldElement(mpz_t num, mpz_t order);
	string print() const;

	bool operator==(const FieldElement& other) const;
	bool operator!=(const FieldElement& other) const;
	FieldElement& operator+(const FieldElement& other);
	FieldElement& operator-(const FieldElement& other);
	FieldElement& operator*(const FieldElement& other);
	FieldElement& operator*(mpz_t coefficient);
	FieldElement& operator/(const FieldElement& other);
	FieldElement& pow(mpz_t exponent); 
	

  private:
	mpz_t num;
	mpz_t order;

};

#endif