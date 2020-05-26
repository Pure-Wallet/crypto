#include "FieldElement.h"

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
	