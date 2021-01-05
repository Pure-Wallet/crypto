# Wallet

This Folder will contain the cryptography libraries for the wallet. I am currently learning from<a href="https://github.com/jimmysong/programmingbitcoin"> Jimmy Song's Programming Bitcoin book</a>. The book is written for Python, so I am coding in Python, but I plan on translating to C++ for the wallet. 

What will be in here:
<ol>
<li>ECDSA Curve - secp256k1 </li>
<li>Key Generation</li>
<li>Transaction crafting<li>
<li>Signatures</li>
<ol>
<li>Verification</li>
<li>Signing</li>
</ol>
<li>Scripting<li>
</ol>

<h2>ECDSA:</h2>
<h4>FieldElement</h4>
Allows for Modulo arithmetic and finite field math. A FieldElement has a number and a prime number denoting the order of the finite field. Operators are overloaded for addition, subtraction, multiplication, scalar multiplication, and exponentiation. Subclassed with S256Field.

<h4>Point</h4>
Allows for creation of Elliptic curves, with equation y^2 = x^3 + a*x + b. a and b are passed in along with the x and y coordinates of the Point. If the Point (x,y) is not on the curve, an error is thrown. These Points also can be added, multiplied, and exponentiated. Subclassed with S256Point.

<h4>S256Field</h4>
A FieldElement with order P=2**256 - 2**32 - 977, the prime number for Bitcoin.

<h4>S256Point</h4>
A Point with equation y^2 = x^3 + 7. a=0, b=7. A Constant S256Point G is defined, which is the Generator Point for Bitcoin.
A PubKey is an object in this class, and the verify method verifies a signature with a hash and itself.

<h4>Signature</h4>
A Signature class has two components, r and s. Used by PrivateKey. Serialization is included here.

<h4>Private Key</h4>
A class that stores a secret number, which is multiplied by the G Point to get the public key (an S256Point). Used to Sign messages.