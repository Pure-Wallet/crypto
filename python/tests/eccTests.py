import unittest
from src.ecc import *


class PointTest(unittest.TestCase):
	def test_ne(self):
		a = Point(3,-7,5,7)
		b = Point(18,77,5,7)
		self.assertTrue(a != b)
		self.assertFalse(a != b)

	def test_on_curve(self):
		with self.assertRaises(ValueError):
			Point(-2,4,5,7)
		Point(3,-7,5,7)
		Point(18,77,5,7)
	
	def test_add0(self):
		a = Point(x=None, y=None, a=5, b=7)
		b = Point(2, 5, 5, 7)
		c = Point(2, -5, 5, 7)
		self.assertEqual(a + b, b)
		self.assertEqual(b + a, b)
		self.assertEqual(b + c, a)

	def test_add1(self):
		a = Point(x=3, y=7, a=5, b=7)
		b = Point(x=-1, y=-1, a=5, b=7)
		self.assertEqual(a + b, Point(x=2, y=-5, a=5, b=7))
	
	def test_add2(self):
		a = Point(x=-1, y=1, a=5, b=7)
		self.assertEqual(a + a, Point(x=18, y=-77, a=5, b=7))

class ECCTest(unittest.TestCase):
	def test_on_curve(self):
		prime = 223
		a = FieldElement(0,prime)
		b = FieldElement(7,prime)
		valid = ((192,105),(17,56), (1,193))
		invalid = ((200,119), (42,99))
		for x_raw, y_raw in valid:
			x = FieldElement(x_raw, prime)
			y = FieldElement(y_raw, prime)
			Point(x,y,a,b)
		for x_raw, y_raw in invalid:
			x = FieldElement(x_raw, prime)
			y = FieldElement(y_raw, prime)
			with self.assertRaises(ValueError):
				Point(x,y,a,b)


	def test_add(self):
		prime = 223
		a = FieldElement(0,prime)
		b = FieldElement(7,prime)
		x1 = (192,47,143)
		x2 = (17,117,76)		
		y1 = (105,71,98)
		y2 = (56,141,66)
		x3 = (170,60,47)
		y3 = (142,139,71)
		for x in range(3):
			p1 = Point(FieldElement(x1[x], prime), FieldElement(y1[x], prime), a, b)
			p2 = Point(FieldElement(x2[x], prime), FieldElement(y2[x], prime), a, b)
			p3 = Point(FieldElement(x3[x], prime), FieldElement(y3[x], prime), a, b)
			self.assertEqual(p3, p1+p2)

class S256Test(unittest.TestCase):

	def test_order(self):
		point = N * G
		self.assertIsNone(point.x)

	def test_pubpoint(self):
		points = (
			# secret, x, y
			(7, 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc, 0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da),
			(1485, 0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda, 0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55),
			(2**128, 0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da, 0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82),
			(2**240 + 2**31, 0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116, 0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053),
		)
		for secret, x, y in points:
			point = S256Point(x,y)
			self.assertEqual(secret * G, point)

class PrivateKeyTest(unittest.TestCase):
    def test_sign(self):
        pk = PrivateKey(randint(0, N))
        z = randint(0, 2**256)
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))


if __name__ == "__main__":
	unittest.main()