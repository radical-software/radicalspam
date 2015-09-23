from numpy.testing import *

from numpy import *

class test_reshape(NumpyTestCase):
    def check_shape(self):

	def reshaped_shape_ok(os, ns):
	    assert zeros(os,int).reshape(ns).shape == ns
	
	reshaped_shape_ok((1000,), (20,50))
	reshaped_shape_ok((20,50), (20,50))
	reshaped_shape_ok((10,), (1,10))
	reshaped_shape_ok((10,), (10,1))
	reshaped_shape_ok((10,), (1,10,1))
	reshaped_shape_ok((1,10), (10,))
	reshaped_shape_ok((1,10), (10,1))
	reshaped_shape_ok((1,10,1), (10,))
	reshaped_shape_ok((2,5), (5,2))
	reshaped_shape_ok((2,1,5), (5,2,1))
	reshaped_shape_ok((1,2,1,5), (5,2,1))

    def check_nocopy(self):
	def copy_p(oldshape,newshape,oldstrides=None,order='C'):
	    if oldstrides is None:
		z = zeros(oldshape,int)
	    else:
		n = add.reduce(multiply(oldshape,oldstrides))
		z1 = zeros(n,int)
		z = ndarray.__new__(ndarray, shape=oldshape, dtype=int, buffer=z1, offset=0, strides=oldstrides)
	    r = z.reshape(newshape,order=order)
	    r.flat[0] = 1
	    return not z.flat[0]
	
	assert not copy_p((10,),(10,))
	assert not copy_p((10,),(2,5))
	assert not copy_p((2,5),(5,2))
	assert not copy_p((2,5),(5,2), oldstrides=(40,8))
	assert not copy_p((7,2,5),(7,5,2), oldstrides=(90,40,8))

	assert not copy_p((7,1,2,5),(7,5,1,2), oldstrides=(90,17,40,8))



if __name__ == "__main__":
        NumpyTest().run()
	
