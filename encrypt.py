import numpy as np
from numpy.polynomial import polynomial as poly
import rlwe_he_scheme_updated as rlwe_updated
import struct
import pickle 
from pathlib import Path

#polynomial modulus degree
n = 2 ** 2
# ciphertext modulus
q = 2 ** 14
# plaintext modulus
t = 2
# base for relin_v1
T = int(np.sqrt(q))
# modulus switching modulus
p = q ** 3
# polynomial modulus
poly_mod = np.array([1] + [0] * (n - 1) + [1])

# standard deviation for the error in the encryption
std1 = 1
# standard deviation for the error in the evaluateKeyGen_v2
std2 = 1

#generating polynomials for an example 
polynomials =[
	rlwe_updated.gen_binary_poly(n),
	rlwe_updated.gen_binary_poly(n)
	]
print("Generated")
print(polynomials)

#this section is to emulate if a client had data and serialized the data 
with open("polys.bin","wb") as f:
	f.write(struct.pack("I", len(polynomials)))
	
	for poly in polynomials:
		f.write(struct.pack("I", len(poly)))
		
		f.write(poly.tobytes())
		
print("serialized")


#client system
#deserializing
loaded=[]

with open("polys.bin", "rb")as f:
	count= struct.unpack("I",f.read(4))[0]
	
	for _ in range(count):
		length=struct.unpack("I", f.read(4))[0]
		
		raw = f.read(length * 8)
		poly=np.frombuffer(raw, dtype=np.int64)
		loaded.append(poly)
print(loaded)

pt1= loaded[0]
pt2= loaded[1]

ct1 = (loaded[0], loaded[1])

print(pt1)
print(pt2)

pypoly=pt1.tolist()
pypoly2=pt2.tolist()


# Keygen
pk, sk = rlwe_updated.keygen(n, q, poly_mod, std1)

# EvaluateKeygen_version1
rlk0, rlk1= rlwe_updated.evaluate_keygen_v1(sk, n, q, T, poly_mod, std1)

print("key generated")

#encryption

ct1 = rlwe_updated.encrypt(pk, n, q, t, poly_mod, pypoly, std1)
ct2 = rlwe_updated.encrypt(pk, n, q, t, poly_mod, pypoly2, std1)

print(ct1)
print(ct2)

#serialize encrypted text 

enc=[ct1,ct2]

with open("enc.bin", "wb") as f:
	f.write(struct.pack("I", len(enc)))
	
	for ct in enc:
		f.write(struct.pack("I", len(ct)))
		
		for poly in ct:
			poly= np.array(poly, dtype=np.int64)	
			f.write(struct.pack("I", len(poly)))	
			f.write(poly.tobytes())

#server system 

#deserialization
loaded=[]

with open("enc.bin", "rb") as f:
	count= struct.unpack("I", f.read(4))[0]
	for _ in range(count):
		poly_count = struct.unpack("I", f.read(4))[0]
		
		ct=[]
		
		for _ in range(poly_count):
			length= struct.unpack("I",f.read(4))[0]
			
			raw= f.read(length * 8)
			
			poly = np.frombuffer(raw, dtype=np.int64)
			
			ct.append(poly)
			
		loaded.append(tuple(ct))
ct1=loaded[0]
ct2=loaded[1]

print(ct1)
print(ct2)


#homomorphic addition or multiplication
choose= input("Do you want to add or multiply? (+/*): ").strip().lower()

if choose in "+":
	ct3= rlwe_updated.add_cipher(ct1, ct2, q, poly_mod)
	np.save("ct3.npy", ct3)
	print("serialized")
elif choose in "*":
	ct4= rlwe_updated.mul_cipher_v1(ct1, ct2, q, t, T, poly_mod , rlk0, rlk1)
	np.save("ct4.npy", ct4)
	print("serialized")
	

else:
	print("Error")
		
	
	
#client system once the encrypted values are sent from the server 
	
choice = input("Do you want to decrypt the message? (y/n): ").strip().lower()
	
if choice == "y":
	ct_path= None

	if Path("ct3.npy").exists():
		ct_path = "ct3.npy"
		
	elif Path("ct4.npy").exists():
		ct_path= "ct4.npy"
	else:
		raise FileNotFoundError("File not Found")
	
	ct= np.load(ct_path, allow_pickle=True)
	if ct is None:
		raise FileNotFoundError("Error.")
	
	if isinstance(ct, np.ndarray) and ct.dtype == object:
		ct = ct.tolist()
	pt= rlwe_updated.decrypt(sk, n, q, t, poly_mod, ct)
	print(pt)

elif choice == "n":
	print("Values are stored")	
else:
	print("Invalid input.")
		
	
	



	

	





