from cryptography import x509
from cryptography.hazmat.backends import default_backend
from PyKCS11 import *
from PyKCS11.LowLevel import *
from cryptography import x509
from cryptography.hazmat.primitives import serialization

pkcs11_lib = "<HSM_SO_File>"  # HSM PKCS#11 kütüphanesinin yolu
slot = 0  # HSM slot numarası
pin = "1111"  # HSM PIN değeri

pkcs11 = PyKCS11Lib()
pkcs11.load(pkcs11_lib)

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login(pin)

ca_cert_label = "privCAcrt"  # CA sertifikasının etiketi
ca_key_label = "priv"  # CA anahtarının etiketi

ca_cert = session.findObjects([(CKA_LABEL, ca_cert_label), (CKA_CLASS, CKO_CERTIFICATE)])[0]
ca_key = session.findObjects([(CKA_LABEL, ca_key_label), (CKA_CLASS, CKO_PRIVATE_KEY)])[0]

csr_file_path = "/app/priv.csr"  # İmzalanacak CSR dosyasının yolu

with open(csr_file_path, "rb") as csr_file:
    csr_data = csr_file.read()

mechanism = Mechanism(CKM_SHA256_RSA_PKCS)
signature = session.sign(ca_key, csr_data, mechanism)

signed_csr_data = csr_data + bytes(signature)

# İmzalı CSR'ı CRT formatına dönüştürme
csr = x509.load_pem_x509_csr(csr_data, default_backend())
crt = csr.public_bytes(encoding=serialization.Encoding.PEM)

crt_file_path = "/app/priv.crt"  # İmzalı CSR dosyasının CRT formatında kaydedileceği yol

with open(crt_file_path, "wb") as crt_file:
    crt_file.write(crt)

session.logout()
session.closeSession()
