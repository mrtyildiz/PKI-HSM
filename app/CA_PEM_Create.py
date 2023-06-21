from PyKCS11 import *
from PyKCS11.LowLevel import *
import base64
import binascii

lib = '<HSM_SO_File>'  # HSM kütüphanesinin yolunu güncelleyin
pkcs11 = PyKCS11Lib()
pkcs11.load(lib)


slot = pkcs11.getSlotList()[0]  # HSM cihazının yuvasını seçin
session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)  # Oturum açın

ca_cert_label = 'ProcenneprivCA'  # CA sertifikasının etiketini belirtin
ca_cert = session.findObjects([
    (CKA_LABEL, ca_cert_label),
    (CKA_CLASS, CKO_CERTIFICATE)
])[0]

cert_der = session.getAttributeValue(ca_cert, [CKA_VALUE])[0]  # DER formatında sertifika değerini alın
cert_der_bytes = bytes(cert_der)
#print(cert_der)
cert_pem = '-----BEGIN CERTIFICATE-----\n'
cert_pem += base64.b64encode(cert_der_bytes).decode('ascii')
cert_pem += '\n-----END CERTIFICATE-----'
#print(cert_pem)
# PEM dosyasını kaydetme
with open('ca_certificate.pem', 'w') as pem_file:
    pem_file.write(cert_pem)


session.closeSession()  # Oturumu kapatı
