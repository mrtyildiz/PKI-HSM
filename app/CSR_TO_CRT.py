from PyKCS11 import *
from OpenSSL import crypto

pkcs11_lib = "<HSM_SO_File>"  # HSM PKCS#11 kütüphanesinin yolu
slot = 0  # HSM slot numarası
pin = "1111"  # HSM PIN değeri

pkcs11 = PyKCS11Lib()
pkcs11.load(pkcs11_lib)

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login(pin)

# CSR dosyasını yükleme
csr_file = 'priv.csr'  # CSR dosyasının yolunu belirtin
with open(csr_file, 'r') as f:
    csr_data = f.read()

# CA pem dosyasını yükleme
ca_file = 'ca_certificate.pem'  # CA pem dosyasının yolunu belirtin
with open(ca_file, 'r') as f:
    ca_data = f.read()

# CSR'ı OpenSSL nesnesine dönüştürme
csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)

# CA sertifikasını yükleyerek özel anahtarı alın
ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_data)
private_key_slot = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),
                                        (CKA_LABEL, "priv")])[0]
private_key = session.getAttributeValue(private_key_slot, [CKA_VALUE])[0]

# HSM'den alınan özel anahtarı PKey nesnesine dönüştürme
pkey = crypto.PKey()
pkey.import_key(private_key)

# Sertifika oluşturma
cert = crypto.X509()
cert.set_subject(csr.get_subject())
cert.set_pubkey(csr.get_pubkey())
cert.set_serial_number(12345)  # Sertifika seri numarasını istediğiniz şekilde belirleyin
cert.gmtime_adj_notBefore(0)  # Sertifika başlangıç tarihini istediğiniz şekilde ayarlayın
cert.gmtime_adj_notAfter(31536000)  # Sertifika bitiş tarihini istediğiniz şekilde ayarlayın
cert.set_issuer(ca_cert.get_subject())
cert.sign(pkey, "sha256")

# Sertifikayı PEM formatına dönüştürme
cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

# Sertifikayı dosyaya yazma
output_file = 'certificate.pem'  # Çıktı sertifikasının yolunu belirtin
with open(output_file, 'w') as f:
    f.write(cert_pem)

# HSM cihazından çıkış yapma
session.logout()
session.close()

print("Sertifika oluşturma işlemi tamamlandı.")
