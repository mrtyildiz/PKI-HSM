from PyKCS11 import *
from PyKCS11.LowLevel import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.x509 import NameAttribute, CertificateSigningRequestBuilder
from cryptography import x509
# PKCS#11 modülünün yolunu belirtin
def RequestCertificate(Slot_ID,Slot_PIN,PrivKeyName,CommonName,serial_number,country_name):
    pkcs11_lib = "<HSM_SO_File>"
    slot = Slot_ID
    pin = Slot_PIN
    private_key_label = PrivKeyName
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib)
    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    session.login(pin)
    private_key_template = [
        (CKA_LABEL, private_key_label),
        (CKA_CLASS, CKO_PRIVATE_KEY)
    ]
    private_key = session.findObjects(private_key_template)[0]

    # Modulus ve public exponent değerlerini alın
    modulus = session.getAttributeValue(private_key, [CKA_MODULUS])[0]
    public_exponent = session.getAttributeValue(private_key, [CKA_PUBLIC_EXPONENT])[0]

    # RSA anahtarını oluşturun
    private_numbers = rsa.RSAPrivateNumbers(
        p=int.from_bytes(session.getAttributeValue(private_key, [CKA_PRIME_1])[0], byteorder="big"),
        q=int.from_bytes(session.getAttributeValue(private_key, [CKA_PRIME_2])[0], byteorder="big"),
        d=int.from_bytes(session.getAttributeValue(private_key, [CKA_PRIVATE_EXPONENT])[0], byteorder="big"),
        dmp1=int.from_bytes(session.getAttributeValue(private_key, [CKA_EXPONENT_1])[0], byteorder="big"),
        dmq1=int.from_bytes(session.getAttributeValue(private_key, [CKA_EXPONENT_2])[0], byteorder="big"),
        iqmp=int.from_bytes(session.getAttributeValue(private_key, [CKA_COEFFICIENT])[0], byteorder="big"),
        public_numbers=rsa.RSAPublicNumbers(
            e=int.from_bytes(public_exponent, byteorder="big"),
            n=int.from_bytes(modulus, byteorder="big")
        )
    )
    private_key = private_numbers.private_key()
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CommonName),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
    ]))
    csr = csr_builder.sign(private_key, hashes.SHA256())

    # CSR'ı PEM formatına dönüştürme
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    fileName = str(PrivKeyName)+".csr"
    with open(fileName, "wb") as file:
        file.write(csr_pem)
    # HSM bağlantısını kapatın
    session.logout()
    session.closeSession()
    return fileName

#Slot_ID = 0
#Slot_PIN = "1111"
#PrivKeyName = "priv"
#CommonName = "Example"
#serial_number = "12848492"
#country_name = "TR"
#RequestCertificate(Slot_ID,Slot_PIN,PrivKeyName,CommonName,serial_number,country_name)
