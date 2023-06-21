from PyKCS11 import *
from PyKCS11.LowLevel import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.x509 import Name, CertificateBuilder
from cryptography import x509
import datetime
import base64
def CARequestCertificate(Slot_ID,Slot_PIN,PrivateKeyName,CommonName,OrganizationName,CountryName):
    # PKCS#11 modülünün yolunu belirtin
    pkcs11_lib = "<HSM_SO_File>"
    # HSM slotunu seçin
    slot = Slot_ID
    # PIN değerini belirtin
    pin = Slot_PIN
    # Private key etiketini belirtin
    private_key_label = PrivateKeyName
    # CA sertifikası için gerekli bilgileri belirtin
    common_name = CommonName
    organization_name = OrganizationName
    country_name = CountryName
    # PKCS#11 bağlantısını oluşturun
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib)
    # HSM cihazına bağlanın
    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    session.login(pin)
    # Private key'i bulun
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
    # CA sertifikasını oluşturun
    subject = Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name)
    ])
    builder = CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(private_key.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    ca_cert = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256()
    )
    # CA sertifikasını CRT formatına dönüştürme
    ca_cert_bytes = ca_cert.public_bytes(encoding=serialization.Encoding.DER)
    ca_cert_crt = base64.b64encode(ca_cert_bytes).decode("utf-8")

    # CA sertifikasını dosyaya yazdırma
    FileNames = PrivateKeyName + "CA.crt"
    with open(FileNames, "w") as file:
        file.write("-----BEGIN CERTIFICATE-----\n")
        file.write(ca_cert_crt)
        file.write("\n-----END CERTIFICATE-----\n")

    # HSM bağlantısını kapatın
    session.logout()
    session.closeSession()
    return FileNames

#Slot_ID = 0
#Slot_PIN ="1111"
#PrivateKeyName = "priv"
#CommonName = "Procenne"
#OrganizationName = "Procenne"
#CountryName = "TR"

#CARequestCertificate(Slot_ID,Slot_PIN,PrivateKeyName,CommonName,OrganizationName,CountryName)
