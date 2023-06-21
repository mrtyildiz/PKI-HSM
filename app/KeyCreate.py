from pyhsm.hsmclient import HsmClient

### RSA Anahtar oluşturma işlemi
def RSA_Create(Slot_ID,Slot_PIN,KeyName):
   with HsmClient(slot=Slot_ID, pin=Slot_PIN, pkcs11_lib="<HSM_SO_File>") as c:
     PubKeyName = KeyName+"pub"
     PriKeyName = KeyName+"priv"
     key_handles = c.create_rsa_key_pair(public_key_label=PubKeyName,
                                      private_key_label=PriKeyName,
                                      key_length=2048,
                                      public_exponent=b"\x01\x00\x01",
                                      token=True,
                                      modifiable=False,
                                      extractable=False,
                                      sign_verify=True,
                                      encrypt_decrypt=True,
                                      wrap_unwrap=True,
                                      derive=False)
     print(dir(key_handles))
     print("public_handle: " + str(key_handles[0]))
     print("private_handle: " + str(key_handles[1]))

#ID = 0
#PIN ="1111"
#KName = "dene"
#RSA_Create(ID,PIN,KName)
