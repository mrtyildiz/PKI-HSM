from pyhsm.hsmclient import HsmClient


def Get_Handler(Slot_ID,Slot_PIN,KName):
   with HsmClient(slot=Slot_ID, pin=Slot_PIN, pkcs11_lib="<HSM_SO_File>") as c:
     handle = c.get_object_handle(label=KName)
     Str_Handler = str(handle)
     return Str_Handler


