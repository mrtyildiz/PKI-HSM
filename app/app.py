from fastapi import FastAPI
from pydantic import BaseModel
from KeyCreate import RSA_Create
from Get_Handler import Get_Handler
from Certificate_Request import RequestCertificate
from CA_Certificate_Request import CARequestCertificate

app = FastAPI()

class RSA(BaseModel):
    ID: int
    PIN: str
    KName: str
class Request(BaseModel):
    Slot_ID: int
    Slot_PIN: str
    PrivKeyName: str
    CommonName: str
    serial_number: str
    country_name: str

class CARequest(BaseModel):
    Slot_ID: int
    Slot_PIN: str
    PrivateKeyName: str
    CommonName: str
    OrganizationName: str
    CountryName: str

class CertificateLoad(BaseModel):
    SlotID: int
    SlotPIN: str
    CertificateFile: str
    CertificateName: str


@app.post("/RSACreate/")
def RSACreate(data: RSA):
    # Gelen verileri kullanarak kaydetme işlemini gerçekleştirin
    Slot_ID = data.ID
    Slot_PIN = data.PIN
    KeyName = data.KName
    RSA_Create(Slot_ID,Slot_PIN,KeyName)
    # Burada verileri dosyaya, veritabanına veya başka bir yere kaydedebilirsiniz

    return {"message": "Veriler başarıyla kaydedildi."}

@app.post("/Handler/")
def Handler(data: RSA):
    # Gelen verileri kullanarak kaydetme işlemini gerçekleştirin
    Slot_ID = data.ID
    Slot_PIN = data.PIN
    KeyName = data.KName
    str_handler = Get_Handler(Slot_ID,Slot_PIN,KeyName)
    # Burada verileri dosyaya, veritabanına veya başka bir yere kaydedebilirsiniz
    return {"Handler": str_handler}

@app.post("/RequestCertificate/")
def CertificateRequest(data: Request):
    ID = data.Slot_ID
    PIN = data.Slot_PIN
    PrivName = data.PrivKeyName
    CName = data.CommonName
    SerialNumber = data.serial_number
    CountryName = data.country_name
    CSR_FileName = RequestCertificate(ID,PIN,PrivName,CName,SerialNumber,CountryName)
    return {"Oluşturulan Dosya: ": CSR_FileName}

@app.post("/CARequest/")
def CARequest(data: CARequest):
    ID = data.Slot_ID
    PIN = data.Slot_PIN
    PrivName = data.PrivateKeyName
    CommonName = data.CommonName
    OrganizationName = data.OrganizationName
    CountryName = data.CountryName
    CA_Files = CARequestCertificate(ID,PIN,PrivName,CommonName,OrganizationName,CountryName)
    return {"CA sertifikası oluşturulmuştur: ": CA_Files}

@app.post("/LoadCertificate/")
def LoadCertificate(data: CertificateLoad):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    CertificateFile = data.CertificateFile
    CertificateName = data.CertificateName
    Certificate_Load(SlotID,SlotPIN,CertificateFile,CertificateName)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
