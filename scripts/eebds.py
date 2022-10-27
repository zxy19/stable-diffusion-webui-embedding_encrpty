import os
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    print("Downloading pycryptodome")
    os.system(f'python -m pip install pycryptodome')
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("Download unsuccessful")
        exit()


def pad(text):
    """
    #填充函数，使被加密数据的字节码长度是block_size的整数倍
    # refer:https://blog.csdn.net/weixin_38819889/article/details/123642201
    """
    count = len(text.encode('utf-8'))
    add = 16 - (count % 16)
    entext = text + (chr(add) * add)
    return entext.encode('utf-8')

if len(sys.argv) > 1 and sys.argv[0].endswith('eebds.py'):
    pathD = os.getcwd()
    if not os.path.exists(os.path.join(pathD,"encrypt_emb")):
        os.makedirs(os.path.join(pathD,"encrypt_emb"))
    print("Prepare to encrpty a embedding")
    data = None
    fileName = os.path.split(sys.argv[1])[1].split(".")[0]
    with open(sys.argv[1],"rb") as f:
        data=f.read()
    if data is None:
        print("No datas read from given file:"+sys.argv[1])
        exit()
    psw = input("Input the password(in one line)\n")
    copyrightData = input("Input the copyright info(in one line)\n")
    tmpdata = b"enbd"
    tmpdata = tmpdata + copyrightData.encode("utf-8")
    tmpdata = tmpdata + b'\x00\x00\x00\x00\r\n'
    tmpdata = tmpdata + data
    
    while len(tmpdata) % AES.block_size != 0:
        tmpdata = b"\x00"+tmpdata
    psw = pad(psw)
    cipher = AES.new(psw, AES.MODE_ECB)
    decData = cipher.encrypt(tmpdata)
    with open(os.path.join(pathD,"encrypt_emb",fileName+".enpt"),"wb+") as f:
        f.write(decData)
    print("Process finished. File saved at '"+os.path.join(pathD,"encrypt_emb",fileName+".enpt")+"'")
    exit()

#Main codes to inject into the main program
from modules.processing import Processed
import modules.shared as shared
from modules.textual_inversion.textual_inversion import Embedding,EmbeddingDatabase
import modules.devices as devices
import torch
from io import BytesIO
from modules.safe import unsafe_torch_load
import modules.scripts as scripts
import gradio as gr
copyRightInfoValue = ""
dir_mtime = None
print("Encrpty embedding loader is enabled\nNOTICE:This script may cause some problem when you use the RESTART GRADIO function in settings panel.AVOID USING IT")  
a=EmbeddingDatabase.load_textual_inversion_embeddings
def hackedEmbeddingF(_self,**kw):
    a(_self,**kw)
    encScanFun(_self,os.path.join(_self.embeddings_dir,"..","encrypt_emb",""))
EmbeddingDatabase.load_textual_inversion_embeddings=hackedEmbeddingF
def getpsw(name,enpath):
    if os.path.exists(enpath+name+".key"):
        f=open(enpath+name+".key","r")
        ktmp = f.read()
        f.close()
        return ktmp
    else:
        return ""
def encScanFun(_self,enpath):
    global dir_mtime

    if not os.path.exists(enpath):
        os.makedirs(enpath)

    mt = os.path.getmtime(enpath)
    if dir_mtime is not None and mt <= dir_mtime:
        return
    dir_mtime = mt
    resInfo = ""
    print("ENPT scans in %s..."%(enpath,))
    for root, dirs, files in os.walk(enpath, topdown=False):
        for name in files:
            _namesp = name.split(".")
            if len(_namesp) != 2:
                continue
            ebdName,ebdType = _namesp
            if ebdType.lower() != "enpt":
                continue
        # 
            psw = getpsw(ebdName,enpath)
            if psw == "":
                psw = input("Password needed for encrpty embedding [%s],please input the password:"%(ebdName,))
                with open(enpath+ebdName+".key","w+") as f:
                    f.write(psw)

            
            f = open(enpath+name,"rb")
            bindata = f.read()
            print("Read %d bytes from %s"%(len(bindata),ebdName))
            f.close()

            psw = pad(psw)
            cipher = AES.new(psw, AES.MODE_ECB)
            decData = cipher.decrypt(bindata)
            unpadlen=0
            while decData[unpadlen] == 0:unpadlen=unpadlen+1
            decData = decData[unpadlen:]
            infoSplPos = decData.find(b'\x00\x00\x00\x00\r\n')
            decHeader = decData[0:4]
            if decHeader != b'enbd' or infoSplPos==-1:
                #key check
                print("Invalid password for encrpty embedding [%s].\n--> Restart the program to input password again"%(ebdName,))
                os.remove(enpath+ebdName+".key")
            else:
                try:
                    headerText = decData[4:infoSplPos]
                    bodyData = decData[infoSplPos+6:]
                    process_file_raw(_self,bodyData,ebdName)

                    print("\033[0;32;40m=======================================\nCopyright info from [%s]\n%s\033[0m"%(ebdName,headerText.decode("utf-8")))
                    resInfo = resInfo+"=======================================\nCopyright info from [%s]\n%s"%(ebdName,headerText.decode("utf-8"))
                    print("Encrpty embedding %s loaded!"%(ebdName,))
                except Exception as e: 
                    print("Fail in loading embedding [%s]"%(ebdName,))
                    print(e)
    copyRightInfoValue=resInfo
class Script(scripts.Script):
    def __init__(self) -> None:
        super().__init__()

    def title(self):
        return "Load Encrypt Embeddings"

    def show(self, is_img2img):
        return True#cmd_opts.allow_code

    def ui(self, is_img2img):
        self.copyRightInfo = gr.TextArea(label="The copyright info output", visible=True,value=copyRightInfoValue)
        return [self.copyRightInfo]
    def run(self, p):
        return Processed(p)
def process_file_raw(_self,data,name):
    data = unsafe_torch_load(BytesIO(data), map_location="cpu")

    # textual inversion embeddings
    if 'string_to_param' in data:
        param_dict = data['string_to_param']
        if hasattr(param_dict, '_parameters'):
            param_dict = getattr(param_dict, '_parameters')  # fix for torch 1.12.1 loading saved file from torch 1.11
        assert len(param_dict) == 1, 'embedding file has multiple terms in it'
        emb = next(iter(param_dict.items()))[1]
    # diffuser concepts
    elif type(data) == dict and type(next(iter(data.values()))) == torch.Tensor:
        assert len(data.keys()) == 1, 'embedding file has multiple terms in it'

        emb = next(iter(data.values()))
        if len(emb.shape) == 1:
            emb = emb.unsqueeze(0)
    else:
        raise Exception(f"Couldn't identify {name} as neither textual inversion embedding nor diffuser concept.")

    vec = emb.detach().to(devices.device, dtype=torch.float32)
    embedding = Embedding(vec, name)
    embedding.step = data.get('step', None)
    embedding.sd_checkpoint = data.get('hash', None)
    embedding.sd_checkpoint_name = data.get('sd_checkpoint_name', None)
    _self.register_embedding(embedding, shared.sd_model)
    pass