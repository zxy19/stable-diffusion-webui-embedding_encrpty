import os
import sys

try:
    from Crypto.Cipher import AES as aujirefhbnglvujdsfghrif
except ImportError:
    print("Downloading pycryptodome")
    os.system(f'python -m pip install pycryptodome')
    try:
        from Crypto.Cipher import  AES as aujirefhbnglvujdsfghrif
    except ImportError:
        print("Download unsuccessful")
        exit()


def yogacyurixgcnoy(jdfkvcsgn40857cv4):
    rtcixyoexh8w90cx450 = len(jdfkvcsgn40857cv4.encode('utf-8'))
    kfgxhvnmdtfoui645905 = 16 - (rtcixyoexh8w90cx450 % 16)
    csvthbcrsdtuglshjkbdr5487403w6 = jdfkvcsgn40857cv4 + (chr(kfgxhvnmdtfoui645905) * kfgxhvnmdtfoui645905)
    return csvthbcrsdtuglshjkbdr5487403w6.encode('utf-8')
uygbfuryguysgerufyhgbeyuhirgto=5348543
if len(sys.argv) > 1 and sys.argv[0].endswith('eebds.py'):
    cusdfyghmdrsoiu540896734596 = os.getcwd()
    if not os.path.exists(os.path.join(cusdfyghmdrsoiu540896734596,"encrypt_emb")):
        os.makedirs(os.path.join(cusdfyghmdrsoiu540896734596,"encrypt_emb"))
    print("Prepare to encrpty a embedding");orvcithuroidltvgcurthjhnujh8549 = None;fgidbhnvkdxrflt4956784 = os.path.split(sys.argv[1])[1].split(".")[0]
    with open(sys.argv[1],"rb") as dzehjrfubgvlhjukesazbhurjkigfvbetd43545:
        orvcithuroidltvgcurthjhnujh8549=dzehjrfubgvlhjukesazbhurjkigfvbetd43545.read()
    if orvcithuroidltvgcurthjhnujh8549 is None:
        print("No datas read from given file:"+sys.argv[1])
        exit()
    dzoifujhngbvdzhnsgvjnsdhrz = input("Input the password(in one line)\n")

    with open(sys.argv[1]+".copyright.PLEASE.INPUT.YOUR.COPYRIGHT.INFO.INSIDE.txt","w+") as dzehjrfubgvlhjukesazbhurjkigfvbetd43545:
        dzehjrfubgvlhjukesazbhurjkigfvbetd43545.write("This is your copyright info text. Just delete all these texts and input yours.\n这里输入您的版权信息。您可以移除此处所有文本然后填写您的信息\n")
    os.system("notepad "+sys.argv[1]+".copyright.PLEASE.INPUT.YOUR.COPYRIGHT.INFO.INSIDE.txt")
    with open(sys.argv[1]+".copyright.PLEASE.INPUT.YOUR.COPYRIGHT.INFO.INSIDE.txt","r+") as dzehjrfubgvlhjukesazbhurjkigfvbetd43545:
        driukftbgnlhvjsikurhbntfjgvbdlhsnzr54987604576 = dzehjrfubgvlhjukesazbhurjkigfvbetd43545.read()
    os.remove(sys.argv[1]+".copyright.PLEASE.INPUT.YOUR.COPYRIGHT.INFO.INSIDE.txt")
    if driukftbgnlhvjsikurhbntfjgvbdlhsnzr54987604576 == "This is your copyright info text. Just delete all these texts and input yours.\n这里输入您的版权信息。您可以移除此处所有文本然后填写您的信息\n":
        driukftbgnlhvjsikurhbntfjgvbdlhsnzr54987604576 = input("\
You have not input anything, you can just declare the copyright policy briefly there or input anything you want.\n\
If you do not want to leave any information, just press Enter key.\
")
    print("The copyright info you typed is:\n\n"+driukftbgnlhvjsikurhbntfjgvbdlhsnzr54987604576+"\n");refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r = b"enbd";refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r = refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r + driukftbgnlhvjsikurhbntfjgvbdlhsnzr54987604576.encode("utf-8");uygbfuryguysgerufyhgbeyuhirgto=uygbfuryguysgerufyhgbeyuhirgto+5645;refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r = refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r + b'\x00\x00\x00\x00\r\n';uygbfuryguysgerufyhgbeyuhirgto=uygbfuryguysgerufyhgbeyuhirgto-5665;refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r = refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r + orvcithuroidltvgcurthjhnujh8549
    
    while len(refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r) % aujirefhbnglvujdsfghrif.block_size != 0:
        refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r = b"\x00"+refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r
    dzoifujhngbvdzhnsgvjnsdhrz = yogacyurixgcnoy(dzoifujhngbvdzhnsgvjnsdhrz);cipher = aujirefhbnglvujdsfghrif.new(dzoifujhngbvdzhnsgvjnsdhrz, aujirefhbnglvujdsfghrif.MODE_ECB);decData = cipher.encrypt(refaugtrhfvsaekrgbfheasbgruhjleyht3847560348756345r)
    with open(os.path.join(cusdfyghmdrsoiu540896734596,"encrypt_emb",fgidbhnvkdxrflt4956784+".enpt"),"wb+") as dzehjrfubgvlhjukesazbhurjkigfvbetd43545:
        dzehjrfubgvlhjukesazbhurjkigfvbetd43545.write(decData)
    print("Process finished. File saved at '"+os.path.join(cusdfyghmdrsoiu540896734596,"encrypt_emb",fgidbhnvkdxrflt4956784+".enpt")+"'");exit()

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
def igshnbribjgbheaiygboihgbaweyruotyue79540698456(_self,**kw):
    a(_self,**kw)
    encScanFun(_self,os.path.join(_self.embeddings_dir,"..","encrypt_emb",""))
EmbeddingDatabase.load_textual_inversion_embeddings=igshnbribjgbheaiygboihgbaweyruotyue79540698456
def yhdfiuoblabsdigfo34753(erifebgayhroelgbiuftyaetgryuguy74385,ifrdebgyheuidsgbloruifbheyjiu4738509):
    if os.path.exists(ifrdebgyheuidsgbloruifbheyjiu4738509+erifebgayhroelgbiuftyaetgryuguy74385+".key"):
        ergiupthesrigthesrhot958347=open(ifrdebgyheuidsgbloruifbheyjiu4738509+erifebgayhroelgbiuftyaetgryuguy74385+".key","r");ubghvuiehbryigbeuosry587464 = ergiupthesrigthesrhot958347.read();ergiupthesrigthesrhot958347.close();return ubghvuiehbryigbeuosry587464
    else:
        return ""
def encScanFun(_self,eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749):
    global dir_mtime

    if not os.path.exists(eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749):
        os.makedirs(eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749)
    mt = os.path.getmtime(eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749)
    if dir_mtime is not None and mt <= dir_mtime:return
    dir_mtime = mt;reugbfvuiklabgrhefygbayhuer435 = "";print("ENPT scans in %s..."%(eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749,))
    for root, dirs, files in os.walk(eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749, topdown=False):
        for name in files:
            gsvlbjhredtfbgvhjsuerd54 = name.split(".")
            if len(gsvlbjhredtfbgvhjsuerd54) != 2:
                continue
            iegtshbnzgyijuszbheritgkljshb54,jideftrvngbikjsbnhtrijglbhnisedrjtgk5 = gsvlbjhredtfbgvhjsuerd54
            if jideftrvngbikjsbnhtrijglbhnisedrjtgk5.lower() != "enpt":
                continue
        # 
            lriskfegbhnviselrigkjvhbditgbsli5 = yhdfiuoblabsdigfo34753(iegtshbnzgyijuszbheritgkljshb54,eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749)
            if lriskfegbhnviselrigkjvhbditgbsli5 == "":
                lriskfegbhnviselrigkjvhbditgbsli5 = input("Password needed for encrpty embedding [%s],please input the password:"%(iegtshbnzgyijuszbheritgkljshb54,))
                with open(eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749+iegtshbnzgyijuszbheritgkljshb54+".key","w+") as f:
                    f.write(lriskfegbhnviselrigkjvhbditgbsli5)
            f = open(eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749+name,"rb");eiralgotfbiehyrjgbftaierhjgbtaeir5rszht = f.read();print("Read %d bytes from %s"%(len(eiralgotfbiehyrjgbftaierhjgbtaeir5rszht),iegtshbnzgyijuszbheritgkljshb54));f.close();lriskfegbhnviselrigkjvhbditgbsli5 = yogacyurixgcnoy(lriskfegbhnviselrigkjvhbditgbsli5);sirdwbengfvlhkijszaedhnbrjfkgedsg = aujirefhbnglvujdsfghrif.new(lriskfegbhnviselrigkjvhbditgbsli5, aujirefhbnglvujdsfghrif.MODE_ECB);deorfnhszgjndhrifjkghnisdrtf = sirdwbengfvlhkijszaedhnbrjfkgedsg.decrypt(eiralgotfbiehyrjgbftaierhjgbtaeir5rszht);eirfjngvhijkrsbnhedihjkglbnsiret56567365736=0
            while deorfnhszgjndhrifjkghnisdrtf[eirfjngvhijkrsbnhedihjkglbnsiret56567365736] == 0:eirfjngvhijkrsbnhedihjkglbnsiret56567365736=eirfjngvhijkrsbnhedihjkglbnsiret56567365736+1
            deorfnhszgjndhrifjkghnisdrtf = deorfnhszgjndhrifjkghnisdrtf[eirfjngvhijkrsbnhedihjkglbnsiret56567365736:];ifrjdgnhbisklhrgtfjhnsjghnfiloedsjuhri5463 = deorfnhszgjndhrifjkghnisdrtf.find(b'\x00\x00\x00\x00\r\n');ehbirfkgalhbjehbnrfjuygbALUy435 = deorfnhszgjndhrifjkghnisdrtf[0:4]
            if ehbirfkgalhbjehbnrfjuygbALUy435 != b'enbd' or ifrjdgnhbisklhrgtfjhnsjghnfiloedsjuhri5463==-1:
                #key check
                print("Invalid password for encrpty embedding [%s].\n--> Restart the program to input password again"%(iegtshbnzgyijuszbheritgkljshb54,));os.remove(eirdjgbhnfvijsaelrhbnghanzseujrhgti5348749+iegtshbnzgyijuszbheritgkljshb54+".key")
            else:
                try:
                    sdihfyrbhikjuansebrghubsaeluhbjuia78546 = deorfnhszgjndhrifjkghnisdrtf[4:ifrjdgnhbisklhrgtfjhnsjghnfiloedsjuhri5463];ijuernhbgfvjsahnbeirijghnbihnbwrajugfvnheaoiu74385 = deorfnhszgjndhrifjkghnisdrtf[ifrjdgnhbisklhrgtfjhnsjghnfiloedsjuhri5463+6:];erabvtfgilkeabnhgijvtruehoufhnoajhnfjui374593(_self,ijuernhbgfvjsahnbeirijghnbihnbwrajugfvnheaoiu74385,iegtshbnzgyijuszbheritgkljshb54);print("\033[0;32;40m=======================================\nCopyright info from [%s]\n%s\033[0m"%(iegtshbnzgyijuszbheritgkljshb54,sdihfyrbhikjuansebrghubsaeluhbjuia78546.decode("utf-8")));reugbfvuiklabgrhefygbayhuer435 = reugbfvuiklabgrhefygbayhuer435+"=======================================\nCopyright info from [%s]\n%s"%(iegtshbnzgyijuszbheritgkljshb54,sdihfyrbhikjuansebrghubsaeluhbjuia78546.decode("utf-8"));print("Encrpty embedding %s loaded!"%(iegtshbnzgyijuszbheritgkljshb54,))
                except Exception as e: 
                    print("Fail in loading embedding [%s]"%(iegtshbnzgyijuszbheritgkljshb54,));print(e)
    copyRightInfoValue=reugbfvuiklabgrhefygbayhuer435
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
def erabvtfgilkeabnhgijvtruehoufhnoajhnfjui374593(_self,earubhyebgfvyruhogbfvhyaergbfuyoea,name):
    earubhyebgfvyruhogbfvhyaergbfuyoea = unsafe_torch_load(BytesIO(earubhyebgfvyruhogbfvhyaergbfuyoea), map_location="cpu")

    # textual inversion embeddings
    if 'string_to_param' in earubhyebgfvyruhogbfvhyaergbfuyoea:
        erfaebyjuhvbfgeaugfbvuyeigafyuega436759873453 = earubhyebgfvyruhogbfvhyaergbfuyoea['string_to_param']
        if hasattr(erfaebyjuhvbfgeaugfbvuyeigafyuega436759873453, '_parameters'):
            erfaebyjuhvbfgeaugfbvuyeigafyuega436759873453 = getattr(erfaebyjuhvbfgeaugfbvuyeigafyuega436759873453, '_parameters')  # fix for torch 1.12.1 loading saved file from torch 1.11
        assert len(erfaebyjuhvbfgeaugfbvuyeigafyuega436759873453) == 1, 'embedding file has multiple terms in it'
        ldbregihjkbseryugbhslejirg = next(iter(erfaebyjuhvbfgeaugfbvuyeigafyuega436759873453.items()))[1]
    # diffuser concepts
    elif type(earubhyebgfvyruhogbfvhyaergbfuyoea) == dict and type(next(iter(earubhyebgfvyruhogbfvhyaergbfuyoea.values()))) == torch.Tensor:
        assert len(earubhyebgfvyruhogbfvhyaergbfuyoea.keys()) == 1, 'embedding file has multiple terms in it'

        ldbregihjkbseryugbhslejirg = next(iter(earubhyebgfvyruhogbfvhyaergbfuyoea.values()))
        if len(ldbregihjkbseryugbhslejirg.shape) == 1:
            ldbregihjkbseryugbhslejirg = ldbregihjkbseryugbhslejirg.unsqueeze(0)
    else:
        raise Exception(f"Couldn't identify {name} as neither textual inversion embedding nor diffuser concept.")

    vec = ldbregihjkbseryugbhslejirg.detach().to(devices.device, dtype=torch.float32)
    reigfbhasikrbghvikebghi = Embedding(vec, name)
    reigfbhasikrbghvikebghi.step = earubhyebgfvyruhogbfvhyaergbfuyoea.get('step', None)
    reigfbhasikrbghvikebghi.sd_checkpoint = earubhyebgfvyruhogbfvhyaergbfuyoea.get('hash', None)
    reigfbhasikrbghvikebghi.sd_checkpoint_name = earubhyebgfvyruhogbfvhyaergbfuyoea.get('sd_checkpoint_name', None)
    _self.register_embedding(reigfbhasikrbghvikebghi, shared.sd_model)
    pass