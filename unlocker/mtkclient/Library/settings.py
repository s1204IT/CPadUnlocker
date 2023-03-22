import json
import os.path
from binascii import hexlify

class hwparam:
    paramsetting = None
    hwcode = None

    def __init__(self, meid:str, path:str="logs"):
        self.paramfile = "hwparam.json"
        self.hwparampath = path
        if isinstance(meid,bytearray) or isinstance(meid,bytes):
            meid=hexlify(meid).decode('utf-8')
        if meid is None:
            self.paramsetting = {}
            if meid is not None:
                self.paramsetting["meid"] = meid
                if not os.path.exists(self.hwparampath):
                    os.mkdir(self.hwparampath)
                open(os.path.join(path,self.paramfile), "w").write(json.dumps(self.paramsetting))
        else:
            self.paramsetting = {}
            if os.path.exists(os.path.join(path,self.paramfile)):
                try:
                    self.paramsetting = json.loads(open(os.path.join(path,self.paramfile), "r").read())
                except:
                    #json file invalid, load nothing.
                    pass



    def loadsetting(self,key:str):
        if self.paramsetting is not None:
            if key in self.paramsetting:
                return self.paramsetting[key]
        return None

    def writesetting(self, key:str,value:str):
        if self.paramsetting is not None:
            self.paramsetting[key]=value
            self.write_json()

    def write_json(self):
        if self.paramsetting is not None:
            if not os.path.exists(self.hwparampath):
                os.mkdir(self.hwparampath)
            open(os.path.join(self.hwparampath,self.paramfile), "w").write(json.dumps(self.paramsetting))
