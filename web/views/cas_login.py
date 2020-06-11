#!/usr/bin/env python3
# coding: utf-8

import time
import requests
import json
from Crypto.PublicKey import RSA
# 用的是这个库 https://pycryptodome.readthedocs.io/en/latest/src/installation.html
# pip install pycryptodome
from base64 import b64decode as d64, b64encode as e64
import math

url = "http://100.119.192.240:8080/cas"
user = "723488"
password = "123"
systemCode = "EOS-TDOP-CORE"
device = int(time.time())
cas_url = "http://cas.sit.sf-express.com/cas"
api = {
    'key': cas_url + '/app/getkey',
    'login': cas_url + '/app/gwlogin',
    'validate': cas_url + '/app/ticketValidate',
}
login_param = {
    'appName': systemCode,  # 系统编码
    'username': user,  # 用户名
    'password': password,  # 密码
    'device': device,  # 不确定可以填写时间戳
}
valid_param = {
    'tgt': '',
    'device': device
}
R = requests.Session()


def get_key():
    req = R.post(api['key'])
    out(req.text)
    ret = req.json()
    if not ret.get('success'):
        raise Exception('Get Key Failed!')
    return ret['keyid'], ret['publickey']


def login(kid, pkey, log_param):
    param = json.dumps(log_param)
    out(param)
    #public_key = RSA.import_key(d64(pkey))
    #data = do_rsa(param.encode(encoding='utf-8'), public_key.e, public_key.n)
    data = do_rsa(pkey, param)
    out(data)
    h = {'keyid': kid, 'Content-Type': 'application/octet-stream'}
    #req = R.post(api['login'], headers=h, data=data, proxies={'http':'http://127.0.0.1:8888'})
    req = R.post(api['login'], headers=h, data=data)
    out(req.text)
    ret = req.json()
    return ret['tgt']


def validate(tgt):
    p = valid_param.copy()
    p['tgt'] = tgt
    param = json.dumps(p)
    req = R.post(api['validate'], data=param)
    #out(param)
    #out(req.text)
    return json.loads(req.text)


def out(*args, **kwargs):
    print(*args, **kwargs)



def do_rsa_with_e_n(d, e, n):
    # https://github.com/pyca/cryptography/issues/2735#issuecomment-276356841
    keylength = math.ceil(n.bit_length() / 8)
    input_nr = int.from_bytes(d, byteorder='big')
    crypted_nr = pow(input_nr, e, n)
    crypted_data = crypted_nr.to_bytes(keylength, byteorder='big')
    return crypted_data


def do_rsa(pkey: str, data: str):
    public_key = RSA.import_key(d64(pkey))
    d = data.encode(encoding='utf-8')
    return do_rsa_with_e_n(d, public_key.e, public_key.n)


def main():
    print('start python cas login')
    kid, pkey = get_key()
    out(kid, pkey)
    log_param = login_param
    tgt = login(kid, pkey, log_param)
    rsp = validate(tgt)
    out(rsp['userName'])
    return


if __name__ == '__main__':
    main()
    #test2()
