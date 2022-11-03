import requests
import time
import re
import hmac
import hashlib
import math

import os

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
}
init_url = "http://18.255.0.2"
get_challenge_api = "http://18.255.0.2/cgi-bin/get_challenge"
srun_portal_api = "http://18.255.0.2/cgi-bin/srun_portal"
n = '200'
type = '1'
# 电信 联通 ac_id=1 移动=4 选择正确连正确网络才能上网
ac_id = '1'
enc = "srun_bx1"

_PADCHAR = "="
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


def _getbyte(s, i):
    x = ord(s[i]);
    if (x > 255):
        print("INVALID_CHARACTER_ERR: DOM Exception 5")
        exit(0)
    return x


def get_base64(s):
    i = 0
    b10 = 0
    x = []
    imax = len(s) - len(s) % 3;
    if len(s) == 0:
        return s
    for i in range(0, imax, 3):
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2);
        x.append(_ALPHA[(b10 >> 18)]);
        x.append(_ALPHA[((b10 >> 12) & 63)]);
        x.append(_ALPHA[((b10 >> 6) & 63)]);
        x.append(_ALPHA[(b10 & 63)])
    i = imax
    if len(s) - imax == 1:
        b10 = _getbyte(s, i) << 16;
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR);
    elif len(s) - imax == 2:
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8);
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _ALPHA[((b10 >> 6) & 63)] + _PADCHAR);
    return "".join(x)


def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


def force(msg):
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)


def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd


def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)


def get_xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


def get_chksum():
    chkstr = token + username
    chkstr += token + hmd5
    chkstr += token + ac_id
    chkstr += token + ip
    chkstr += token + n
    chkstr += token + type
    chkstr += token + i
    return chkstr


def get_info():
    info_temp = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": enc
    }
    i = re.sub("'", '"', str(info_temp))
    i = re.sub(" ", '', i)
    return i


def init_getip():
    global ip
    init_res = requests.get(init_url, headers=header)
    print("初始化获取ip")
    ip = re.search('id="user_ip" value="(.*?)"', init_res.text).group(1)
    print("ip:" + ip)


def get_token():
    # print("获取token")
    global token
    get_challenge_params = {
        "callback": "jQuery112404953340710317169_" + str(int(time.time() * 1000)),
        "username": username,
        "ip": ip,
        "_": int(time.time() * 1000),
    }
    get_challenge_res = requests.get(get_challenge_api, params=get_challenge_params, headers=header)
    token = re.search('"challenge":"(.*?)"', get_challenge_res.text).group(1)
    # print(get_challenge_res.text)
    print("token为:" + token)


def do_complex_work():
    global i, hmd5, chksum
    i = get_info()
    i = "{SRBX1}" + get_base64(get_xencode(i, token))
    hmd5 = get_md5(password, token)
    chksum = get_sha1(get_chksum())
    print("所有加密工作已完成")


def pd():
    if(username == '' or password ==''):
        print("账号密码为空，请输入")
        exit(0)

def login():
    srun_portal_params = {
        'callback': 'jQuery11240645308969735664_' + str(int(time.time() * 1000)),
        'action': 'login',
        'username': username,
        'password': '{MD5}' + hmd5,
        'ac_id': ac_id,
        'ip': ip,
        'chksum': chksum,
        'info': i,
        'n': n,
        'type': type,
        'os': 'windows+10',
        'name': 'windows',
        'double_stack': '0',
        '_': int(time.time() * 1000)
    }
    # print(srun_portal_params)
    srun_portal_res = requests.get(srun_portal_api, params=srun_portal_params, headers=header)
    # print(srun_portal_res.text)
    array = srun_portal_res.text
    array = array[42:-2]
    array = array.replace('"','')
    array = array.split(',')
    # print(array)
    list1 = []
    list2 = []
    for el in array:
        list1.append(el.split(":")[0])
        list2.append(el.split(":")[1])
    # print(list1)
    # print(list2)
    d1={}
    d1=dict(zip(list1, list2))
    # print(d1)
    # print(d1["username"])
    if(ac_id=='1'):
        print(d1["error"])
        if (d1["error_msg"] != ''):
            print("错误信息为:" + d1["error_msg"])
        else:
            print("无错误信息")
        if "ploy_msg" in d1:
            print("信息为:" + d1["ploy_msg"])
    elif(ac_id=='4'):
        print(d1["error"])
        if (d1["error_msg"] != ''):
            print("错误信息为" + d1["error_msg"])
        else:
            print("无错误信息")


    ret = os.system('ping -w0.5 -n 1 www.baidu.com')
    # if ret == 0:
    #     time_re = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    #     print("OK,%s" % time_re)
    if ret == 0:
        print("\n"+"校园网连接成功")
    else:
        print("校园网连接失败")
        print("提示:账号密码是否正确？网络连接是否正确？ac_id是否选择正确？")


if __name__ == '__main__':
    global username, password
    # 校园网账号
    username = ""
    # 校园网密码
    password = ""
    # 加密函数
    pd()
    init_getip()
    get_token()
    do_complex_work()
    # 登录函数
    login()