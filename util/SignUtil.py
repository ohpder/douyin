import json
import math
import random
import re
import time
from typing import Union
import urllib.parse
from urllib.parse import unquote

import httpx
from httpx import URL, Response

from util import AsyncSignClient
import huakuai
from Signature import Signature
from X_Bogus import XBogus, UA, CANVAS
from util.logger import log
import asyncio
from collections import deque

cookie_deque = deque(maxlen=1024)


def get_ms_token_and_tt_scid(cookie):
    ms_token = ''
    tt_scid = ''
    if isinstance(cookie, str):
        try:
            ms_token = re.findall(r'msToken=(?P<ms_token>.*?)($|;)', cookie)[-1][0]
        except AttributeError:
            pass
        try:
            tt_scid = re.search(r'tt_scid=(?P<tt_scid>.*?)($|;)', cookie).group('tt_scid')
        except AttributeError:
            pass
    elif isinstance(cookie, dict):
        try:
            ms_token = cookie['msToken']
        except KeyError:
            pass
        try:
            tt_scid = cookie['tt_scid']
        except KeyError:
            pass
    return ms_token, tt_scid


def signature_url(target: str, user_agent: str, cookie: str, canvas: int = CANVAS):
    log.info('签名前url:{}', target)
    target_split = target.split('?')
    params = ''
    if len(target_split) == 2:
        params = target_split[1]
    x_bogus = ''
    params_split = params.split('&X-Bogus=')
    if len(params_split) == 2:
        params = params_split[0]
        x_bogus = params_split[1]
    url = target_split[0].split('://')[1]
    split = url.split('.com')
    href = split[0] + '.com'
    pathname = split[1]
    ms_token, tt_scid = get_ms_token_and_tt_scid(cookie)
    _signature = Signature(
        params=f'X-Bogus={x_bogus}&{params}&pathname={pathname}&tt_webid=&uuid=',
        href=href,
        tt_scid=tt_scid, ua=user_agent, canvas=canvas).getSignature()
    if '?' in target:
        signature_ur = target + f'&_signature={_signature}'
    else:
        signature_ur = target + f'?_signature={_signature}'
    log.info('签名后url:{}', signature_ur)
    return signature_ur


def web_sign(target: str, cookie, user_agent: str = UA, canvas: int = CANVAS, body=''):
    if cookie is None:
        cookie = {}
    if canvas is None:
        canvas = CANVAS
    if user_agent is None:
        user_agent = UA
    log.info('签名前url:{}', target)
    if type(cookie) == str:
        ms_token, tt_scid = get_ms_token_and_tt_scid(cookie)
    else:
        try:
            ms_token, tt_scid = cookie['msToken'], cookie['tt_scid']
        except KeyError:
            ms_token, tt_scid = '', ''
    target_split = target.split('?')
    if len(target_split) != 1:
        params = re.sub(r'(&?msToken=.*?(&|$)|&?X-Bogus=.*?(&|$)|&?_signature=.*?(&|$))',
                        '', target_split[1]) + f"&msToken={ms_token}"
    else:
        params = f'msToken={ms_token}'
    x_bogus = XBogus(params, user_agent, canvas, body).get_x_bogus()
    url = target_split[0].split('://')[1]
    split = url.split('.com')
    href = split[0] + '.com'
    pathname = split[1]
    _signature = Signature(
        params=f'X-Bogus={x_bogus}&{params}&pathname={pathname}&tt_webid=&uuid=',
        href=href,
        tt_scid=tt_scid, ua=user_agent, canvas=canvas).getSignature()
    res = f"{target_split[0]}?{params}&X-Bogus={x_bogus}&_signature={_signature}"
    log.info('签名后url:{}', res)
    return res


def local_time():
    return math.floor(time.time())


def local_time_ms():
    return math.floor(time.time() * 1000)


def cookie_str_to_dic(cookie: str):
    res = {}
    cookie_split = cookie.split('; ')
    for i_split in cookie_split:
        split = i_split.split('=')
        if len(split) > 1:
            res[unquote(i_split[0:i_split.index('=')])] = unquote(i_split[i_split.index('=') + 1:])
    return res


def add_x_bogus(target: str, user_agent: str, canvas: int = CANVAS, cookie='', body=''):
    if canvas is None:
        canvas = CANVAS
    if user_agent is None:
        user_agent = UA
    log.info('签名前url:{}', target)
    if type(cookie) == str:
        ms_token, tt_scid = get_ms_token_and_tt_scid(cookie)
    else:
        try:
            ms_token, tt_scid = cookie['msToken'], cookie['tt_scid']
        except:
            pass
    target_split = target.split('?')
    if len(target_split) != 1:
        params = re.sub(r'(&?msToken=.*?(&|$)|&?X-Bogus=.*?(&|$)|&?_signature=.*?(&|$))',
                        '', target_split[1]) + f"&msToken={ms_token}"
    else:
        params = f'msToken={ms_token}'
    x_bogus = XBogus(params, user_agent, canvas, body).get_x_bogus()
    res = f"{target_split[0]}?{params}&X-Bogus={x_bogus}"
    log.info('签名后url:{}', res)
    return res


class DouyinClient(AsyncSignClient):

    def sign(self, request: httpx.Request):
        if ('/aweme/v1/web' in str(request.url) or '/api/' in str(request.url)) and request.method != 'HEAD':
            try:
                user_agent = request.headers['user-agent']
            except KeyError:
                user_agent = request.headers['User-Agent']
            request.url = URL(
                web_sign(target=str(request.url), cookie=self.cookies, user_agent=user_agent, canvas=CANVAS,
                         body=request.content.decode()))

    async def before_retry(self, response: Response) -> bool:

        if response.text == '':
            s_v_web_id = self.cookies.get('s_v_web_id')
            if s_v_web_id is None:
                s_v_web_id = create_s_v_web_id()
                self.cookies.set('s_v_web_id', s_v_web_id)
            await huakuai.get_page_content(client=self)
            return True
        elif '__ac_signature=window.byted_acrawler.sign("",__ac_nonce)' in response.text:
            ac_nonce = self.cookies.get('__ac_nonce')
            request = response.request
            try:
                user_agent = request.headers['user-agent']
            except KeyError:
                user_agent = request.headers['User-Agent']
            ac_signature = get_ac_signature(ac_nonce, user_agent, str(request.url).replace('https://', ''))
            self.cookies.set('__ac_signature', ac_signature, domain='www.douyin.com')
            return True
        else:
            try:
                content = json.loads(re.findall('(?<=const verify_data = ).+', response.text)[0])
                res = await huakuai.captcha(self, content['fp'], content['detail'])
                log.info(res)
                if res['code'] != 200:
                    await huakuai.get_page_content(self)
                else:
                    self.cookies.set('s_v_web_id', content['fp'])
                return True
            except IndexError:
                pass
        return False


async def get_douyin_client(proxy: Union[str, None] = None, cookie=None, http2: bool = False,
                            is_login=False) -> httpx.AsyncClient:
    if cookie is None and is_login is False:
        cookie = await get_douyin_cookie()
    if isinstance(cookie, str):
        cookie = cookie_str_to_dic(cookie)
    if proxy is None or proxy == '':
        return DouyinClient(cookies=cookie, http2=http2)
    proxies = {
        "all://": f"http://{proxy}",
    }
    return DouyinClient(cookies=cookie, http2=http2, proxies=proxies)


def get_client(proxy: Union[str, None] = None, cookie: dict = None, http2: bool = False) -> httpx.AsyncClient:
    if isinstance(cookie, str):
        cookie = cookie_str_to_dic(cookie)
    if proxy is None or proxy == '':
        return httpx.AsyncClient(cookies=cookie, http2=http2)
    else:
        proxies = {
            "all://": f"http://{proxy}",
        }
        return httpx.AsyncClient(cookies=cookie, http2=http2, proxies=proxies)


def get_captcha_body(x, _id, fp):
    return huakuai.captcha_encrypt(huakuai.get_trace(x, _id, fp))


def baseN(num, b): return ((num == 0) and "0") or (
        baseN(num // b, b).lstrip("0") + "0123456789abcdefghijklmnopqrstuvwxyz"[num % b])


def create_s_v_web_id():
    key = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    t = len(key)
    n = baseN(int(time.time() * 1000), 36)
    r = []
    for i in range(36):
        o = 0 | int(random.random() * t)
        if 19 == i:
            r.insert(i, key[3 & o | 8])
        else:
            r.insert(i, key[o])
    r.insert(8, '_')
    r.insert(13, '_')
    r.insert(18, '_')
    r.insert(23, '_')
    r.insert(14, '4')
    res = "verify_" + n + "_" + "".join(r)
    return res


async def test_captcha():
    client = httpx.AsyncClient(http2=True)
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Origin': 'https://haohuo.jinritemai.com',
        'Pragma': 'no-cache',
        'Referer': 'https://haohuo.jinritemai.com/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }

    data = {
        'ui_params': '{"from_live":false,"from_video":null,"three_d_log_data":null,"follow_status":null,"which_account":null,"ad_log_extra":null,"from_group_id":null,"bolt_param":null,"transition_tracker_data":null,"selected_ids":null,"window_reposition":null,"is_short_screen":null,"full_mode":null}',
        'use_new_price': '1',
        'is_h5': '1',
        'bff_type': '2',
        'is_in_app': '0',
        'promotion_ids': 'undefined',
        'meta_param': '',
        'source_page': '',
        'request_additions': '',
        'isFromVideo': 'false',
    }

    response = await client.post(
        web_sign(
            f'https://ecom.ecombdapi.com/aweme/v2/shop/promotion/pack/?is_h5=1&is_native_h5=1&verifyFp={create_s_v_web_id()}&msToken=xF2RbCKorrdj_vJb_YAHIE59ddlTFOnGUUAY1hXrHo3fBq6_CmLGic-SLt3c_WOhfIiCeDy9cl23FXrKC-LMY-cg4tgo3HNw00qbOegl3dZfC8ogKi1DR-Z3WnAja50=&X-Bogus=DFSzswVYLRpeBNyXSdvp4VXAIQ5l',
            '', headers['User-Agent'], CANVAS, urllib.parse.urlencode(data)),
        headers=headers,
        data=data,
    )
    content = json.loads(response.json()['bdturing'])
    res = await huakuai.captcha(client, content['fp'], content['detail'])
    log.info(res)


def get_ac_signature(_ac_nonce, user_agent, href, canvas=CANVAS):
    return Signature(params=_ac_nonce, href=href,
                     ua=user_agent, canvas=canvas).get_ac_signature()


async def create_douyin_cookie(passport_csrf_token=True):
    headers = {
        'authority': 'www.douyin.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'accept-language': 'zh-CN,zh;q=0.9',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'upgrade-insecure-requests': '1',
        'user-agent': UA,
    }
    client = get_client(None, {}, True)
    await client.get(f'https://www.douyin.com', headers=headers)
    ac_nonce = client.cookies.get('__ac_nonce')
    if ac_nonce is None:
        return
    ac_signature = get_ac_signature(ac_nonce, headers['user-agent'], '',
                                    random.randint(1000000000, 1999999999)
                                    )
    client.cookies.set('__ac_signature', ac_signature, domain='www.douyin.com')
    response = await client.get(f'https://www.douyin.com', headers=headers)
    cookie = client.cookies
    if response.status_code == 200 and cookie.get('ttwid') is not None:
        if passport_csrf_token:
            await get_passport_csrf_token(client)
        cookie.set('s_v_web_id', create_s_v_web_id(), domain='.douyin.com')
        log.info(cookie)
        cookie_deque.append(cookie)
        return cookie
    else:
        return await create_douyin_cookie()


async def get_douyin_cookie():
    if len(cookie_deque) < 5:
        await asyncio.wait([create_douyin_cookie() for _ in range(10)])
    count = 1
    while len(cookie_deque) < 1 and count < 10:
        await asyncio.sleep(0.2)
        count += 1
    cookie = cookie_deque.pop()
    cookie_deque.append(cookie)
    return cookie


camel_pat = re.compile(r'([A-Z])')
under_pat = re.compile(r'_([a-z])')


def camel_to_underscore(name):
    return camel_pat.sub(lambda x: '_' + x.group(1).lower(), name)


def convert_json(d, convert):
    if isinstance(d, dict):
        new_d = {}
        for k, v in d.items():
            new_d[convert(k)] = convert_json(v, convert) if isinstance(v, dict) or isinstance(v, list) else v
        return new_d

    elif isinstance(d, list):
        new_d = []
        for i in d:
            i = convert_json(i, convert)
            new_d.append(i)
        return new_d
    else:
        return d


async def get_passport_csrf_token(client):
    headers = {
        'authority': 'sso.douyin.com',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9',
        'cache-control': 'no-cache',
        'origin': 'https://www.douyin.com',
        'pragma': 'no-cache',
        'referer': 'https://www.douyin.com/',
        'sec-ch-ua': '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    }

    response = await client.get(
        'https://sso.douyin.com/check_login/?service=https:%2F%2Fwww.douyin.com&aid=6383&account_sdk_source=sso&language=zh&sdk_version=2.1.3',
        headers=headers,
    )
    log.info(response.json())


async def test():
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        # Requests sorts cookies= alphabetically
        # 'Cookie': cookies,
        'Pragma': 'no-cachse',
        # 'Referer': 'https://www.douyin.com/user/MS4wLjABAAAAmRo-DO3swt5s73DgpOijqOcsko86lym6BQxWpNPuT0wVoHop4MRrUPhl2i-ZaHx8',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': UA,
        'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }
    client = await get_douyin_client(cookie={})
    response = await client.get(
        f'https://www.douyin.com/video/7181394595337522464',
        headers=headers)
    await client.aclose()
    res = response.text
    return res


if __name__ == '__main__':
    # res = asyncio.get_event_loop().run_until_complete(test())
    # pass
    print(create_s_v_web_id())
