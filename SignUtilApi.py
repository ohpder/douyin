import asyncio
import random
import typing

import httpx
from httpx import URL, Response, AsyncBaseTransport, Request, Cookies
from httpx._client import UseClientDefault, USE_CLIENT_DEFAULT
from httpx._config import DEFAULT_TIMEOUT_CONFIG, DEFAULT_MAX_REDIRECTS, Limits, DEFAULT_LIMITS
from httpx._types import AuthTypes, QueryParamTypes, HeaderTypes, CookieTypes, VerifyTypes, CertTypes, ProxiesTypes, \
    TimeoutTypes, URLTypes
from loguru import logger as log


class AsyncSignClient(httpx.AsyncClient):
    def __init__(self,
                 *,
                 auth: typing.Optional[AuthTypes] = None,
                 params: typing.Optional[QueryParamTypes] = None,
                 headers: typing.Optional[HeaderTypes] = None,
                 cookies: typing.Optional[CookieTypes] = None,
                 verify: VerifyTypes = True,
                 cert: typing.Optional[CertTypes] = None,
                 http1: bool = True,
                 http2: bool = False,
                 proxies: typing.Optional[ProxiesTypes] = None,
                 mounts: typing.Optional[typing.Mapping[str, AsyncBaseTransport]] = None,
                 timeout: TimeoutTypes = DEFAULT_TIMEOUT_CONFIG,
                 follow_redirects: bool = False,
                 limits: Limits = DEFAULT_LIMITS,
                 max_redirects: int = DEFAULT_MAX_REDIRECTS,
                 event_hooks: typing.Optional[
                     typing.Mapping[str, typing.List[typing.Callable]]
                 ] = None,
                 base_url: URLTypes = "",
                 transport: typing.Optional[AsyncBaseTransport] = None,
                 app: typing.Optional[typing.Callable] = None,
                 trust_env: bool = True,
                 default_encoding: str = "utf-8", auto_retry=True, ):
        super().__init__(auth=auth, params=params, headers=headers, cookies=cookies, verify=verify, cert=cert,
                         http1=http1, http2=http2, proxies=proxies, mounts=mounts, timeout=timeout,
                         follow_redirects=follow_redirects, limits=limits, max_redirects=max_redirects,
                         event_hooks=event_hooks, base_url=base_url, transport=transport, app=app, trust_env=trust_env,
                         default_encoding=default_encoding)
        self.auto_retry = auto_retry
        self.retrying = False

    async def sign(self, request):
        pass

    async def send(
            self,
            request: Request,
            *,
            stream: bool = False,
            auth: typing.Union[AuthTypes, UseClientDefault, None] = USE_CLIENT_DEFAULT,
            follow_redirects: typing.Union[bool, UseClientDefault] = USE_CLIENT_DEFAULT,
    ) -> Response:
        await self.sign(request)
        response = await httpx.AsyncClient.send(self, request=request, stream=stream, auth=auth,
                                                follow_redirects=follow_redirects)
        retry_count = 1
        while await self.is_retry(response) and self.auto_retry and retry_count < 3:
            await self.sign(request)
            set_cookie(request, self.cookies)
            response = await httpx.AsyncClient.send(self, request=request, stream=stream, auth=auth,
                                                    follow_redirects=follow_redirects)
            retry_count += 1
        if retry_count < 3 and not self.retrying:
            await self.call_ok(response)
        return response

    async def is_retry(self, response: Response) -> bool:
        """
        重试前检查是否需要重试及重试前做操作
        :return: False：不重试，True:重试
        """
        return False

    async def call_ok(self,response:httpx.Response):
        pass


def set_cookie(request: Request, cookies: Cookies):
    try:
        request.headers.pop('Cookie')
    except KeyError:
        pass
    cookies.set_cookie_header(request)


class DouyinClient(AsyncSignClient):
    def __init__(self,
                 *,
                 auth: typing.Optional[AuthTypes] = None,
                 params: typing.Optional[QueryParamTypes] = None,
                 headers: typing.Optional[HeaderTypes] = None,
                 cookies: typing.Optional[CookieTypes] = None,
                 verify: VerifyTypes = True,
                 cert: typing.Optional[CertTypes] = None,
                 http1: bool = True,
                 http2: bool = False,
                 proxies: typing.Optional[ProxiesTypes] = None,
                 mounts: typing.Optional[typing.Mapping[str, AsyncBaseTransport]] = None,
                 timeout: TimeoutTypes = DEFAULT_TIMEOUT_CONFIG,
                 follow_redirects: bool = False,
                 limits: Limits = DEFAULT_LIMITS,
                 max_redirects: int = DEFAULT_MAX_REDIRECTS,
                 event_hooks: typing.Optional[
                     typing.Mapping[str, typing.List[typing.Callable]]
                 ] = None,
                 base_url: URLTypes = "",
                 transport: typing.Optional[AsyncBaseTransport] = None,
                 app: typing.Optional[typing.Callable] = None,
                 trust_env: bool = True,
                 default_encoding: str = "utf-8", auto_retry=True, cache_cookies=True,
                 canvas=random.randint(1000000000, 1999999999)):
        super().__init__(auth=auth, params=params, headers=headers, cookies=cookies, verify=verify, cert=cert,
                         http1=http1, http2=http2, proxies=proxies, mounts=mounts, timeout=timeout,
                         follow_redirects=follow_redirects, limits=limits, max_redirects=max_redirects,
                         event_hooks=event_hooks, base_url=base_url, transport=transport, app=app, trust_env=trust_env,
                         default_encoding=default_encoding, auto_retry=auto_retry)
        self.canvas = canvas
        self.cache_cookies = cache_cookies

    async def sign(self, request: httpx.Request):
        if ('/v1/' in str(request.url) or '/api/' in str(request.url) or '/v2/' in str(
                request.url)) and request.method != 'HEAD':
            try:
                user_agent = request.headers['user-agent']
            except KeyError:
                user_agent = request.headers['User-Agent']
            sign_url = await web_sign(url=str(request.url), cookies=self.cookies, user_agent=user_agent,
                                      canvas=self.canvas,
                                      content=request.content.decode())
            request.url = URL(
                sign_url
            )

    async def is_retry(self, response: Response) -> bool:
        self.retrying = True
        if response.text == '':
            raise RuntimeError('抖音返回数据为空')
        elif '__ac_signature=window.byted_acrawler.sign("",__ac_nonce)' in response.text:
            raise RuntimeError('cookie无__ac_signature')
        elif 'const verify_data = ' in response.text:
            raise RuntimeError('出现滑块')
        self.retrying = False
        return False

    async def call_ok(self, response: httpx.Response):
        pass


def cookies_to_str(cookies: dict):
    _res = ''
    if isinstance(cookies, httpx.Cookies):
        for cookie in cookies.jar:
            _res += f'{cookie.name}={cookie.value}; '
    else:
        for name, value in cookies.items():
            _res += f'{name}={value}; '
    return _res[:-2]


async def web_sign(url: str, cookies, user_agent, canvas, content=''):
    log.info('签名前url:{}', url)
    json_data = {
        'url': url,
        'cookies': cookies_to_str(cookies),
        'user_agent': user_agent,
        'canvas': canvas,
        'content': content
    }
    client = httpx.AsyncClient()
    response = await client.post('http://xxx/sign/web', json=json_data)
    sign_url = response.json()['data']
    log.info('签名后url:{}', sign_url)
    return sign_url


def get_douyin_client(cookies: dict, proxy: typing.Union[str, None] = None, http2: bool = True,
                            canvas=random.randint(1000000000, 1999999999)) -> DouyinClient:
    if proxy is None or proxy == '':
        return DouyinClient(cookies=cookies, http2=http2, cache_cookies=False,
                            canvas=canvas)
    proxies = {
        "all://": f"http://{proxy}",
    }
    return DouyinClient(cookies=cookies, http2=http2, proxies=proxies, cache_cookies=False,
                        canvas=canvas)


if __name__ == '__main__':

    headers = {
        "authority": "www.douyin.com",
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "bd-ticket-guard-client-csr": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0NCk1JSUJEakNCdFFJQkFEQW5NUXN3Q1FZRFZRUUdFd0pEVGpFWU1CWUdBMVVFQXd3UFltUmZkR2xqYTJWMFgyZDENCllYSmtNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV3aVVCeVUxMW9xV0xYdG1BSUx6R2k4NzMNCkE1bDkvZFQ4SlFRclhMbXl6TzBBQWhDYmZpZkxBTy9qa1R4Rm56QldUU0hvcld4L2RSQzRtb1RhR3JDSFo2QXMNCk1Db0dDU3FHU0liM0RRRUpEakVkTUJzd0dRWURWUjBSQkJJd0VJSU9kM2QzTG1SdmRYbHBiaTVqYjIwd0NnWUkNCktvWkl6ajBFQXdJRFNBQXdSUUloQUxXMkorUGxaZjVtZFZhZXRJYTFaWEFhODAxMHd5TjVPUzdzbjBObjd3N0oNCkFpQm5YbytBOFlRWTVOZWxLVVlkM3RuSEhvTDVsMFMzYWZqamFKTmw2Rk5PK2c9PQ0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tDQo=",
        "bd-ticket-guard-version": "2",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "referer": "https://www.douyin.com/",
        "sec-ch-ua": "\"Chromium\";v=\"110\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"110\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
    }
    cookies = {
        "__ac_nonce": "06400b96f003766d2954a",
        "__ac_signature": "_02B4Z6wo00f01uCuh1wAAIDDg6RHNPYg7DrgjoPAANw419",
        "ttwid": "1%7CLgbQO-_Y5b2HmDLfQ5Wjjrb-e6ugN5Efsfs4xeU3FlI%7C1677769071%7C3e8fc7d962a7c2737667a1ada6eaeb2f994b6005b293dcedca380a1f6fa98789",
        "douyin.com": "",
        "home_can_add_dy_2_desktop": "%220%22",
        "strategyABtestKey": "%221677769075.082%22",
        "VIDEO_FILTER_MEMO_SELECT": "%7B%22expireTime%22%3A1678373875094%2C%22type%22%3A1%7D",
        "passport_csrf_token": "95540226b7cb0d2ae738fb298fbb372e",
        "passport_csrf_token_default": "95540226b7cb0d2ae738fb298fbb372e",
        "s_v_web_id": "verify_ler8e02a_fSya8uMj_1LQ1_4tB5_8aCD_yShaTEoJF7qw",
        "bd_ticket_guard_client_data": "eyJiZC10aWNrZXQtZ3VhcmQtdmVyc2lvbiI6MiwiYmQtdGlja2V0LWd1YXJkLWNsaWVudC1jc3IiOiItLS0tLUJFR0lOIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLVxyXG5NSUlCRGpDQnRRSUJBREFuTVFzd0NRWURWUVFHRXdKRFRqRVlNQllHQTFVRUF3d1BZbVJmZEdsamEyVjBYMmQxXHJcbllYSmtNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV3aVVCeVUxMW9xV0xYdG1BSUx6R2k4NzNcclxuQTVsOS9kVDhKUVFyWExteXpPMEFBaENiZmlmTEFPL2prVHhGbnpCV1RTSG9yV3gvZFJDNG1vVGFHckNIWjZBc1xyXG5NQ29HQ1NxR1NJYjNEUUVKRGpFZE1Cc3dHUVlEVlIwUkJCSXdFSUlPZDNkM0xtUnZkWGxwYmk1amIyMHdDZ1lJXHJcbktvWkl6ajBFQXdJRFNBQXdSUUloQUxXMkorUGxaZjVtZFZhZXRJYTFaWEFhODAxMHd5TjVPUzdzbjBObjd3N0pcclxuQWlCblhvK0E4WVFZNU5lbEtVWWQzdG5ISG9MNWwwUzNhZmpqYUpObDZGTk8rZz09XHJcbi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLVxyXG4ifQ==",
        "msToken": "XfVECsOF_iedA1AV26-hFol1WmCCFh_1rZyV1rcCm_bKilxKwAVLDxT7HeGYuXc_gc_wljiispByNwws-GWaS76LuqyFcxTiKFeY88sRJE2wTjmYJ-ll0SLeAdPpDA==",
        "csrf_session_id": "2d6212f6aacd4d1f78388b6607a8d033",
        "ttcid": "889143995d8948248c40841fbcdc53d438",
        "tt_scid": "NtsSAeGDY6kkhkZ4ZPl5dYDMI5xjJdU8qVhsXZLtRjfhpVTt2yfLtciFAQvVqzkM80bd"
    }
    url = "https://www.douyin.com/aweme/v1/web/comment/list/"
    params = {
        "device_platform": "webapp",
        "aid": "6383",
        "channel": "channel_pc_web",
        "aweme_id": "7205793159949946145",
        "cursor": "0",
        "count": "20",
        "item_type": "0",
        "insert_ids": "",
        "rcFT": "",
        "pc_client_type": "1",
        "version_code": "170400",
        "version_name": "17.4.0",
        "cookie_enabled": "true",
        "screen_width": "1707",
        "screen_height": "1067",
        "browser_language": "zh-CN",
        "browser_platform": "Win32",
        "browser_name": "Chrome",
        "browser_version": "110.0.0.0",
        "browser_online": "true",
        "engine_name": "Blink",
        "engine_version": "110.0.0.0",
        "os_name": "Windows",
        "os_version": "10",
        "cpu_core_num": "16",
        "device_memory": "8",
        "platform": "PC",
        "downlink": "1.45",
        "effective_type": "4g",
        "round_trip_time": "150",
        "webid": "7205963180614911488",
    }
    client = get_douyin_client(cookies=cookies)
    response = asyncio.run(client.get(url, headers=headers, cookies=cookies, params=params))

    print(response.text)
