import os
import pathlib
import typing

import httpx
from httpx._client import UseClientDefault, USE_CLIENT_DEFAULT
from httpx._config import DEFAULT_TIMEOUT_CONFIG, DEFAULT_MAX_REDIRECTS, Limits, DEFAULT_LIMITS
from httpx._types import AuthTypes, QueryParamTypes, HeaderTypes, CookieTypes, VerifyTypes, CertTypes, ProxiesTypes, \
    TimeoutTypes, URLTypes, RequestContent, RequestData, RequestFiles
from httpx import Request, URL, Response, AsyncBaseTransport, Cookies


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

    def build_request(self,
                      method: str,
                      url: URLTypes,
                      *,
                      content: typing.Optional[RequestContent] = None,
                      data: typing.Optional[RequestData] = None,
                      files: typing.Optional[RequestFiles] = None,
                      json: typing.Optional[typing.Any] = None,
                      params: typing.Optional[QueryParamTypes] = None,
                      headers: typing.Optional[HeaderTypes] = None,
                      cookies: typing.Optional[CookieTypes] = None,
                      timeout: typing.Union[TimeoutTypes, UseClientDefault] = USE_CLIENT_DEFAULT,
                      extensions: typing.Optional[dict] = None, ) -> Request:
        request = httpx.AsyncClient.build_request(self, method=method, url=url, content=content, data=data, files=files,
                                                  json=json, params=params, headers=headers, cookies=cookies,
                                                  timeout=timeout, extensions=extensions)
        self.sign(request)
        return request

    def sign(self, request):
        pass

    async def send(
            self,
            request: Request,
            *,
            stream: bool = False,
            auth: typing.Union[AuthTypes, UseClientDefault, None] = USE_CLIENT_DEFAULT,
            follow_redirects: typing.Union[bool, UseClientDefault] = USE_CLIENT_DEFAULT,
    ) -> Response:
        response = await httpx.AsyncClient.send(self, request=request, stream=stream, auth=auth,
                                                follow_redirects=follow_redirects)
        retry_count = 0
        retry = True
        while retry and self.auto_retry and retry_count < 3:
            retry = await self.before_retry(response)
            if not retry:
                break
            self.sign(request)
            set_cookie(request, self.cookies)
            response = await self.request(
                url=request.url, method=request.method,
                headers=request.headers,
                content=request.content)
            retry_count += 1

        return response

    async def before_retry(self, response: Response) -> bool:
        """
        重试前检查是否需要重试及重试前做操作
        :return: False：不重试，True:重试
        """
        return False


def set_cookie(request: Request, cookies: Cookies):
    try:
        request.headers.pop('Cookie')
    except KeyError:
        pass
    cookies.set_cookie_header(request)
