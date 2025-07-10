# -*- coding: utf-8 -*-
import sys
import json
import base64
import requests
from urllib.parse import unquote

SS = "shadowsocks"
VMESS = "vmess"
VLESS = "vless"


class InternalError(Exception):
    def __init__(self, msg):
        self.message = msg


class ServerInfo:
    def __init__(self, protocol: str):
        self.protocol = protocol
        self.host = ""
        self.port = 0
        self.key = ""
        self.algorithm: str | None = None
        self.alter_id = 0
        self.net = "tcp"
        self.camouflage = "none"
        self.tls = ""
        self.sni = ""
        self.addition = ""
        self.tag = ""
        self.path = None
        self.flow: str | None = None
        self.client_fingerprint: str | None = None


def base64decode(encoded: str) -> bytes:
    try:
        encoded += "=" * ((4 - len(encoded) % 4) % 4)
        return base64.decodebytes(encoded.encode("utf-8"))
    except Exception as e:
        print(e)
        return encoded.encode("utf-8")
    

def base64decode_or_original(s: str) -> str:
    if s.find('@') != -1 and s.find(':') != -1:
        return s
    
    try:
        s = base64decode(s).decode("utf-8")
        return s
    except UnicodeDecodeError:
        return s
    

def urldecode_or_original(s: str) -> str:
    try:
        decoded_s = unquote(s)
        return decoded_s
    except Exception:
        return s


def decode_shadowsocks(ss_server_str: str) -> ServerInfo | None:
    info = ServerInfo(SS)
    try:
        s_tag = ss_server_str.split("#")
        if len(s_tag) > 1:
            info.tag = urldecode_or_original(s_tag[1].strip())
        if len(s_tag) > 0:
            server = s_tag[0]
            server = base64decode_or_original(server)

            auth_server = server.split("@")
            if len(auth_server) > 1:
                host_port = auth_server[1]
                method_key = auth_server[0]
            else:
                return None

            [info.algorithm, info.key] = base64decode_or_original(method_key).split(":", maxsplit=1)
            [info.host, port] = host_port.split(":", maxsplit=1)
            info.port = int(port)
            return info
        else:
            return None
    except Exception as e:
        print(e, file=sys.stderr)
        return None



def decode_vmess(ss_server_str: str) -> ServerInfo | None:
    try:
        ss_server_str = base64decode(ss_server_str).decode("utf-8")
    except UnicodeDecodeError:
        raise InternalError("Can not decode base64 '" + ss_server_str + "'.")

    try:
        vmess_conf = json.loads(ss_server_str)
    except Exception:
        raise InternalError("Can not decode json '" + ss_server_str + "'.")

    info = ServerInfo(VMESS)
    info.tag = vmess_conf.get("ps", "")
    info.host = vmess_conf.get("add", "")
    info.port = int(vmess_conf.get("port", "0"))
    info.tls = vmess_conf.get("tls", info.tls)
    info.alter_id = int(vmess_conf.get("aid", "0"))
    info.key = vmess_conf.get("id", "")
    info.sni = vmess_conf.get("sni", "")
    info.camouflage = vmess_conf["type"] or "none"
    info.net = vmess_conf.get("net", info.net)
    info.algorithm = "auto"
    if "path" in vmess_conf.keys():
        info.path = vmess_conf["path"]
    return info


def decode_vless(server_str: str) -> ServerInfo | None:
    info = ServerInfo(VLESS)
    try:
        [server_info, info.tag] = server_str.split("#", maxsplit=1)
        info.tag = urldecode_or_original(info.tag.strip())
        [base, extra] = server_info.split("?", maxsplit=1)
        [info.key, endpoint] = base.split("@", maxsplit=1)
        [info.host, port] = endpoint.split(":", maxsplit=1)
        info.port = int(port)
        params = extra.split("&")
        for param in params:
            if param.startswith("type="):
                info.net = param.split("=", maxsplit=1)[1]
            elif param.startswith("flow="):
                info.flow = param.split("=", maxsplit=1)[1]
            elif param.startswith("sni="):
                info.sni = param.split("=", maxsplit=1)[1]
            elif param == "security=tls":
                info.tls = "tls"
            elif param.startswith("fp="):
                info.client_fingerprint = param.split("=", maxsplit=1)[1]
    except Exception as e:
        print(e, file=sys.stderr)
        return None
    return info


def subscription_to_servers(url: str, cache_file: str | None) -> list[ServerInfo]:
    result: list[ServerInfo] = list()
    try:
        resp = requests.get(url, headers= {"User-Agent": "Mozilla/5.0 (Python; requests;) JMSToClash/20250710"} , proxies={"http": "", "https": ""}, timeout=10)
    except Exception as e:
        raise InternalError("requests.get raises exceptions. " + str(e))
    if not resp.ok:
        raise InternalError("requests.get's response not ok.")

    server_confs_bs = base64decode(resp.text)
    try:
        server_confs_str = server_confs_bs.decode("utf-8", "strict")
    except UnicodeDecodeError as e:
        raise InternalError(
            f"subscription b64 decoded result can not decode to string by utf-8 \n {e.reason} \n dump: \n {server_confs_bs.hex()}"
        )

    server_confs = server_confs_str.split("\n")

    for server_conf in server_confs:
        info = uri_to_server(server_conf)

        if info is not None:
            result.append(info)

    if cache_file is not None:
        try:
            with open(cache_file, mode="w") as f:
                f.write(resp.text)
        except OSError:
            pass

    return result


def cache_to_servers(file: str):
    result = list()
    try:
        with open(file, mode="r") as f:
            text = f.read()
            server_confs_bs = base64decode(text)
            try:
                server_confs_str = server_confs_bs.decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise InternalError(
                    "subscription b64 decoded result can not decode to string by utf-8"
                )

            server_confs = server_confs_str.split("\n")

            for server_conf in server_confs:
                info = uri_to_server(server_conf)

                if info is not None:
                    result.append(info)

            return result
    except OSError as e:
        raise InternalError("can not open cache file " + file + ", " + str(e))
    return result


def uri_to_server(uri: str) -> ServerInfo | None:
    p_s = uri.split("://")
    if len(p_s) < 2:
        return None
    protocol = p_s[0]
    server = p_s[1]
    info = None
    if protocol == "ss":
        try:
            info = decode_shadowsocks(server)
        except InternalError as e:
            print(e.message, file=sys.stderr)
    elif protocol == "vmess":
        try:
            info = decode_vmess(server)
        except InternalError as e:
            print(e.message, file=sys.stderr)
    elif protocol == "vless":
        try:
            info = decode_vless(server)
        except InternalError as e:
            print(e.message, file=sys.stderr)

    return info


def server_conf_2_dict(server_conf: ServerInfo) -> dict[str, str | int | bool | dict]:
    clash_proxy = {
        "name": server_conf.tag,
        "type": "ss" if server_conf.protocol == SS else server_conf.protocol,
        "server": server_conf.host,
        "port": server_conf.port,
        "password" if server_conf.protocol == SS else "uuid": server_conf.key,
    }
    if server_conf.protocol == SS:
        clash_proxy["cipher"] = server_conf.algorithm
    elif server_conf.protocol == VMESS:
        clash_proxy["cipher"] = server_conf.algorithm
        clash_proxy["alterId"] = server_conf.alter_id
        clash_proxy["network"] = server_conf.net
        clash_proxy["tls"] = server_conf.tls == "tls"
        if server_conf.tls == "tls":
            clash_proxy["skip-cert-verify"] = True
            clash_proxy["servername"] = server_conf.sni or "example.com"
        if server_conf.net == "grpc":
            clash_proxy["grpc-opts"] = {}
            if server_conf.path:
                clash_proxy["grpc-opts"]["grpc-service-name"] = server_conf.path
    elif server_conf.protocol == VLESS:
        clash_proxy["flow"] = server_conf.flow
        clash_proxy["network"] = server_conf.net or "tcp"
        clash_proxy["tls"] = server_conf.tls == "tls"
        if server_conf.tls == "tls":
            clash_proxy["skip-cert-verify"] = True
            clash_proxy["servername"] = server_conf.sni or "example.com"
        if server_conf.client_fingerprint:
            clash_proxy["client-fingerprint"] = server_conf.client_fingerprint

    return clash_proxy
