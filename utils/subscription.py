# -*- coding: utf-8 -*-
import sys
import json
import base64
import requests

SS = "shadowsocks"
VMESS = "vmess"


class InternalError(Exception):
    def __init__(self, msg):
        self.message = msg


class ServerInfo:
    def __init__(self, protocol: str):
        self.protocol = protocol
        self.host = ""
        self.port = 0
        self.key = ""
        self.algorithm = ""
        self.alter_id = 0
        self.net = "tcp"
        self.camouflage = "none"
        self.tls = ""
        self.sni = ""
        self.addition = ""
        self.tag = ""
        self.path = None


def base64decode(encoded: str) -> bytes:
    try:
        encoded += "=" * ((4 - len(encoded) % 4) % 4)
        return base64.decodebytes(encoded.encode("utf-8"))
    except Exception as e:
        print(e)
        return encoded.encode("utf-8")


def decode_shadowsocks(ss_server_str: str):
    info = ServerInfo(SS)
    s_tag = ss_server_str.split("#")
    if len(s_tag) > 1:
        info.tag = s_tag[1]
    if len(s_tag) > 0:
        server = s_tag[0]
        try:
            server = base64decode(server).decode("utf-8")
        except UnicodeDecodeError:
            raise InternalError("shadowsocks server can't decode to utf-8")

        auth_server = server.split("@")
        if len(auth_server) > 1:
            host_port = auth_server[1]
            method_key = auth_server[0]
        else:
            return None

        [info.algorithm, info.key] = method_key.split(":")
        [info.host, port] = host_port.split(":")
        info.port = int(port)
        return info
    else:
        return None


def decode_vmess(ss_server_str: str):
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


def subscription_to_servers(url: str, cache_file: str or None):
    result = list()
    try:
        resp = requests.get(url, headers= {"User-Agent": "curl/8.5.0"} , proxies={"http": "", "https": ""})
    except Exception as e:
        raise InternalError("requests.get raises exceptions. " + str(e))
    if not resp.ok:
        raise InternalError("requests.get's response not ok.")

    server_confs_bs = base64decode(resp.text)
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


def uri_to_server(uri: str):
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
    return info


def server_conf_2_dict(server_conf):
    clash_proxy = {
        "name": server_conf.tag,
        "type": "vmess" if server_conf.protocol == VMESS else "ss",
        "server": server_conf.host,
        "port": server_conf.port,
        "cipher": server_conf.algorithm,
        "uuid" if server_conf.protocol == VMESS else "password": server_conf.key,
    }

    if server_conf.protocol == VMESS:
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

    return clash_proxy
