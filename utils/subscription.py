# -*- coding: utf-8 -*-
import sys
import json
import base64
import time
import requests
from urllib.parse import unquote

SS = "shadowsocks"
VMESS = "vmess"
VLESS = "vless"
TROJAN = "trojan"
HY2 = "hysteria2"
ANYTLS = "anytls"

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
        self.up: str | None = None
        self.down: str | None = None
        # Plugin fields for obfs-local
        self.plugin: str | None = None
        self.plugin_opts: dict | None = None


def base64decode(encoded: str) -> bytes:
    try:
        encoded += "=" * ((4 - len(encoded) % 4) % 4)
        return base64.decodebytes(encoded.encode("utf-8"))
    except Exception as e:
        print(e)
        return encoded.encode("utf-8")


def base64decode_or_original(s: str) -> str:
    if s.find("@") != -1 and s.find(":") != -1:
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

            # Check for query string (plugin parameters)
            query_params = ""
            if "?" in server:
                server, query_params = server.split("?", maxsplit=1)

            auth_server = server.split("@")
            if len(auth_server) > 1:
                host_port = auth_server[1]
                method_key = auth_server[0]
            else:
                return None

            [info.algorithm, info.key] = base64decode_or_original(method_key).split(
                ":", maxsplit=1
            )

            # Parse host:port, handling possible query params attached to port
            host_port_parts = host_port.split(":")
            if len(host_port_parts) >= 2:
                info.host = host_port_parts[0]
                port_part = host_port_parts[1]
                # Handle case where port might have query params appended
                if "?" in port_part:
                    port_part = port_part.split("?")[0]
                info.port = int(port_part)
            else:
                return None

            # Parse query parameters for plugin
            if query_params:
                params = query_params.split("&")
                for param in params:
                    if param.startswith("plugin="):
                        plugin_value = urldecode_or_original(
                            param[7:]
                        )  # Remove "plugin="
                        # Parse plugin options (semicolon-separated)
                        plugin_parts = plugin_value.split(";")
                        if len(plugin_parts) > 0:
                            plugin_name = plugin_parts[0]
                            if plugin_name == "obfs-local" or plugin_name == "obfs":
                                info.plugin = "obfs"
                                info.plugin_opts = {}
                                for part in plugin_parts[1:]:
                                    if "=" in part:
                                        key, value = part.split("=", maxsplit=1)
                                        if key == "obfs" and value:
                                            info.plugin_opts["mode"] = value
                                        elif key == "obfs-host" and value:
                                            info.plugin_opts["host"] = value
                                        elif key == "path" and value:
                                            info.plugin_opts["path"] = value

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


def decode_trojan(server_str: str) -> ServerInfo | None:
    info = ServerInfo(TROJAN)
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
            elif param.startswith("sni="):
                info.sni = param.split("=", maxsplit=1)[1]
    except InternalError as e:
        print(e, file=sys.stderr)
        return None
    return info


def decode_hysteria2(server_str: str) -> ServerInfo | None:
    info = ServerInfo(HY2)
    info.down = "200"
    info.up = "30"
    try:
        [server_info, info.tag] = server_str.split("#", maxsplit=1)
        info.tag = urldecode_or_original(info.tag.strip())
        [base, extra] = server_info.split("?", maxsplit=1)
        base = base.split("/", maxsplit=1)[0]
        [info.key, endpoint] = base.split("@", maxsplit=1)
        [info.host, port] = endpoint.split(":", maxsplit=1)
        ports = port.split(",")
        info.port = int(ports[0])
        params = extra.split("&")
        for param in params:
            if param.startswith("sni="):
                info.sni = param.split("=", maxsplit=1)[1]
    except InternalError as e:
        print(e, file=sys.stderr)
        return None
    return info

def decode_anytls(server_str: str) -> ServerInfo | None:
    info = ServerInfo(ANYTLS)
    try:
        [server_info, info.tag] = server_str.split("#", maxsplit=1)
        info.tag = urldecode_or_original(info.tag.strip())
        [base, extra] = server_info.split("?", maxsplit=1)
        base = base.split("/", maxsplit=1)[0]
        [info.key, endpoint] = base.split("@", maxsplit=1)
        [info.host, port] = endpoint.split(":", maxsplit=1)
        ports = port.split(",")
        info.port = int(ports[0])
        params = extra.split("&")
        for param in params:
            if param.startswith("sni="):
                info.sni = param.split("=", maxsplit=1)[1]
            elif param.startswith("fp="):
                info.client_fingerprint = param.split("=", maxsplit=1)[1]
    except InternalError as e:
        print(e, file=sys.stderr)
        return None
    return info


def subscription_to_servers(
    url: str, cache_file: str | None, ua: str | None = None
) -> list[ServerInfo]:
    result: list[ServerInfo] = list()

    max_retries = 10
    retry_count = 0
    last_exception = None
    resp = None
    ua = ua or "curl/8.17.0"
    while retry_count <= max_retries:
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": ua},
                proxies={"http": "", "https": ""},
                timeout=10,
                allow_redirects=True,
                verify=False,
            )
            break
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.SSLError,
        ) as e:
            last_exception = e
            retry_count += 1
            continue
        except Exception as e:
            raise InternalError("requests.get raises exceptions. " + str(e))

    if resp is None:
        raise InternalError(
            f"requests.get failed after {max_retries} retries. Last error: {str(last_exception)}"
        )

    if not resp.ok:
        raise InternalError(f"requests.get's response not ok. \n {resp.status_code}")

    server_confs_bs = base64decode(resp.text)
    try:
        server_confs_str = server_confs_bs.decode("utf-8", "strict")
    except UnicodeDecodeError as e:
        raise InternalError(
            f"subscription b64 decoded result can not decode to string by utf-8 \n {e.reason}"
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
    elif protocol == VMESS:
        try:
            info = decode_vmess(server)
        except InternalError as e:
            print(e.message, file=sys.stderr)
    elif protocol == VLESS:
        try:
            info = decode_vless(server)
        except InternalError as e:
            print(e.message, file=sys.stderr)
    elif protocol == TROJAN:
        try:
            info = decode_trojan(server)
        except InternalError as e:
            print(e.message, file=sys.stderr)
    elif protocol == HY2 or protocol == "hy2":
        try:
            info = decode_hysteria2(server)
        except InternalError as e:
            print(e.message, file=sys.stderr)
    elif protocol == ANYTLS:
        try:
            info = decode_anytls(server)
        except InternalError as e:
            print(e.message, file=sys.stderr)

    return info


def server_conf_2_dict(server_conf: ServerInfo) -> dict[str, str | int | bool | dict]:
    clash_proxy = {
        "name": server_conf.tag,
        "type": "ss" if server_conf.protocol == SS else server_conf.protocol,
        "server": server_conf.host,
        "port": server_conf.port,
        "password"
        if (
            server_conf.protocol == SS
            or server_conf.protocol == TROJAN
            or server_conf.protocol == HY2
            or server_conf.protocol == ANYTLS
        )
        else "uuid": server_conf.key,
    }
    if server_conf.protocol == SS:
        clash_proxy["cipher"] = server_conf.algorithm
        if server_conf.plugin:
            clash_proxy["plugin"] = server_conf.plugin
        if server_conf.plugin_opts:
            clash_proxy["plugin-opts"] = server_conf.plugin_opts
    elif server_conf.protocol == VMESS:
        clash_proxy["cipher"] = server_conf.algorithm
        clash_proxy["alterId"] = server_conf.alter_id
        clash_proxy["network"] = server_conf.net
        clash_proxy["tls"] = server_conf.tls == "tls"
        if server_conf.tls == "tls":
            clash_proxy["skip-cert-verify"] = True
            clash_proxy["sni"] = server_conf.sni or "example.com"
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
            clash_proxy["sni"] = server_conf.sni or "example.com"
        if server_conf.client_fingerprint:
            clash_proxy["client-fingerprint"] = server_conf.client_fingerprint
    elif server_conf.protocol == TROJAN:
        clash_proxy["skip-cert-verify"] = True
        if server_conf.sni is not None:
            clash_proxy["sni"] = server_conf.sni
        if server_conf.net is not None:
            clash_proxy["network"] = server_conf.net
    elif server_conf.protocol == HY2:
        clash_proxy["skip-cert-verify"] = True
        if server_conf.sni is not None:
            clash_proxy["sni"] = server_conf.sni
        if server_conf.down is not None:
            clash_proxy["down"] = server_conf.down
        if server_conf.up is not None:
            clash_proxy["up"] = server_conf.up
    elif server_conf.protocol == ANYTLS:
        clash_proxy["skip-cert-verify"] = True
        if server_conf.sni is not None:
            clash_proxy["sni"] = server_conf.sni
        if server_conf.client_fingerprint is not None:
            clash_proxy["client-fingerprint"] = server_conf.client_fingerprint
    return clash_proxy
