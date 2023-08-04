#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import getopt
import base64
import requests
import json
import yaml

SUBSCRIPTION_URL = \
    'https://jmssub.net/members/getsub.php?service={0}&id={1}&usedomains=1'

SS = "shadowsocks"
VMESS = "vmess"
SERVERS_PRIORITY = [3, 5, 1, 2, 4, 801]


class InternalError(Exception):
    def __init__(self, msg):
        self.message = msg


class ServerInfo:
    def __init__(self, protocol: str):
        self.protocol = protocol
        self.host = ''
        self.port = 0
        self.key = ''
        self.algorithm = ''
        self.alter_id = 0
        self.net = 'tcp'
        self.camouflage = 'none'
        self.tls = ''
        self.sni = ''
        self.addition = ''
        self.tag = ''


def base64decode(encoded: str) -> bytes:
    try:
        encoded += "=" * ((4 - len(encoded) % 4) % 4)
        return base64.decodebytes(encoded.encode("utf-8"))
    except Exception as e:
        print(e)


def decode_shadowsocks(ss_server_str: str):
    info = ServerInfo(SS)
    s_tag = ss_server_str.split('#')
    if len(s_tag) > 1:
        info.tag = s_tag[1]
    if len(s_tag) > 0:
        server = s_tag[0]
        try:
            server = base64decode(server).decode("utf-8")
        except UnicodeDecodeError:
            raise InternalError("shadowsocks server can't decode to utf-8")

        auth_server = server.split('@')
        if len(auth_server) > 1:
            host_port = auth_server[1]
            method_key = auth_server[0]
        else:
            return None

        [info.algorithm, info.key] = method_key.split(':')
        [info.host, port] = host_port.split(':')
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
    info.tag = vmess_conf.get('ps', '')
    info.host = vmess_conf.get('add', '')
    info.port = int(vmess_conf.get('port', '0'))
    info.tls = vmess_conf.get('tls', info.tls)
    info.alter_id = int(vmess_conf.get('aid', '0'))
    info.key = vmess_conf.get('id', '')
    info.sni = vmess_conf.get('sni', '')
    info.camouflage = vmess_conf['type'] or 'none'
    info.net = vmess_conf.get('net', info.net)
    info.algorithm = 'auto'
    return info


def grab_subscriptions(service_id: str, uuid: str, fallback: None or str):
    result = list()
    try:
        resp = requests.get(SUBSCRIPTION_URL.format(service_id, uuid))
    except Exception:
        raise InternalError("requests.get raises exceptions.")
    if not resp.ok:
        raise InternalError("requests.get's response not ok.")

    server_confs_bs = base64decode(resp.text)
    try:
        server_confs_str = server_confs_bs.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise InternalError("subscription b64 decoded result can not decode to string by utf-8")

    server_confs = server_confs_str.split('\n')

    if fallback is not None:
        server_confs.append(fallback)

    for server_conf in server_confs:
        p_s = server_conf.split('://')
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

        if info is not None:
            result.append(info)

    return result


def generate_clash_config(proxies: list, path: str, listen: int, allow_len: bool):
    clash_config = {
        "allow-lan": allow_len,
        "mixed-port": listen,
        "mode": "rule",
        "external-controller": "127.0.0.1:9090",
        "proxies": [],  # wait to fill
        "proxy-groups": [
            {
                "name": "fastest",
                "type": "fallback",
                "proxies": [],  # wait to fill
                "url": "https://cp.cloudflare.com/",
                "interval": 300
            }
        ],
        "rules": [
            "MATCH,fastest"
        ]
    }

    for proxy in proxies:
        clash_proxy = {
            "name": proxy.tag,
            "type": 'vmess' if proxy.protocol == VMESS else 'ss',
            "server": proxy.host,
            "port": proxy.port,
            "cipher": proxy.algorithm,
            "uuid" if proxy.protocol == VMESS else "password":
                proxy.key,

        }

        if proxy.protocol == VMESS:
            clash_proxy['alterId'] = proxy.alter_id
            clash_proxy['network'] = proxy.net
            clash_proxy['tls'] = proxy.tls == 'tls'
            if proxy.tls == 'tls':
                clash_proxy['skip-cert-verify'] = True

        clash_config["proxies"].append(clash_proxy)
        clash_config['proxy-groups'][0]['proxies'].append(proxy.tag)

        def proxy_sort_cmp(s: str) -> int:
            try:
                sid = int(s.split('@')[1].split('.')[0].split('s')[1])
                return SERVERS_PRIORITY.index(sid)
            except ValueError:
                return 99
            except KeyError:
                return 99
            except Exception:
                return 99

        clash_config['proxy-groups'][0]['proxies'].sort(reverse=False, key=proxy_sort_cmp)

    if not path:
        return  # dry run ?

    try:
        with open(path, 'w') as f:
            yaml.dump(clash_config, f)
    except Exception as e:
        print(e, file=sys.stderr)
        raise InternalError("Can not dump yaml to path: '" + path + "'.")


def main():
    path = None
    listen = 1082
    allow_lan = False
    service = ''
    uuid = ''
    fallback = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "nf:p:s:u:b:")
        for opt, arg in opts:
            if opt == '-f':
                path = arg
            elif opt == '-p':
                listen = int(arg)
            elif opt == '-n':
                allow_lan = True
            elif opt == '-s':
                service = arg
            elif opt == '-u':
                uuid = arg
            elif opt == '-b':  # fallback
                fallback = arg

        server_confs = grab_subscriptions(service, uuid, fallback)
        generate_clash_config(server_confs, path, listen, allow_lan)
    except getopt.GetoptError:
        print("使用参数 -f /path/to/clash_config.yaml -p 1082 -s service_id -u uuid", file=sys.stderr)
    except InternalError as e:
        print(e.message, file=sys.stderr)


# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':
    main()
