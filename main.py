#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os.path
import sys
import getopt
import yaml
from utils.subscription import *

SUBSCRIPTION_URL = (
    "https://jjsubmarines.com/members/getsub.php?service={0}&id={1}&usedomains=1"
)


SERVERS_PRIORITY = [3, 5, 1, 2, 4, 801]


def grab_subscriptions(service_id: str, uuid: str, fallback: None or str, path: str):
    url = SUBSCRIPTION_URL.format(service_id, uuid)
    cache_file = os.path.join(os.path.dirname(path), "cache.txt")
    try:
        result = subscription_to_servers(url, cache_file)
    except InternalError as e:
        print("无法读取订阅链接，尝试使用上次缓存……", file=sys.stderr)
        try:
            result = cache_to_servers(cache_file)
        except InternalError as e:
            print(e.message, file=sys.stderr)
            result = list()

    if fallback:
        fb_server = uri_to_server(fallback)
        result.insert(0, fb_server)
    return result


def generate_clash_config(
    proxies: list, path: str, listen: int, allow_len: bool, support_meta: bool
):
    clash_config = {
        "allow-lan": allow_len,
        "port": listen,
        "socks-port": listen + 1,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": "127.0.0.1:9090",
        "proxies": [],  # wait to fill
        "proxy-groups": [
            {
                "name": "jms-available",
                "type": "fallback",
                "proxies": [],  # wait to fill
                "url": "https://cp.cloudflare.com/",
                "interval": 300,
            },
            {"name": "manual", "type": "select", "proxies": ["jms-available"]},
        ],
        "rules": ["MATCH,manual"],
    }

    if support_meta:
        clash_config["rule-providers"] = {
            "custom-direct": {
                "type": "file",
                "behavior": "classical",
                "path": "./custom-direct.yaml",
            }
        }
        clash_config["rules"] = [
            "RULE-SET,custom-direct,DIRECT",
            "GEOSITE,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "GEOIP,LAN,DIRECT,no-resolve",
        ] + clash_config["rules"][:1]
        if allow_len:
            clash_config["bind-address"] = "*"

    for proxy in proxies:
        clash_proxy = server_conf_2_dict(proxy)
        clash_config["proxies"].append(clash_proxy)
        clash_config["proxy-groups"][0]["proxies"].append(proxy.tag)

        def proxy_sort_cmp(s: str) -> int:
            try:
                sid = int(s.split("@")[1].split(".")[0].split("s")[1])
                return SERVERS_PRIORITY.index(sid)
            except ValueError:
                return 99
            except KeyError:
                return 99
            except Exception:
                return 99

        clash_config["proxy-groups"][0]["proxies"].sort(
            reverse=False, key=proxy_sort_cmp
        )

    if not path:
        return  # dry run ?

    try:
        with open(path, "w") as f:
            yaml.dump(clash_config, f)
    except Exception as e:
        print(e, file=sys.stderr)
        raise InternalError("Can not dump yaml to path: '" + path + "'.")


def main():
    path = None
    listen = 1082
    allow_lan = False
    service = ""
    uuid = ""
    fallback = None
    support_meta = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "mnf:p:s:u:b:")
        for opt, arg in opts:
            if opt == "-f":
                path = arg
            elif opt == "-p":
                listen = int(arg)
            elif opt == "-n":
                allow_lan = True
            elif opt == "-s":
                service = arg
            elif opt == "-u":
                uuid = arg
            elif opt == "-b":  # fallback
                fallback = arg
            elif opt == "-m":
                support_meta = True

        server_confs = grab_subscriptions(service, uuid, fallback, path)
        generate_clash_config(server_confs, path, listen, allow_lan, support_meta)
    except getopt.GetoptError:
        print(
            "使用参数 -f /path/to/clash_config.yaml -p 1082 -s service_id -u uuid",
            file=sys.stderr,
        )
    except InternalError as e:
        print(e.message, file=sys.stderr)


# 按间距中的绿色按钮以运行脚本。
if __name__ == "__main__":
    main()
