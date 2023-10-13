#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import getopt
import os.path
import sys
import yaml

from utils.subscription import *


def link_to_servers(link: str):
    if not link:
        return None

    return subscription_to_servers(link, None)


def generate_proxy_providers(server_confs, path: str):
    configs = {"proxies": []}

    for server_conf in server_confs:
        configs["proxies"].append(server_conf_2_dict(server_conf))

    try:
        with open(path, "w") as f:
            yaml.dump(configs, f)
    except Exception as e:
        print(e, file=sys.stderr)
        raise InternalError("Can not dump yaml to path: '" + path + "'.")


def modify_main_config(main_conf_path: str, provider_conf_path: str, name: str):
    if not main_conf_path:
        raise InternalError("no main config path passed.")
    _, provider_file_name = os.path.split(provider_conf_path)
    clash_config: dict or None = None
    try:
        with open(main_conf_path, "r") as f:
            clash_config = yaml.safe_load(f)
    except Exception as e:
        print(e, file=sys.stderr)
        raise InternalError("Can not load yaml from path: '" + main_conf_path + "'.")

    if not clash_config:
        raise InternalError("Can not load yaml from path: '" + main_conf_path + "'.")

    name = name or "extra"
    provider_name = name + "-provider"
    provider = {
        "type": "file",
        "path": "./" + provider_file_name,
        "health-check": {
            "enable": True,
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 300,
        },
    }

    if "proxy-providers" in clash_config.keys():
        clash_config["proxy-providers"][provider_name] = provider
    else:
        clash_config["proxy-providers"] = {provider_name: provider}

    clash_config["proxy-groups"].append(
        {
            "name": name,
            "type": "url-test",
            "use": [provider_name],
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 300,
        }
    )

    for group in clash_config["proxy-groups"]:
        if group["name"] == "manual":
            group["proxies"].append(name)
            break

    try:
        with open(main_conf_path, "w") as f:
            yaml.dump(clash_config, f)
    except Exception as e:
        print(e, file=sys.stderr)
        raise InternalError("Can not dump yaml to path: '" + main_conf_path + "'.")


def main():
    path = None
    link = None
    main_conf_path = None
    name = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "l:f:m:n:")
        for opt, arg in opts:
            if opt == "-f":
                path = arg
            elif opt == "-l":
                link = arg
            elif opt == "-m":
                main_conf_path = arg
            elif opt == "-n":
                name = arg

        server_confs = link_to_servers(link)
        generate_proxy_providers(server_confs, path)
        modify_main_config(main_conf_path, path, name)
    except getopt.GetoptError:
        print(
            "使用参数 -f /path/to/proxy-providers.yaml -l https://location.subscription/url",
            file=sys.stderr,
        )
    except InternalError as e:
        print(e.message, file=sys.stderr)


if __name__ == "__main__":
    main()
