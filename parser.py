import requests
from collections import Counter, defaultdict
import os
import csv
import socket
import re
import utils
from typing import Dict, List, Any

from collections import defaultdict, Counter
import re

class TrieNode:
    def __init__(self):
        # сколько раз этот узел посетили
        self.count: int = 0
        # дочерние узлы: segment -> TrieNode
        self.children: Dict[str, TrieNode] = {}

    def insert(self, path: str):
        segments = [seg for seg in path.strip("/").split("/") if seg]
        node = self
        node.count += 1
        for seg in segments:
            if seg not in node.children:
                node.children[seg] = TrieNode()
            node = node.children[seg]
            node.count += 1

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "children": {
                seg: child.to_dict()
                for seg, child in self.children.items()
            }
        }

    def __repr__(self):
        return f"<TrieNode count={self.count} children={list(self.children)}>"

def print_tree(node: TrieNode, name: str = "/", prefix: str = "") -> str:
    lines = []

    def helper(n, name, prefix_line, prefix_children) -> str:
        lines.append(f"{prefix_line}{name} ({n.count})")
        children = list(n.children.items())
        for idx, (seg, child) in enumerate(children):
            last = (idx == len(children) - 1)
            new_prefix_line = prefix_children + ("└── " if last else "├── ")
            new_prefix_children = prefix_children + ("    " if last else "│   ")
            helper(child, seg, new_prefix_line, new_prefix_children)

    helper(node, name, "", "")
    return "\n".join(lines)

def parse_crtsh(domain) -> Any:
    hosts = Counter()
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    })
    response = session.get(f"https://crt.sh/?q={domain}&output=json")
    if response.status_code != 200:
        print("fault ", response.status_code, response.text)
        return 
    for res in response.json():

        clean = re.findall(r"(\*\.)?(.*)", res["common_name"])
        if len(clean) < 1:
            continue
        hosts[clean[0][1]] += 1
        names = res["name_value"].split("\n")
        for name in names:
            clean = re.findall(r"(\*\.)?(.*)", name)
            if len(clean) < 1:
                continue
            hosts[clean[0][1]] += 1
    # utils.json_save(response.json(), "ivi.json")
    # utils.json_save(hosts.most_common(20), "host.json")
    return hosts.most_comon(25)

def run_subfinder(domain, output, wordlist="~/wordlists/subdomains-ffuf.txt"):
    os.exec(f"subfinder -dL {wordlist} -d {domain} >> {output}")

def parse_wireshark_stats(filename) -> Counter:
    ip = Counter()
    with open(filename, "r") as f: 
        reader = csv.reader(f.read().strip().split("\n")[2:])
        for row in reader:
            ip[row[2]] += int(row[3]) if row[3] else 0
    return ip

def get_ip_list(filename) -> List[str]:
    ips = list()
    with open(filename, "r") as f: 
        reader = csv.reader(f.read().strip().split("\n")[2:])
        for row in reader:
            ips.append(row[2])
    return sorted(list(ips), key=lambda x: socket.inet_aton(x))

def parse_links_file(filename, regex=None):
    root = TrieNode()
    hostnames = Counter()
    domains = Counter()
    http_path = Counter()
    hostname2path = defaultdict(set)
    with open(filename, "r") as f:
        for line in f.readlines():
            matches = re.findall(r"^(?:(?:https?):\/\/)?([^\/?#]+)(\/[^?#]*)?(?:\??([^#]*))", line)
            if len(matches) == 0:
                continue
            link = matches[0]
            if not regex:
                match = link[0]
            else:
                match = re.findall(regex, link[0])
                if len(match) == 0:
                    continue
                match = match[0]
            domain = re.findall(r"(?:.*\.)?(.*\..*)", match)
            
            path = link[1].strip()
            if len(domain):
                domains[domain[0]] += 1
            hostnames[match] += 1
            root.insert(path)
            http_path[link[1].strip()] += 1
            if match not in hostname2path:
                hostname2path[match] = set()
            hostname2path[match].add(link[1])
    return hostnames, domains, http_path, hostname2path, root

def parse_sitemap(url) -> Counter:
    links_cnt = Counter()
    res = requests.get(url).text
    links = re.findall(r"(?:<loc>)(https?:\/\/[\d\w\.\-\/]+)(?:<\/loc>)", res)
    for link in links:
        if link[-4:] == ".xml":
            rec = parse_sitemap(link)
            for i in rec:
                links_cnt[i] += rec[i]
        links_cnt[link] += 1
    return links_cnt

def parse_robots_txt(hostname) -> Counter:
    url = f"https://{hostname}/robots.txt"
    print(url)
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    })
    res = session.get(url)
    print(res.text)
    if res.status_code != 200:
        return links
    links = re.findall(r"(?:Disa|A)llow:.?(.*)", res.text.strip())
    return Counter(links)
    