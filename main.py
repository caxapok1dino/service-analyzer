# -------------------------
# imports 
import parser
import utils

from pprint import pprint
# -------------------------
class Path:
    def __init__(self, base_path) -> None:
        self.base_path = base_path
        self.dump_path = self.base_path + "dump/"
        # self.ssl_keyfile = self.dump_path + "ssl.log"
        self.links_path = self.base_path + "links.txt"
        self.wireshark_stats_path = self.base_path + 'wireshark_ips.csv'

class Service:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.save_path = self.path.base_path + "results.json"
        self.ips = None
        self.hosts = None
        self.domains = None
        self.paths = None
        self.paths_list = None
        self.path_trie = None
    
    def analyze(self):
        self.ips = parser.parse_wireshark_stats(self.path.wireshark_stats_path)
        self.hosts, self.domains, self.paths, self.paths_list, self.path_trie = parser.parse_links_file(self.path.links_path)


    def __dict__(self):
        return {
            "path": self.path.base_path,
            "ip": self.ips,
            "hosts": self.hosts,
            "domains": self.domains,
            "paths": self.paths,
            "path_relations": self.path.base_path + "path-tree.txt",
            "path_trie": self.path_trie.to_dict(),
            "top15": {
                "ip": self.ips.most_common(15),
                "domain": self.domains.most_common(15),
                "hosts": self.hosts.most_common(15),
                "paths": self.paths.most_common(15)
            }
        }
    
    def save(self):
        utils.json_save(self.__dict__(), self.save_path)
        with open(self.path.base_path + "path-tree.txt", "w") as f:
            f.write(parser.print_tree(self.path_trie))

# =========================
# alibaba
# -------------------------
alibaba = Service(Path("alibaba/"))


# =========================
# ivi
# -------------------------
ivi = Service(Path("ivi/"))
ivi.analyze()
ivi.save()


# =========================
# megamarket
# -------------------------
megamarket = Service(Path("megamarket/"))
megamarket.analyze()
megamarket.save()

# hostnames, paths, connected = parser.parse_links_file(megamarket_path.links_path, r"(?:[\w\-\.]+)?(?:[\w\-])?megamarket\.[\w]+")


# =========================
# kinopoisk
# -------------------------
kinopoisk_path = Path("kinopoisk/")


