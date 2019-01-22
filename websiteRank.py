import requests
import re


class website_rank:
    def __init__(self, domain):
        self.url = "https://www.alexa.com/siteinfo/" + domain

    def __search_regex(self, regex, phrase):
        match = re.search(regex, phrase)
        if match:
            return match.group(1)

    def check(self):
        r = requests.get(self.url)
        page = str(r.text).split("\n")
        print(page)
        found_global = False
        for line in page:
            if "</strong>" in line and any(char.isdigit() for char in line):
                perspective = line.replace(',', '')
                found = self.__search_regex("(\d+)\s+<", perspective)
                if found and found[:1] != "0":
                    if not found_global:
                        found_global = True
                        yield ("global_rank", found)
            if "Flag" in line and "nbsp" in line:
                perspective = line.replace(',', '')
                country = self.__search_regex(".*\w+;(.*)</a>", perspective)
                country_rank = self.__search_regex(".*>(\d+)<", perspective)
                yield (country, country_rank)

if __name__ == "__main__":
    for rank_tuple in website_rank('google.com').check():
        print(rank_tuple)
