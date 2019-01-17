from urllib.parse import urlparse
import re
import requests

# 1= legitimate, -1= phishing, 0 =suspicious

# using IP address

def ipaddr(addr):
    valid = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",addr)
    if valid:
        return -1
    else:
        return 1


# HEX in path
def hexurl(addr):
    valid = re.match("(0x[0-9A-F]+.){4}", addr)
    if valid:
        return -1
    else:
        return 1


# long url: leng<54 =1,  leng >=54 || leng <=75 =0, >75 =-1
def longurl(addr):
    if len(addr) > 75:
        return -1
    elif len(addr) < 54 :
        return 1
    else:
        return 0

# URL shortening: tiny =-1, otherwise =1
def shortenurl(addr):
    parsed = requests.head(addr, allow_redirects=True).url
    if parsed != addr:
        return -1
    else:
        return 1

# having @ symbol: true =-1, false =1
def symbol(addr):
    if '@' in addr:
        return -1
    else:
        return 1


# redirecting by //
# // appear more than 1 =-1. else =1
def redirecting(addr):
    if addr.count('//') > 1:
        return -1
    else:
        return 1



# existing of "-" : true =-1, false =1
# e.g. http://www.Confirme-paypal.com/
def domaincontainsymbol(addr):
    pass


# subDomain and multi sub domain
def domainPart(addr):
    pass


# https certificate:
# trusted && >1yr =1, https && not trusted =0, otherwise =-1
def httpscert(addr):
    pass


# domains registration length:
# <=1yrs =-1, otherwise =1
def domainexpires(addr):
    pass


# the existence of https token in domain domainPart
# e.g. http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/
def domainhttps(addr):
    pass


# age of domain
# >=6 months =1, otherwise =-1
def ageofdomain(addr):
    pass


# DNS records
# no records =-1, otherwise =1
def dnsrecord(addr):
    pass


# website Rank: <10000 =1, >10000 =0, otherwise =-1
def webrank(addr):
    pass


# pageRank: <0.2 =-1, otherwise= 1
def pagerank(addr):
    pass


if __name__ == "__main__":
    url = ""
    path = urlparse(url)
    ipaddr(path.netloc)
    hexurl(path.netloc)
    longurl(url)
    shortenurl(url)
    # unfinished
    symbol(url)
    redirecting(url)
    domaincontainsymbol(url)
    domainPart(url)
    httpscert(url)
    domainexpires(url)
    domainhttps(url)
    ageofdomain(url)
    dnsrecord(url)
    webrank(url)
    pagerank(url)
