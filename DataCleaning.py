from urllib.parse import urlparse
from tld import get_tld
from datetime import date, datetime
import re, ssl, socket, requests
import pandas as pd
import numpy as ny
import whois


# 1= legitimate, -1= phishing, 0 =suspicious
# using IP selfess

class DataCleaning:

    def __init__(self, url):
        self.url = url
        self.path = urlparse(self.url)
        self.date = datetime.now()

    # print(self.path)

    def ip(self):
        valid = re.match(
            "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
            self.path.netloc)
        if valid:
            return -1
        else:
            return 1

    # HEX in path
    def hex_url(self):
        valid = re.match("(0x[0-9A-F]+.){4}", self.path.netloc)
        if valid:
            return -1
        else:
            return 1

    # long url: leng<54 =1,  leng >=54 || leng <=75 =0, >75 =-1
    def long_url(self):
        if len(self.url) > 75:
            return -1
        elif len(self.url) < 54:
            return 1
        else:
            return 0

    # URL shortening: tiny =-1, otherwise =1
    def shorten(self):
        parsed = requests.head(self.url, allow_redirects=True).url
        if parsed != self.url:
            return -1
        else:
            return 1

    # having @ symbol: true =-1, false =1
    def symbol(self):
        if '@' in self.url:
            return -1
        else:
            return 1

    # redirecting by //
    # // appear more than 1 =-1. else =1
    def redirecting(self):
        if self.url.count('//') > 1:
            return -1
        else:
            return 1

    # existing of "-" : true =-1, false =1
    # e.g. http://www.Confirme-paypal.com/
    def domain_contain_symbol(self):
        if '-' in self.url:
            return -1
        else:
            return 1

    # subDomain and multi sub domain
    def domain_part(self):
        res = get_tld(self.url, as_object=True)
        domain = self.path.netloc
        # print(res.tld)
        d = domain.replace('.' + res.tld, '')
        d = d.replace('www.', '')
        # print(d.count('.'))
        if d.count('.') > 2:
            return -1
        elif d.count('.') > 1:
            return 0
        else:
            return 1

    # https certificate:
    # trusted && >1yr =1, https && not trusted =0, otherwise =-1
    def https_cert(self):
        try:
            hostname = self.path.netloc
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            d0 = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            d1 = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            age = d1 - d0
            issuer = dict(x[0] for x in cert['issuer'])
            issued_by = issuer['organizationName']
            df = pd.read_csv('trustedCertAuthority.csv')
            authority = df.issuer.unique()
            if age.days > 365 and issued_by in authority:
                return 1
            else:
                return 0
        except:
            return -1

    # the existence of https token in domain domainPart
    # e.g. http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/
    def domain_https(self):
        if 'https' in self.path.netloc:
            return -1
        else:
            return 1

    # age of domain
    # >=6 months =1, otherwise =-1
    def age_of_domain(self):
        try:
            # print(self.path.netloc)
            domain = whois.query(self.path.netloc)
            reg_age = self.date - domain.creation_date
            if reg_age.days <= 365:
                return -1
            else:
                return 1
        except:
            return 0

    # DNS records
    # no records =-1, otherwise =1
    def dns_record(self):
        try:
            # print(self.path.netloc)
            domain = whois.query(self.path.netloc)
            if len(domain.name_servers) > 0:
                return 1
            else:
                return -1
        except:
            return 0
