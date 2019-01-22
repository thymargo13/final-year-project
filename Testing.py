from DataCleaning import DataCleaning
import pandas as pd
import numpy as ny

features = ['ip', 'hex', 'long', 'shorten', '@symbol', 'doubleslash', 'hyphen', 'multisubdomain', 'httpscert',
            'httpsdomain', 'domainage', 'dnsrecord', 'result']
'''
 get phishing url from phish Tank
'''
api_key = "1154bab9c6e0918ce8d9f5a83157eba11499d11ba63d7ed5a1b70bab3ff17923"
phishingUrl = 'http://data.phishtank.com/data/' + api_key + '/online-valid.csv'
df = pd.read_csv(phishingUrl)
print(df.url.head())

'''
 get legitimated url from page rank
'''
'''
 generate data set 
'''
a = DataCleaning(df.url)  # url要一個一個LOOP 入去阿!!
# ip(), hex_url(), long_url(), shorten(), symbol(), redirecting(), domain_contain_symbol(), domain_part(),
# https_cert(), domain_https() ,age_of_domain(), dns_record(), result

# print(a.ip())
# print(b.httpscert())


'''
class Testing:
    def __init__(self, num1, num2):
        self.abc = num1
        self.bcd = num2
        self.num3 = 5

    def add(self):
        print(self.abc + self.bcd + self.num3)


if __name__ == '__main__':
    print("hello world")
    t1 = Testing(4, 5)
    t1.add()
'''
