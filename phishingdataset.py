import pandas as pd
from DataCleaning import DataCleaning

df = pd.read_csv('verified_online.csv')
df2 = DataCleaning(df.url)
print(df2.dns_record())
