import datetime

t = datetime.datetime.now(datetime.timezone.utc)
amzdate = t.strftime('%Y%m%dT%H%M%SZ')
datestamp = t.strftime('%Y%m%d')
print("amzdate:", amzdate)
print("datestamp:", datestamp)
