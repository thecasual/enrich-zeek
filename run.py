import argparse
from intel import intel
from esconnect import es
from elasticsearch_dsl import Search

#Run as windows service - schedule task - cronjob
#Compare query to intel index
#If already exist in intel index ignore
#If not in index, query VT and write to index
#If score is higher than X than send email(s)

desc = 'Intel Checker'
parser = argparse.ArgumentParser(description=desc)
parser.add_argument("--domain", "-d", help="Example: www.google.com")
parser.add_argument("--file", "-f", help="Example: aca2d12934935b070df8f50e06a20539")
args = parser.parse_args()

if args.domain:
  domain = intel(args.domain, 'dns')
  print("Domain provided")

  if domain.matchregex:
    print("Domain validated")
    domain.check()
    if domain.hasdata == True:
      domain.parse()
      print("The domain \"{0}\" has a total of {1} hits from {2} intel sources.".format(domain.data, domain.score, domain.totalsources))
    else:
      print("Domain does not exist or hit rate limit")  
  else:
    print("Domain does not match.")
    exit()

if args.file:
  file=intel(args.file, 'sha256')
  print("Hash provided")
  if file.matchregex:
    file.check()
    
    if file.hasdata == True:
      file.parse()
      print("The hash \"{0}\" has a total of {1} hits from {2} intel sources.".format(file.data, file.totalsources-file.score, file.totalsources))
    else:
      print("File does not exist or hit rate limit")  
  else:
    print("Hash does not match.")
    exit()
  

#ES Tester
#client = es()
#client.connect()
#client.search = Search(using=client.client, index='*:logstash-bro*').query({"match" : {"event_type":"bro_dns"}}).filter('range', ** { '@timestamp': {'gt': 'now-15m'}})
#client.query()
#print(client.list)