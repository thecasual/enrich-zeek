import argparse
from intel import intel
from esconnect import es
from elasticsearch_dsl import Search
import configparser
import os.path

#Run as windows service - schedule task - cronjob
#Compare query to intel index
#If already exist in intel index ignore
#If not in index, query VT and write to index
#If score is higher than X than send email(s)


config = configparser.ConfigParser()
if os.path.isfile('enricher_custom.conf'):
    config.read('enricher_custom.conf')
else:
    config.read('enricher.conf')
apikey = config['DEFAULT']['apikey']


desc = 'Intel Checker'
parser = argparse.ArgumentParser(description=desc)
parser.add_argument("--data", "-d", help="Example: google.com or F68E37DC9CABF2EE8B94D6A5D28AD04BE246CCC2E82911F8F1AC390DCF0EE364")
args = parser.parse_args()

if args.data:
  data = intel(args.data, apikey)

  if data.matchregex:
    print("{0} matches the regex for {1}".format(data.data, data.datatype))
    data.check()

    if data.hasdata == True:
      data.parse()
      print("The query \"{0}\" has a total of {1} hits from {2} intel sources.".format(data.data, data.score, data.totalsources))
    else:
      print("Data does not exist or the rate limit has been met")  
  else:
    print("Query provided does not match an accepted value")
    exit()

#ES Tester
#client = es()
#client.connect()
#client.search = Search(using=client.client, index='*:logstash-bro*').query({"match" : {"event_type":"bro_dns"}}).filter('range', ** { '@timestamp': {'gt': 'now-15m'}})
#client.query()
#print(client.list)