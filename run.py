import argparse
from intel import intel
from esconnect import es

#Run as windows service - schedule task - cronjob
#Compare query to intel index
#If already exist in intel index ignore
#If not in index, query VT and write to index
#If score is higher than X than send email(s)

desc = 'Intel Checker'
parser = argparse.ArgumentParser(description=desc)
parser.add_argument("--domain", "-d", help="Example: www.google.com")
args = parser.parse_args()

if args.domain:
  domain = intel(args.domain, 'dns')
  print("Domain provided")

  if domain.matchregex:
    print("Domain validated")
    domain.checkdomain()
  print("The domain \"{0}\" has a total of {1} hits from {2} intel sources.".format(domain.data, domain.score, domain.totalsources))