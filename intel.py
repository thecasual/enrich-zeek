import requests
import re

class intel():
  def __init__(self, data, apikey):
    self.data = data
    self.apikey = apikey
    self.datatype = ""
    self.regex = "gimmie error!"
    self.score = 0
    self.matchregex = False
    self.hasdata = False
    domainregex = re.compile('(^[\d\w-]+\.[\d\w]+$)')
    hashregex = re.compile('(^[A-Fa-f0-9]{64}$)')

    if re.match(domainregex, self.data):
      self.datatype = 'dns'

    if re.match(hashregex, self.data):
      self.datatype = 'hash'

    if self.datatype == 'dns':
      self.url = 'https://www.virustotal.com/vtapi/v2/url/report'
      self.regex = domainregex
      self.cleanregex = re.compile('(^(?!(clean|unrated)))')

    if self.datatype == 'hash':
      self.url = 'https://www.virustotal.com/vtapi/v2/file/report'
      self.regex = hashregex
      self.cleanregex = re.compile('(^(?!None))')

    if re.match(self.regex, self.data):
      self.matchregex = True

  def check(self):
    params = {'apikey': self.apikey, 'resource': self.data}
    response = requests.get(self.url, params=params)
    if response.status_code==200:
      self.response = response.json()
      if self.response['verbose_msg'] == 'Scan finished, scan information embedded in this object':
        self.hasdata=True  
      if self.response['verbose_msg'] == 'Scan finished, information embedded':
        self.hasdata=True 

  def parse(self):
    self.message = {}

    if self.response['verbose_msg'] == 'Resource does not exist in the dataset':
      print("Resource does not exist in the dataset")
      return "Resource does not exist in the dataset"
    else:
      self.datatype = self.data

      for sources in self.response["scans"]:
        self.message[sources] = self.response["scans"][sources]["result"]
        
      self.totalsources = len(self.message)

      for key, value in self.message.items():
        if re.match(self.cleanregex, str(value)):
          self.score = self.score +1

      