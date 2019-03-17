import requests
import re
import configparser
import os.path

config = configparser.ConfigParser()
if os.path.isfile('enricher_custom.conf'):
    config.read('enricher_custom.conf')
else:
    config.read('enricher.conf')

class intel():
  def __init__(self, data, datatype, apikey=None, url=None, hasdata=False):
    self.data = data
    self.datatype = datatype
    self.apikey = apikey
    self.url = url
    self.hasdata = hasdata
    self.score = 0
    self.matchregex=False
    
    if self.datatype == 'dns':
      self.url = 'https://www.virustotal.com/vtapi/v2/url/report'
      self.regex = re.compile('(^[\d\w-]+\.[\d\w]+$)')
      self.apikey = config['DEFAULT']['apikey']
      self.cleanregex = re.compile('(^(?!(clean|unrated)))')

    if self.datatype == 'sha256':
      self.url = 'https://www.virustotal.com/vtapi/v2/file/report'
      self.regex = re.compile('([A-Fa-f0-9]{64})')
      self.apikey = config['DEFAULT']['apikey']
      self.cleanregex = re.compile('(^(?!(None)))')
      
    if re.match(self.regex, self.data):
      self.matchregex = True

  def check(self):
    params = {'apikey': self.apikey, 'resource': self.data}
    response = requests.get(self.url, params=params)
    print(response)
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
        if value == None:
          self.score = self.score +1

      #Adjust for the domain entry
      if self.totalsources > 0:
        self.totalsources = self.totalsources - 1
