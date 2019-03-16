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

    if self.datatype == 'dns':
      self.url = 'https://www.virustotal.com/vtapi/v2/url/report'
      self.regex = re.compile('(^(www\.|https:\/\/)(?=[\s\S]+\.[\s\S]+$)[\w\d-]+\.\w+|(?=[\s\S]+\.[\s\S]+$))')
      self.apikey = config['DEFAULT']['apikey']

    if re.match(self.regex, self.data):
      self.matchregex = True

  def checkdomain(self):
    params = {'apikey': self.apikey, 'resource': self.data}
    response = requests.get(self.url, params=params)
    self.response = response.json()
    #Maybe add check here to see if data is good
    self.hasdata = True
    if self.hasdata == True:
      self.parsedomain()

  def parsedomain(self):
    self.message = {}
    if self.response['verbose_msg'] == 'Resource does not exist in the dataset':
      print("Resource does not exist in the dataset")
      return "Resource does not exist in the dataset"
    else:
      self.message['Domain'] = self.response["resource"]
      for i in self.response["scans"]:
        self.message[i] = self.response["scans"][i]["result"]