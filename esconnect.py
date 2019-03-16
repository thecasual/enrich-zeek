from elasticsearch import Elasticsearch
import configparser
import datetime
from elasticsearch_dsl import Search
import json

config = configparser.ConfigParser()
config.read('enricher.conf')
eshost = config['DEFAULT']['eshost']
servertimeout = int(config['DEFAULT']['servertimeout'])

class es():
  def __init__(self):
    self.eshost = config['DEFAULT']['eshost']
    self.servertimeout = int(config['DEFAULT']['servertimeout'])
    self.search = ""
    self.client = ""
    self.result = ""
    self.list = set()

  def connect(self):
    self.client = Elasticsearch(hosts=self.eshost, timeout=self.servertimeout)

#Example query object --> Search(using=client.client, index='*:logstash-bro*').query({"match" : {"event_type":"bro_dns"}}).filter('range', ** { '@timestamp': {'gt': 'now-15m'}})
  def query(self):
    self.result = self.search.execute()
    for i in self.result:
      self.list.add(i.query)