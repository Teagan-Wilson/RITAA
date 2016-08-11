#Graylog Stream Query Service
#Teagan Wilson
#7/29/16
#Pulls Data from a Graylog Stream, parses it and inserts into a MongoDB instance
from pymongo import MongoClient
import pymongo
import json
import requests
import time
import urllib2
import re

#Setup Database Connection
client = MongoClient()
db = client.queue

#Static Variables
timestamp = int(time.time())
ipurl = 'https://graylog.shickusa.com:12900/search/universal/relative?query=*&range=60&limit=1000&filter=streams:5798f1ad4894b436df435fa6'
dnsurl = 'https://graylog.shickusa.com:12900/search/universal/relative?query=*&range=60&limit=1000&filter=streams:579a55dc4894b42940bbad7f'
auth = ("", "")
params = {'fields': 'IP,Name', 'Accept' : 'application/json'}
headers = {'Accept': 'application/json','fields': 'IP'}


#Query Stream Function
def QueryGLS(url):
	response = requests.get(url, auth=auth, params=params, headers=headers)
	loaded_content = json.loads(response.content)
	return loaded_content

#Insert IP Function
def insertIP( ip, timestamp ):
	result = db.tolookupip.insert_one({ "ip": ip, "timestamp": timestamp})

#Insert DNS Function
def insertDNS( url , timestamp ):
	result = db.tolookupdnso.insert_one({ "url": url, "timestamp": timestamp})
	print result.inserted_id
	
#Get Streams from Graylog
#slipstreamIP = QueryGLS(ipurl)


slipstreamDNS = QueryGLS(dnsurl)

#Process IP Stream and Insert into Queue
#for ip in slipstreamIP['messages']:
#	print(ip['message']['IP'])
#	insert(ip['message']['IP'],timestamp)
 
#Process DNS logs and Insert into Queue
for ip in slipstreamDNS['messages']:
	pat = re.compile("\(0\)")
	ip['message']['Name'] = pat.sub("",ip['message']['Name'])
	pat = re.compile("^\.")
	ip['message']['Name'] = pat.sub("",ip['message']['Name'])
	pat = re.compile("(\(\w+\))+")
	ip['message']['Name'] = pat.sub(".",ip['message']['Name'])
	insertDNS(ip['message']['Name'],timestamp)
	
