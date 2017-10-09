#!/usr/bin/python
#
#DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#                    Version 3, August 2017
#Everyone is permitted to copy and distribute verbatim or modified
#copies of this license document, and changing it is allowed as long
#as the name is changed.
#           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
# TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
#
#1. You just DO WHAT THE FUCK YOU WANT TO.
#2. As the "THE BEER-WARE LICENSE", if we meet some day, and you
# think this stuff is worth it, you can buy me a beer in return.
#
#         ///\\\  ( Have Fun )
#        / ^  ^ \ /
#      __\  __  /__
#     / _ `----' _ \
#     \__\   _   |__\
#      (..) _| _ (..)
#       |____(___|     Mynameisv
#_ __ _ (____)____) _ _________________________________ _'
###########################################################
# MS Updates retriever
#############################
# Download and parse MS security updates
#
# [ History ]
# * 2017-07
#  o creation
#
#############################
#
##
###
###########################################################
# Python Imports
#############################
import datetime
from obj_RequestsWrap import objRequestsWrap
#
##
###
################################################################
## Parameters, Config and Prerequisites
################################
#
##
###
###########################################################
# Object
#############################
class objMsUpdates:
	#
	################################
	def __init__(self):
		#
		# Microsoft Security Update REST API Url 
		self.sUrl = u'https://api.msrc.microsoft.com/Updates?api-Version={apiver}'
		#
		# Microsoft Security Update REST API Version
		self.sMSApiVersion = u'2016-08-01'
		#
		# API Key
		self.sApiKey = u''
		#
		pass
	#end __init__
	#
	#############################
	def iso8601ToDatetime(self, sDate):
		"""
		Convert release date from  ISO 8601 to datetime.datetime
		Dirty way, without supporting real UTC :-/
		
		:param sDate: date as ISO 8601 to convert
		:return: datetime.datetime
		"""
		oDate = datetime.datetime.strptime(sDate, '%Y-%m-%dT%H:%M:%SZ')
		return oDate
	#end iso8601ToDatetime
	#
	#############################
	def setApiKey(self, value):
		"""
		Set api key
		:param value:		api key, as string
		"""
		self.sApiKey = value.strip()
	#end setApiKey
	#
	#############################
	def setUrl(self, value):
		"""
		Set url
		:param value:		url, as string
		"""
		self.sUrl = value.strip()
	#end setUrl
	#
	#############################
	def get(self, dConfig={}):
		"""
		:param dConfig: proxy config, as a dictionnary
		:return: a json dictionnary containing informations about this ms update with in theory the following indexes :
							{	u'CvrfUrl': url of the bulletin,
								u'Severity': seems clear,
								u'DocumentTitle': title with the month and year, 
						 		u'CurrentReleaseDate': release date of the bulletin that can be really different from the real release date
						 		u'RealReleaseDate': my own correction to set the real release date
								u'Alias': short bulletin name, ie. u'2016-Apr'
						 		u'InitialReleaseDate': bulletin release date, closed to the real release date
						 		u'ID': id of the bulletin, close to the alias, ie. u'2016-Apr'
						 	}
		"""
		#
		# Build URL
		sUrl = self.sUrl.replace(u'apiver', self.sMSApiVersion)
		#
		# Create request obj
		oReq = objRequestsWrap()
		#
		# Set api key header
		oReq.setHeaders({u'api-key':self.sApiKey})
		#
		if (type(dConfig)!=dict):
			print u' [!] Config not a dictionnary'
			return u''
		elif (len(dConfig)>0):
			# Request headers and proxy
			oReq.buildRequestFromDict(dConfig)
		else:
			# No conf
			pass
		#
		# Do the request
		oResp = oReq.get(sUrl)
		#
		# Response is in Json, yeah, modern structure, great !
		# Parse reponse as Json
		try:
			dJson = oResp.json()
		except Exception, e:
			print ' [!] Error parsing Json response, content:{%s}, exception:{%s}' % (oResp.text[0:32], str(e))
			return u''
		#
		# Select the value
		try:
			lUnsortedUpdates = dJson[u'value']
		except Exception, e:
			print ' [!] Error value field does not exists in dictionnary, exception:{%s}' % (str(e))
			return u''
		#
		# returns the json value as a list of dictionnary
		if type(lUnsortedUpdates)==list:
			#
			# lUnsortedUpdates is not sorted, not by date
			# And worst, sometimes updates have a wrong release date... 2016-Oct is set at 2016-12-13
			# Frack you Microsoft, what is that fracking lack of rigor !!?
			for iKey, dUpdate in enumerate(lUnsortedUpdates):
				#
				# Get real update date
				sRealReleaseDate = self.getUpdateRealDate(dUpdate[u'ID'],dUpdate[u'CurrentReleaseDate'])
				#
				# Set this date
				lUnsortedUpdates[iKey][u'RealReleaseDate'] = sRealReleaseDate
			#
			# Sort that unshorted shit by release date
			lSortedUpdates = sorted(lUnsortedUpdates, key=lambda k: k[u'RealReleaseDate'])
			#
			return lSortedUpdates
		else:
			# Fuck fuck fuck !!!!
			return []
	#end get
	#
	#############################
	def getUpdateRealDate(self, sId, sReleaseDate):
		#
		# Month inn english, hard coded
		dMonths = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
		#
		lId = sId.split('-')
		if (len(lId)!=2):
			return sReleaseDate
		else:
			if (lId[1].lower()==u'oob'):
				# out of band, keep release date
				return sReleaseDate
			else:
				# Try to get the year
				try:
					iIdYear = int(lId[0])
				except:
					return sReleaseDate
				# Try to get the month
				if (lId[1][0:3].lower() not in dMonths):
					return sReleaseDate
				else:
					iIdMonth = dMonths.index(lId[1][0:3].lower())+1
					oReleaseDate = self.iso8601ToDatetime(sReleaseDate)
					if ((oReleaseDate.year != iIdYear) or (oReleaseDate.month != iIdMonth)):
						# ok, release date seems wrong...
						sNewReleaseDate = '%04d-%02d-01T01:00:00Z' %(iIdYear,iIdMonth )
						return sNewReleaseDate
					else:
						return sReleaseDate
	#end getUpdateRealDate
	#
	#############################			
#end class
#
##
###
# End
###
##
#