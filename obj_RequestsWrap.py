#!/usr/bin/python
# -*- coding: ascii -*-
#
#DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
#                    Version 2, December 2004 
#Everyone is permitted to copy and distribute verbatim or modified 
#copies of this license document, and changing it is allowed as long 
#as the name is changed. 
#           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
# TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 
#
#1. You just DO WHAT THE FUCK YOU WANT TO.
#2. As the "THE BEER-WARE LICENSE", if we meet some day, and you
# think this stuff is worth it, you can buy me a beer in return.
###########################################################
# objRequestsWrap
#############################
# 
# Wrapper for requests
#
# [ To do ]
# + requests wrapper
#
#############################
#
##
###
###########################################################
# Python Imports
#############################
import os
import sys
try:
	import requests
except Exception, e:
	print ' [!] Must install {requests}'
	print '     # pip install requests'
	print '     http://docs.python-requests.org/en/master/user/install/#install'
	sys.exit(1)
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
# Class
#############################
class objRequestsWrap:
	#
	#############################
	def __init__(self):
		# use proxy (True) or not (False)
		self.bProxyEnabled = False
		# username for proxy auth
		self.sProxyUsername = u''
		# password for proxy auth
		self.sProxyPassword = u''
		# proxy url with port, like http://1.2.3.4:8080
		self.dProxyUrl = u''
		# proxy auth type as a string: u'basic' or u'digest'
		self.sProxyAuthType = u'basic'
		# if ssl/tls decypher, ca file name containing the ca, as a string, like: u'myownca.crt'
		self.sProxySslCa = u''
		# http request headers
		self.dHeaders = {}
		# http request params (?a=b&c=d...)
		self.dParams = {}
		#
		# Auth Object
		self.oProxyAuth = None
	#end __init__
	#
	#############################
	def buildRequestFromDict(self, dConfig):
		"""
		Configure requests header and proxy
		"""
		if (dConfig):
			if (u'enabled' in dConfig):
				self.setProxyEnabled(dConfig[u'enabled'])
			if (u'username' in dConfig):
				self.setProxyUsername(dConfig[u'username'])
			if (u'password' in dConfig):
				self.setProxyPassword(dConfig[u'password'])
			if (u'proxy' in dConfig):
				self.setProxyUrl(dConfig[u'proxy'])
			if (u'authtype' in dConfig):
				self.setProxyAuthType(dConfig[u'authtype'])
			if (u'sslca' in dConfig):
				self.setProxySslCa(dConfig[u'sslca'])
		else:
			self.setProxyEnabled(False)
	#end buildRequestConf
	#
	#############################
	def setProxyEnabled(self, value):
		"""
		Set proxy enabled
		:param value		True or False, as boolean
		"""
		if (type(value)==bool):
			self.bProxyEnabled = value
		else:
			self.bProxyEnabled = False
	#end setProxyEnabled
	#
	#############################
	def setProxyUsername(self, value):
		"""
		Set proxy username
		:param value		username, as string
		"""
		if ((type(value)==str) or (type(value)==unicode)):
			self.sProxyUsername = value.strip()
		else:
			self.sProxyUsername = u''
	#end setProxyUsername
	#
	#############################
	def setProxyPassword(self, value):
		"""
		Set proxy Password
		:param value		Password, as string
		"""
		if ((type(value)==str) or (type(value)==unicode)):
			self.sProxyPassword = value.strip()
		else:
			self.sProxyPassword = u''
	#end setProxyPassword
	#
	#############################
	def setProxyUrl(self, value):
		"""
		Set proxy Url
		:param value		Url starting with https:// ou http://, as string
		"""
		if ((type(value)==str) or (type(value)==unicode)):
			if ((self.dProxyUrl[0:7]!=u'http://') and (self.dProxyUrl[0:8]==u'https://')):
				value = u'http://'+value.strip()
			else:
				pass
			self.dProxyUrl = {u'http':value, u'https':value}
		else:
			self.dProxyUrl = u''
	#end setProxyPassword
	#
	#############################
	def setProxyAuthType(self, value):
		"""
		Set proxy auth type
		:param value		Proxy auth type basic or digest, as string
		"""
		if ((type(value)==str) or (type(value)==unicode)):
			self.sProxyAuthType = value.strip()
			if (self.sProxyAuthType==u'basic'):
				self.oProxyAuth = requests.auth.HTTPBasicAuth(self.sProxyUsername, self.sProxyPassword)
			elif (self.sProxyAuthType==u'digest'):
				self.oProxyAuth = requests.auth.HTTPDigestAuth(self.sProxyUsername, self.sProxyPassword)
			else:
				self.oProxyAuth = None
				self.sProxyAuthType = u''
		else:
			pass
	#end setProxyAuthType
	#
	#############################
	def setProxySslCa(self, value):
		"""
		Set proxy ssl ca file for ssl/tls decryption
		:param value		ca file, as string
		"""
		if ((type(value)==str) or (type(value)==unicode)):
			self.sProxySslCa = value.strip()
			if (os.path.isfile(self.sProxySslCa)):
				pass
			else:
				self.sProxySslCa = u''
	#end setProxySslCa
	#
	#############################
	def setHeaders(self, value):
		"""
		Set header for http request
		:param value		dictionnary {'header name':'value'}
		"""
		# Check param
		if ((type(value)==dict) and (value>0)):
			# Check fields and build local/self dictionnary
			for sField in value:
				sField = sField.strip()
				sValue = value[sField].strip()
				if len(sValue)>0:
					self.dHeaders[sField] = sValue
				else:
					pass
		else:
			self.dHeaders = {}
	#end setHeaders
	#
	#############################
	def setParams(self, value):
		"""
		Set header for http request
		:param value		dictionnary {'param name':'value'}
		"""
		# Check param
		if ((type(value)==dict) and (value>0)):
			# Check fields and build local/self dictionnary
			for sField in value:
				sField = sField.strip()
				sValue = value[sField].strip()
				if len(sValue)>0:
					self.dParams[sField] = sValue
				else:
					pass
		else:
			self.dParams = {}
	#end setParams
	#
	#############################
	def get(self, sUrl, bExitIfError=False):
		"""
		Set header for http request
		:param dHeaders		dictionnary {'header name':'value'}
		"""
		try:
			if (self.bProxyEnabled == True):
				# There is a proxy...
				if (self.oProxyAuth != None):
					# Proxy with auth
					if (self.sProxySslCa==u''):
						# SSL/TLS decypher
						oResponse = requests.get(sUrl, params=self.dParams, headers=self.dHeaders, proxies=self.dProxyUrl, auth=self.oProxyAuth, verify=self.sProxySslCa)
					else:
						oResponse = requests.get(sUrl, params=self.dParams, headers=self.dHeaders, proxies=self.dProxyUrl, auth=self.oProxyAuth)
				else:
					# No proxy auth
					if (self.sProxySslCa!=u''):
						# SSL/TLS decypher
						oResponse = requests.get(sUrl, params=self.dParams, headers=self.dHeaders, proxies=self.dProxyUrl, verify=self.sProxySslCa)
					else:
						oResponse = requests.get(sUrl, params=self.dParams, headers=self.dHeaders, proxies=self.dProxyUrl)
			else:
				# No proxy
				oResponse = requests.get(sUrl, params=self.dParams, headers=self.dHeaders)
		except Exception, e:
			print ' [!] Error in GET, exception:{%s}' % (str(e))
			if (bExitIfError==True):
				sys.exit(1)
			else:
				return None
		#
		# check server status code
		if (oResponse.status_code==200):
			# Ok
			return oResponse
		elif (oResponse.status_code==204):
			print ' [!] Error, 204 Request rate limit exceeded'
		elif  (oResponse.status_code==403):
			print ' [!] Error, 403 Forbidden'
		else:
			print ' [!] Error, Unknown status_code:{%d}' % (oResponse.status_code)
		# If we are here we have an error
		if (bExitIfError==True):
			sys.exit(1)
		else:
			return None
	#end get
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