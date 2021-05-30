#!/usr/bin/python3
# -*- coding: utf-8 -*-


import datetime
import hashlib
import json
import argparse
import os
import sys
import urllib
from urllib.request import Request, urlopen 
from urllib.error import URLError
import zipfile
import re
import random
import ssl


class httpProxy():
	url = ""
	user = ""
	password = ""
	auth = ""

#descarga un archivo al directorio y nombre indicado en dest
def fileDownload(url, dest, agent):
	try:
		req = Request(url)
		if len(agent) > 2:
			req.add_header('user-agent', agent)

		with urlopen(req) as response, open(dest, 'wb') as out_file:
			data = response.read()
			out_file.write(data)
			return None	
	except URLError as e:
		return e

def getuseragent():
    lines = open('data/agents.txt').read().splitlines()
    return random.choice(lines)

def savelog(e, url):
	logfile = open("errors.moodlescan.log", "a")
	if (hasattr(e, "reason")):
		logfile.write(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") + " - " + url + " - " + str(e.reason) + "\n")
	else:
		logfile.write(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") + " - " + url + " - no reason\n" )
	logfile.close()

def getignoressl():
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	return ctx


#genera una conecion HTTP con o sin proxy, dependiendo de los parametros, adicionalmente, el proxy lo puede autenticar con NTLM o Basic
def httpConnection(url,  proxy, agent, ignore):
	
	if (proxy.auth == "ntlm"):
		#todo
		print("")
	else:
		auth_handler = urllib.request.HTTPBasicAuthHandler()
		auth_handler.add_password(realm='Proxy', uri=proxy.url, user=proxy.user, passwd=proxy.password)

	if (proxy.url):		
		opener = urllib.request.build_opener(auth_handler)
		urllib.install_opener(opener)

	req = Request(url)
	if len(agent) > 2:
		req.add_header('user-agent', agent)

	if (ignore):
		return urlopen(req,  context=ignore)
	else:
		return urlopen(req)

def banner():
	print ("""

 .S_SsS_S.     sSSs_sSSs      sSSs_sSSs     .S_sSSs    S.        sSSs    sSSs    sSSs   .S_SSSs     .S_sSSs    
.SS~S*S~SS.   d%%SP~YS%%b    d%%SP~YS%%b   .SS~YS%%b   SS.      d%%SP   d%%SP   d%%SP  .SS~SSSSS   .SS~YS%%b   
S%S `Y' S%S  d%S'     `S%b  d%S'     `S%b  S%S   `S%b  S%S     d%S'    d%S'    d%S'    S%S   SSSS  S%S   `S%b  
S%S     S%S  S%S       S%S  S%S       S%S  S%S    S%S  S%S     S%S     S%|     S%S     S%S    S%S  S%S    S%S  
S%S     S%S  S&S       S&S  S&S       S&S  S%S    S&S  S&S     S&S     S&S     S&S     S%S SSSS%S  S%S    S&S  
S&S     S&S  S&S       S&S  S&S       S&S  S&S    S&S  S&S     S&S_Ss  Y&Ss    S&S     S&S  SSS%S  S&S    S&S  
S&S     S&S  S&S       S&S  S&S       S&S  S&S    S&S  S&S     S&S~SP  `S&&S   S&S     S&S    S&S  S&S    S&S  
S&S     S&S  S&S       S&S  S&S       S&S  S&S    S&S  S&S     S&S       `S*S  S&S     S&S    S&S  S&S    S&S  
S*S     S*S  S*b       d*S  S*b       d*S  S*S    d*S  S*b     S*b        l*S  S*b     S*S    S&S  S*S    S*S  
S*S     S*S  S*S.     .S*S  S*S.     .S*S  S*S   .S*S  S*S.    S*S.      .S*P  S*S.    S*S    S*S  S*S    S*S  
S*S     S*S   SSSbs_sdSSS    SSSbs_sdSSS   S*S_sdSSS    SSSbs   SSSbs  sSS*S    SSSbs  S*S    S*S  S*S    S*S  
SSS     S*S    YSSP~YSSY      YSSP~YSSY    SSS~YSSY      YSSP    YSSP  YSS'      YSSP  SSS    S*S  S*S    SSS  
        SP                                                                                    SP   SP          
        Y                                                                                     Y    Y           
                                                                                                               
Version 0.8 - May/2021""")

	print ("." * 109)
	print ("""
By Victor Herrera - supported by www.incode.cl
	""")
	print ("." * 109)
	print ("")

	if len(sys.argv) == 1:

		print ("""

		Options

		-u [URL] 	: URL with the target, the moodle to scan
		-a 		: Update the database of vulnerabilities to latest version
		-r 		: Enable HTTP requests with random user-agent

		Proxy configuration

		-p [URL]	: URL of proxy server (http)
		-b [user]	: User for authenticate to proxy server
		-c [password]	: Password for authenticate to proxt server
		-d [protocol]  : Protocol of authentication: basic or ntlm

		""")



def main():
	banner()
	agent = ""
	parser = argparse.ArgumentParser()
	ignore = False

	parser.add_argument('-u', '--url', dest="url", help="URL with the target, the moodle to scan")
	parser.add_argument('-k', action="store_true", dest="ignore", help="Ignore SSL Certificate")
	parser.add_argument('-r', action="store_true", dest="agent", help="Enable HTTP requests with random user-agent")
	parser.add_argument('-a', action="store_true",dest="act", help="Update the database of vulnerabilities to latest version")
	parser.add_argument('-p', '--proxy', dest="prox", help="URL of proxy server")
	parser.add_argument('-b', '--proxy-user', dest="proxu", help="User for authenticate to proxy server")
	parser.add_argument('-c', '--proxy-pass', dest="proxp", help="Password for authenticate to proxt server")
	parser.add_argument('-d', '--proxy-auth', dest="proxa", help="Protocol of authentication: basic or ntlm")
	

	options = parser.parse_args()
	if options.act:
		checkupdate()

	if options.agent:
		agent = getuseragent()

	if options.ignore:
		ignore = getignoressl()

	if options.url:
		proxy = httpProxy()

		#se revisa si es necesario crear instancia de proxy
		if (options.prox):	

			proxy.url = options.prox

			if (options.proxu):
				proxy.user = options.proxu

			if (options.proxp):
				proxy.password = options.proxp
			
			if (options.proxa):
				proxy.auth = options.proxa

		getheader(options.url, proxy, agent, ignore)
		v = getversion(options.url, proxy, agent, ignore)
		if v:
			getcve(v)
			
		print ("\nScan completed.\n")


def update():
	#TODO: catch HTTP errors (404, 503, timeout, etc)
	print ("A new version of database was found, updating...")
	urlup = "https://raw.githubusercontent.com/inc0d3/moodlescan/master/update/update.zip"
	r = fileDownload(urlup, "data.zip", "")
	if (r):
			print("Error to connect with database service : " + str(r.reason) )
			sys.exit()
			
	zip_ref = zipfile.ZipFile('data.zip', 'r')
	zip_ref.extractall('data')
	zip_ref.close()
	os.remove('data.zip')
	print ("\nThe database is now updated.\n")


def checkupdate():
	#TODO: catch HTTP errors (404, 503, timeout, etc)

	urlup = "https://raw.githubusercontent.com/inc0d3/moodlescan/master/update/update.dat"
	
	try:

		fo = open("update.dat", "r+")
		actual = int(fo.readline())
		fo.close()
		
		r = fileDownload(urlup, "update.dat", "")
		if (r):
			print("Error to connect with database service : " + str(r.reason) )
			sys.exit()
		
		fo = open("update.dat", "r+")
		ultima = int(fo.readline())
		fo.close()
		
		if ultima > actual:
			update()
		else:
			print("The moodlescan database is up to date (version: " + str(actual) + ").\n")
		
	except IOError as e:
		if e.errno == 2:
			print(e)
			urllib.urlretrieve (urlup, "update.dat")
			fo = open("update.dat", "r+")
			update()
		else:
			print (e)
	



def getheader(url, proxy, agent, ignore):
	print ("Getting server information " + url + " ...\n")
	
	try:
		cnn = httpConnection(url, proxy, agent, ignore)
		headers = ['server', 'x-powered-by', 'x-frame-options', 'x-xss-protection', 'last-modified']		
		for el in headers:
			if cnn.info().get(el):
				print (el.ljust(15) + "	: " + cnn.info().get(el))
	except URLError as e:
		print("Error: Can't connect with the target : " + str(e.reason) )
		savelog(e, url)
		sys.exit()
	except Exception as e:
		print ("\nError: Can't connect with the target. Check URL option.\n\nScan finished.\n")
		savelog(e, url)
		sys.exit()
	

def getversion(url, proxy, agent, ignore):
	print ("\nGetting moodle version...")

	s = [['/admin/environment.xml'], ['/composer.lock'], ['/lib/upgrade.txt'], ['/privacy/export_files/general.js'], ['/composer.json'], ['/question/upgrade.txt'], ['/admin/tool/lp/tests/behat/course_competencies.feature']]
	
	i = 0
	urllib.request.urlcleanup() #no cache

	#obtiene todos los hash md5 remotamente a partir de la lista "s", luego al elemento de la misma
	#lista le agrega su hash md5, quedando:
	#[['/admin/environment.xml', '5880153d43cdc31d2ff81f2984b82e83'], ['/admin/upgrade.txt', '87a1a291465a87ac9f67473898044941'].....
	for a in s:		
		#TODO: catch HTTP errors (404, 503, timeout, etc)
		try:
			cnn = httpConnection(url + a[0], proxy, agent, ignore)
			#cnn = urllib.request.urlopen()
			cnt = cnn.read()
			s[i].append(hashlib.md5(cnt).hexdigest())
			
		except URLError as e:
			#print("Error " + str(e.code) + " en: " + url + a[0])
			s[i].append(0)
				
		i = i + 1


	with open('data/version.txt', 'r') as fve:
    		data = fve.read()
	
	
	#busca en el archivo version.txt la cantidad de ocurrencias de los hashs obtenidos y los agrega a "s"
	#[['/admin/environment.xml', '5880153d43cdc31d2ff81f2984b82e83', 16], ['/composer.lock', 'edb7c357a8798a545154180891215e09', 9]....
	#si existe alguno con una ocurrencia, esa es la versión, de lo contrario se almacena en "occ" el de menor ocurrencias
	f = 100
	version = 0
	occ = 100
	nada = 1
	
	for m in s:
		if m[1] != 0:
			l = re.findall(".*" + m[1] + ".*", data)
			encontrados = len(l)
			m.append(encontrados)
			if encontrados > 0:
				if encontrados == 1:
					return printversion(l[0])
				
				if encontrados < occ:
					occ = encontrados
					archivo = m
					nada = 0
	
	#se crea una lista con todas las versiones que tienen el hash encontrado con menor frecuencia en el paso anterior
	#luego se comienza a revisar cuál de esas versiones tiene la mayor cantidad de similitud con la lista inicial "s" (hashes del objetivo)
	if nada == 0:
		candidatos = re.findall(".*" + archivo[1] + ".*", data)
		
		for z in s:
			occ = 0
			for x in candidatos:		
				tmp = x.split(";")		
				if tmp[2] != z[0]:
						c = re.findall(tmp[0] + ";" +  str(z[1]) + ".*", data)
						if len(c) > 0:						
							version = c[0]
							occ = occ + 1
			
			if occ == 1:
				break
			
	else:
		version = 0

	return printversion(version)
	

	

def printversion(version):
	if version != 0:
		print ("\nVersion found via " + version.split(';')[2] + " : Moodle " +  version.split(';')[0])
		return version.split(';')[0].replace("v","")
		
	print ("\nVersion not found")
	return False

def getcve(version):	
	print("\nSearching vulnerabilities...\n")
	f = open('data/cve.json','r')
	jsond = json.load(f)
	f.close()
	
	#version = "," + version + ","
	
	nvuln = 0
	nexpl = 0
	
	for cve in jsond:
		try:
			indice = cve[4].index(version)
		except ValueError:
			indice = -1

		if indice > 0:
			nvuln += 1
			printcve(cve)
				

	print("\nVulnerabilities found: " + str(nvuln))			


def printcve(cve):
	print("")
	print("[!] " + cve[0] + ": " + cve[3])
	print("    Authentication: " + cve[2] )
	print("    Vulnerability type: " + cve[1] )

	for r in cve[5]:
		print("    Reference: " + r)

if __name__ == "__main__":
	main()








