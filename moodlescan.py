#!/usr/bin/python

import datetime
import hashlib
import json
import argparse
import os
import sys
import urllib
from urllib.error import URLError
import zipfile
import re

from incode.httputils import *

print ("""

moodlescan v0.5
.........................................................
escrito por Victor Herrera - auspiciado por www.incode.cl
""")

if len(sys.argv) == 1:

	print ("""

	Opciones

	-u [URL] 	: Inicia el scan en la URL indicada
	-a 		: Actualiza la base de datos de vulnerabilidades

	Configuracion de Proxy

	-p [URL]	: Url del proxy (http)
	-b [usuario]	: Usuario para autenticar en proxy
	-c [clave]	: Password para autenticar en proxy
	-d [protocolo]  : Protocolo de autenticacion en proxy: basic o ntlm

	""")



parser = argparse.ArgumentParser()

parser.add_argument('-u', '--url', dest="url", help="Direccion del sitio web a escanear")
parser.add_argument('-p', '--proxy', dest="prox", help="Direccion http del proxy")
parser.add_argument('-b', '--proxy-user', dest="proxu", help="Usuario para autenticar en proxy")
parser.add_argument('-c', '--proxy-pass', dest="proxp", help="Password para autenticar en proxy")
parser.add_argument('-d', '--proxy-auth', dest="proxa", help="Protocolo de autenticacion en proxy: basic o ntlm")
parser.add_argument('-a', action="store_true",dest="act", help="Actualizar base de datos")

options = parser.parse_args()



def update():
	#TODO: catch HTTP errors (404, 503, timeout, etc)
	print ("Nueva version de la base de datos encontrada, actualizando...")
	urlup = "https://raw.githubusercontent.com/inc0d3/moodlescan/master/update/data.zip"
	r = fileDownload(urlup, "data.zip")
	if (r):
			print("Ha ocurrido un error al conectarse con el servidor de actualizacion : " + str(r.reason) )
			sys.exit()
			
	zip_ref = zipfile.ZipFile('data.zip', 'r')
	zip_ref.extractall('data')
	zip_ref.close()
	os.remove('data.zip')
	print ("\nLa base de datos ha sido actualizada correctamente.\n")


def checkupdate():
	#TODO: catch HTTP errors (404, 503, timeout, etc)

	urlup = "https://raw.githubusercontent.com/inc0d3/moodlescan/master/update/update.dat"
	
	try:

		fo = open("update.dat", "r+")
		actual = int(fo.readline())
		fo.close()
		
		r = fileDownload(urlup, "update.dat")
		if (r):
			print("Ha ocurrido un error al conectarse con el servidor de actualizacion : " + str(r.reason) )
			sys.exit()
		
		fo = open("update.dat", "r+")
		ultima = int(fo.readline())
		fo.close()
		
		if ultima > actual:
			update()
		else:
			print("La base de datos de moodlescan ya se encuentra actualizada (version: " + str(actual) + ").\n")
		
	except IOError as e:
		if e.errno == 2:
			print(e)
			urllib.urlretrieve (urlup, "update.dat")
			fo = open("update.dat", "r+")
			update()
		else:
			print (e)
	



def getheader(url, proxy):
	print ("Obteniendo datos del servidor " + url + " ...\n")
	
	try:
		cnn = httpConnection(url, proxy)
		headers = ['server', 'x-powered-by', 'x-frame-options', 'date', 'last-modified']		
		for el in headers:
			if cnn.info().get(el):
				print (el.ljust(15) + "	: " + cnn.info().get(el))
	except URLError as e:
		print("Ha ocurrido un error al conectarse con el objetivo : " + str(e.reason) )
		sys.exit()
	except Exception as e:
		print ("\nHa ocurrido un error al intentar conectar con el objetivo. Verifique la URL.\n\nBusqueda finalizada.\n")
		sys.exit()
	

def getversion(url):
	print ("\nObteniendo version de moodle...")

	s = [['/admin/environment.xml'], ['/composer.lock'], ['/lib/upgrade.txt'], ['/privacy/export_files/general.js'], ['/composer.json'], ['/question/upgrade.txt']]
	
	i = 0
	urllib.request.urlcleanup() #no cache

	#obtiene todos los hash md5 remotamente a partir de la lista "s", luego al elemento de la misma
	#lista le agrega su hash md5, quedando:
	#[['/admin/environment.xml', '5880153d43cdc31d2ff81f2984b82e83'], ['/admin/upgrade.txt', '87a1a291465a87ac9f67473898044941'].....
	for a in s:		
		#TODO: catch HTTP errors (404, 503, timeout, etc)
		try:
			cnn = urllib.request.urlopen(url + a[0])
			cnt = cnn.read()
			s[i].append(hashlib.md5(cnt).hexdigest())
			
		except URLError as e:
			if e.code == 404:
				s[i].append(0)
		i = i + 1


	with open('data/version.txt', 'r') as fve:
    		data = fve.read()
	
	
	#busca en el archivo version.txt la cantidad de ocurrencias de los hashs obtenidos y los agrega a "s"
	#[['/admin/environment.xml', '5880153d43cdc31d2ff81f2984b82e83', 16], ['/composer.lock', 'edb7c357a8798a545154180891215e09', 9]....
	#se almacena el de menor ocurrencias
	f = 100
	version = 0
	occ = 100
	nada = 1

	for m in s:
		if m[1] != 0:
			l = re.findall(".*" + m[1] + ".*", data)
			if len(l) > 0:
				m.append(len(l))
				if len(l) < occ:
					occ = len(l)
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
	else:
		version = 0

	

	if version != 0:
		print ("\nVersion encontrada via " + version.split(';')[2] + " : Moodle " +  version.split(';')[0])
		return version.split(';')[0].replace("v","")
		
	print ("\nVersion de moodle no encontrada")
	return False

def getcve(version):	
	print("\nBuscando vulnerabilidades...")
	f = open('data/cve.txt','r')
	jsond = json.load(f)
	f.close()
	
	version = "," + version + ","
	
	nvuln = 0
	nexpl = 0
	
	for a in jsond['vulnerabilidades']:
		for k , b in a.items():
			if version  in b['afectadas']:
				nvuln +=1
				print ("\nCVE		: " + k + " ### Tipo : " + b['tipo'] + " ### Autenticacion? : " + b['auth'] + " ### Exploit? : " + b['exploit'])
				print ("Descripcion	: " + b['descripcion'])
				

	print("\nVulnerabilidades encontradas: " + str(nvuln))			
				
				
if options.act:
	checkupdate()

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

	getheader(options.url, proxy)
	v = getversion(options.url)
	if v:
		getcve(v)
		
	print ("\nBusqueda finalizada.\n")





