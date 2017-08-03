#!/usr/bin/python

import datetime
import hashlib
import json
import optparse
import os
import sys
import urllib2
import zipfile
import re

from incode.httputils import *



print ("""

                     moodlescan v0.3
.........................................................
escrito por Victor Herrera - auspiciado por www.incode.cl

Opciones

-u [URL] 	: Inicia el scan en la URL indicada
-a 		: Actualiza la base de datos de vulnerabilidades

""")

parser = optparse.OptionParser()

parser.add_option('-u', '--url', dest="url", help="Direccion del sitio web a escanear")
parser.add_option('-a', action="store_true",dest="act", help="Actualizar base de datos")

options, remainder = parser.parse_args()

def update():
	#TODO: catch HTTP errors (404, 503, timeout, etc)
	print ("Nueva version de la base de datos encontrada, actualizando...")
	urlup = "https://raw.githubusercontent.com/inc0d3/moodlescan/master/update/data.zip"
	fileDownload(urlup, "data.zip")
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
	



def getheader(url):
	print ("Obteniendo datos del servidor " + url + " ...\n")
	
	try:
		cnn = urllib2.urlopen(url)
		headers = ['server', 'x-powered-by', 'x-frame-options', 'date', 'last-modified']		
		for el in headers:
			if cnn.info().get(el):
				print (el.ljust(15) + "	: " + cnn.info().get(el))
	except Exception as e:
		print ("\nHa ocurrido un error al intentar conectar con el objetivo. Verifique la URL.\n\nBusqueda finalizada.\n")
		sys.exit()
	

def getversion(url):
	print ("\nObteniendo version de moodle...")

	s = [['/admin/environment.xml'], ['/admin/upgrade.txt'], ['/lib/upgrade.txt'], ['/tags.txt'], ['/README.txt']]
	
	i = 0
	for a in s:		
		#TODO: no cache y catch HTTP errors (404, 503, timeout, etc)
		try:
			cnn = urllib2.urlopen(url + a[0])
			cnt = cnn.read()
			s[i].append(hashlib.md5(cnt).hexdigest())
			
		except urllib2.URLError as e:
			if e.code == 404:
				s[i].append(0)
		i = i + 1

	with open('data/version.txt', 'r') as fve:
    		data = fve.read()
		
	f = 100
	version = 0
	for m in s:
		if m[1] != 0:
			l = re.findall(".*" + m[1] + ".*", data)
			if (len(l) < f) and (len(l) > 0) :
				f = len(l)
				version = l[0]

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
	getheader(options.url)
	v = getversion(options.url)
	if v:
		getcve(v)
		
	print ("\nBusqueda finalizada.\n")





