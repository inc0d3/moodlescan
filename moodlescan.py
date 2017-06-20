#!/usr/bin/python

import datetime
import hashlib
import json
import optparse
import os
import sys
import urllib
import urllib2
import zipfile


print ("""

                     moodlescan v0.2
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
	urllib.urlretrieve (urlup, "data.zip")
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
		li = fo.readline()
		actual = datetime.datetime.strptime(li,"%Y%m%d%H%M%S")
		fo.close()
		
		urllib.urlretrieve (urlup, "update.dat")
		fo = open("update.dat", "r+")
		li = fo.readline()
		ultima = datetime.datetime.strptime(li,"%Y%m%d%H%M%S")
		fo.close()
		
		if ultima > actual:
			update()
		else:
			print("La base de datos de moodlescan ya esta actualizada (version: " + actual.strftime("%d-%m-%Y %H:%M") + ").\n")
		
	except IOError as e:
		if e.errno == 2:
			urllib.urlretrieve (urlup, "update.dat")
			fo = open("update.dat", "r+")
			update()
		else:
			print (e)
	



def getheader(url):
	print ("Obteniendo datos del servidor " + url + " ...")
	
	try:
		cnn = urllib2.urlopen(url)
		
		print ("")
		print ("server		: " + cnn.info().get('server'))
		if cnn.info().get('x-powered-by'):
			print ("x-powered-by	: " + cnn.info().get('x-powered-by'))	
		if cnn.info().get('x-frame-options'):
			print ("x-frame-options	: " + cnn.info().get('x-frame-options'))
		print ("date		: " + cnn.info().get('date'))
		print ("")
	except Exception as e:
		print ("\nHa ocurrido un error al intentar conectar con el objetivo. Verifique la URL.\n\nBusqueda finalizada.\n")
		sys.exit()
	

def getversion(url):
	print ("Obteniendo version de moodle...")
	f = open('data/version.txt','r')
	jsond = json.load(f)
	f.close()

	for a in jsond['archivos']:
		for k , b in a.items():
			
			ar = k
			
			#TODO: no cache y catch HTTP errors (404, 503, timeout, etc)
			cnn = urllib2.urlopen(url + k)
			cnt = cnn.read()

			hr = hashlib.md5(cnt).hexdigest()

			#print (ar + " -- " + hr)

			for c in b:
				for k, x in c.items():
					if hr == k:
						print ("\nVersion encontrada via " + ar + " : Moodle v" +  x['version'])
						return x['version']
				
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
				print ("\nCVE		: " + k)
				print ("Descripcion	: " + b['descripcion'])
				print ("Tipo		: " + b['tipo'])
				print ("Autenticacion?	: " + b['auth'])
				print ("Exploit?	: " + b['exploit'])
				
				
if options.act:
	checkupdate()

if options.url:
	getheader(options.url)
	v = getversion(options.url)
	if v:
		getcve(v)
		
	print ("\nBusqueda finalizada.\n")





