#!/usr/bin/python

import datetime
import hashlib
import json
import optparse
import os
import urllib.request
import zipfile


print ("""

      moodlescan v0.1
............................
auspiciado por www.incode.cl
""")

parser = optparse.OptionParser()

parser.add_option('-u', '--url', dest="url", help="Direccion del sitio web a escanear")
parser.add_option('-a', action="store_true",dest="act", help="Actualizar base de datos")

options, remainder = parser.parse_args()

def update():
	print ("actualizando...")
	urllib.urlretrieve ("http://localhost/img/data.zip", "data.zip")
	zip_ref = zipfile.ZipFile('data.zip', 'r')
	zip_ref.extractall('data')
	zip_ref.close()
	os.remove('data.zip')
	print ("\nla base de datos ha sido actualizada")


def checkupdate():
	u = urllib.urlopen ("http://localhost/img/update.dat")
	i = u.info()
	ultima = i.getdate('last-modified')
	ultima = datetime.datetime(*ultima[:6])

	
	try:

		fo = open("update.dat", "r+")

	except IOError as e:
		if e.errno == 2:
			urllib.urlretrieve ("http://localhost/img/update.dat", "update.dat")
			fo = open("update.dat", "r+")
		else:
			print (e)
	

	li = fo.readline()

	actual = datetime.datetime.strptime(li,"%Y%m%d%H%M%S")

	if ultima > actual:
		update()


def getheader(url):
	print ("Obteniendo datos del servidor " + url + " ...")
	cnn = urllib.request.urlopen(url)
	
	print ("")
	print ("server		: " + cnn.info().get('server'))
	if cnn.info().get('x-powered-by'):
		print ("x-powered-by	: " + cnn.info().get('x-powered-by'))	
	if cnn.info().get('x-frame-options'):
		print ("x-frame-options	: " + cnn.info().get('x-frame-options'))
	print ("date		: " + cnn.info().get('date'))
	print ("")



def getversion(url):
	print ("Obteniendo version de moodle...")
	f = open('data/version.txt','r')
	jsond = json.load(f)
	f.close()

	for a in jsond['archivos']:
		for k , b in a.items():
			
			ar = k
			
			#TODO: no cache y catch HTTP errors (404, 503, etc)
			cnn = urllib.request.urlopen(url + k)
			cnt = cnn.read()

			hr = hashlib.md5(cnt).hexdigest()

			for c in b:
				for k, x in c.items():
					if hr == k:
						print ("\nVersion encontrada via " + ar + " : " +  x['version'])
						return
				
	print ("\nVersion de moodle no encontrada")
	


if options.act:
	checkupdate()

if options.url:
	getheader(options.url)
	getversion(options.url)






