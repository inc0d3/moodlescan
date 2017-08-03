
import urllib2

#descarga un archivo al directorio y nombre indicado en dest
def fileDownload(url, dest):
	try:

		resp = urllib2.urlopen(url)
		with open(dest, 'wb') as f:
  			f.write(resp.read())

  		return None	
	except urllib2.URLError as e:
		return e