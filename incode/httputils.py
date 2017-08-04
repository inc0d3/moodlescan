
import urllib2


class httpProxy():
	url = ""
	user = ""
	password = ""
	auth = ""

#descarga un archivo al directorio y nombre indicado en dest
def fileDownload(url, dest):
	try:

		resp = urllib2.urlopen(url)
		with open(dest, 'wb') as f:
  			f.write(resp.read())

  		return None	
	except urllib2.URLError as e:
		return e


#genera una conecion HTTP con o sin proxy, dependiendo de los parametros, adicionalmente, el proxy lo puede autenticar con NTLM o Basic
def httpConnection(url,  proxy):
	
	

	#TODO: habilitar autenticacion ntlm
	if (proxy.auth == "ntlm"):
		passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
		passman.add_password(None, proxy.url, proxy.user, proxy.password)
		auth = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
	else:
		passman = urllib2.HTTPPasswordMgr()
		passman.add_password(None, proxy.url, proxy.user, proxy.password)
		auth = urllib2.HTTPBasicAuthHandler(passman)


	if (proxy.url):
		proxy = urllib2.ProxyHandler({'http': proxy.url})
		opener = urllib2.build_opener(proxy.url, auth, urllib2.HTTPHandler)
		urllib2.install_opener(opener)

	return urllib2.urlopen(url)
