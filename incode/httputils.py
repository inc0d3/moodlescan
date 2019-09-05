
import urllib
import urllib.request


class httpProxy():
	url = ""
	user = ""
	password = ""
	auth = ""

#descarga un archivo al directorio y nombre indicado en dest
def fileDownload(url, dest):
	try:
		with urllib.request.urlopen(url) as response, open(dest, 'wb') as out_file:
			data = response.read()
			out_file.write(data)
			return None	
	except urllib2.URLError as e:
		return e


#genera una conecion HTTP con o sin proxy, dependiendo de los parametros, adicionalmente, el proxy lo puede autenticar con NTLM o Basic
def httpConnection(url,  proxy):
	#TODO: habilitar autenticacion ntlm
	if (proxy.auth == "ntlm"):
		passman = urllib.HTTPPasswordMgrWithDefaultRealm()
		passman.add_password(None, proxy.url, proxy.user, proxy.password)
		auth = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
	else:
		passman = urllib.request.HTTPPasswordMgr()
		passman.add_password(None, proxy.url, proxy.user, proxy.password)
		auth = urllib.request.HTTPBasicAuthHandler(passman)


	if (proxy.url):		
		proxy = urllib.ProxyHandler({'http': proxy.url})
		opener = urllib.build_opener(proxy.url, auth, urllib2.HTTPHandler)
		urllib.install_opener(opener)

	return urllib.request.urlopen(url)
