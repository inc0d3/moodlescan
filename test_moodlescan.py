#!/usr/bin/env python3

import moodlescan

def test_update():
	moodlescan.checkupdate()

def test_getuseragent():
	moodlescan.getuseragent()

def test_getheader_01_ssl():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "https://moodle.uam.es/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getheader_02_ssl():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "https://moodle.oulu.fi/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getheader_03_ssl():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "https://ecampus.ugr.es/moodle/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getheader_03_http():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "http://virtual.cucs.udg.mx/moodle/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getheader_01_nossl():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = moodlescan.getignoressl()
	url = "http://moodlecolegiopatriciolynch.cl/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getversion_01():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = moodlescan.getignoressl()
	url = "http://moodlecolegiopatriciolynch.cl/"
	moodlescan.getheader(url, proxy, agent, ignore)
	v = moodlescan.getversion(url, proxy, agent, ignore)
	if v:
		moodlescan.getcve(v)

def test_getversion_02():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "https://ecampus.ugr.es/moodle/"
	moodlescan.getheader(url, proxy, agent, ignore)
	v = moodlescan.getversion(url, proxy, agent, ignore)
	if v:
		moodlescan.getcve(v)

	