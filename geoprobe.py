# geoprobe - a tool to sniff, collect and geolocate 802.11 ProbeRequests using WiGLE API.
# Copyright (C) 2018 Jacobo Bouzas Quiroga jacobo.bouzas.quiroga@udc.es
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
from time import sleep
from datetime import date
import shelve
from threading import Thread
import pyric             # pyric errors
import pyric.pyw as pyw  # iw functionality
from scapy.all import sniff, Dot11ProbeReq, Dot11, Dot11Elt
import geohash_hilbert as ghh
from mac_vendors import get_readable_mac
from pygle import network as pygle_api
import argparse

#
# WARNING: PIECE OF UGLY CODE PIECED TOGETHER IN A HURRY FOR EXTRA CREDIT
# TAMPER WITH IT AT A GREAT COST TO YOUR SANITY, EYES AND PATIENCE, YOU
# HAVE BEEN WARNED.
#

class Observable:
	'''Part of Zahori, a GUI app with a similar purpose that I'm writing,
	I don't wanna bother refactoring it.'''
	def __init__(self):
		self._observers = []

	def add_observer(self,observer):
		self._observers.append(observer)

	def notify_observers(self,event):
		[o.notify(event) for o in self._observers]

class ChannelHopper(Thread):
	'''I'm not documenting this but it's really pretty obvious.'''

	def __init__(self, interface, delay=1, channels=[1,6,11,2,7,12,3,8,13,4,9]):
		super().__init__()
		self._running = True
		self._delay = delay
		self._channels = channels
		self._interface = interface

	def channel_hopping(self):
		i = 0
		while self._running:
			pyw.chset(self._interface, self._channels[i], None)
			i += 1
			i %= len(self._channels)
			sleep(self._delay)

	def run(self):
		self.channel_hopping()

	def stop(self):
		self._running = False

# event type	  code	meaning
EV_SCAN_OK 		= 0		# scan finished ok (EV_SCAN_OK)
EV_SCAN_FAILED	= 1		# scan terminated with errors (EV_SCAN_FAILED, reason)
EV_SCAN_RESULTS = 2		# newly scanned information (EV_SCAN_RESULTS, results)

class Scanner(Thread, Observable):
	''' Scanner class, handles scanner runs including setting up a monitor and
disposing of it when not necessary anymore. God has mercy on our souls.

	get_wireless_interfaces()	- returns available interfaces for monitoring
	Scanner(iface_name)			- creates a new scanner on the provided interface
	scan(timeout=10)			- makes an scan run until timeout seconds run out'''

	_MON_NAME = "mon0"

	# return available radio interfaces
	def get_wireless_interfaces():
		return pyw.winterfaces()

	def __init__(self, iface_name):
		Thread.__init__(self)
		Observable.__init__(self)

		self._HANDLER = self._make_handler()
		self._abort = False
		self._monitor = None
		self._iface_name = iface_name
		self._iface = pyw.getcard(iface_name)
		self._timeout = 0
	
	_LFILTER=lambda pkt: pkt.haslayer(Dot11ProbeReq)
	
	def _stop_filter(self, dummy):
		return self._abort
	
	def _make_handler(self):
		def handler(pkt):
			client_bssid = pkt[Dot11].addr2
			try:
				network_ssid = pkt[Dot11Elt].info.decode('utf-8','replace')
				msg = client_bssid, network_ssid
				#print(client_bssid, network_ssid)
				self.notify_observers((EV_SCAN_RESULTS, msg))
			except UnicodeDecodeError:
				pass # TODO: log this
		return handler
	
	def run(self):
		print("Starting scanner...")
		self._abort = False
		hopper = None
		try:
			# set up monitor
			self._monitor = pyw.devadd(self._iface, Scanner._MON_NAME, 'monitor')
			for card,dev in pyw.ifaces(self._monitor):
				if card.dev != self._monitor.dev:
					pyw.devdel(card)
			pyw.up(self._monitor)
			self._iface = None
			
			# set up channel hopping
			hopper = ChannelHopper(self._monitor)
			hopper.start()
		
			sniff(iface=Scanner._MON_NAME,
				store=0,
				prn=self._HANDLER,
				lfilter=Scanner._LFILTER,
				timeout=self._timeout,
				stop_filter=self._stop_filter)
			self.notify_observers((EV_SCAN_OK,))
		except pyric.error as e:
			self.notify_observers((EV_SCAN_FAILED, e))
		finally:
			if hopper:
				# stop channel hopping
				hopper.stop()
			if self._monitor:
				# destroy monitor interface
				self._iface = pyw.devadd(self._monitor, self._iface_name, 'managed')
				pyw.devdel(self._monitor)
				pyw.up(self._iface)
				self._monitor = None
	
	def scan(self,timeout=10):
		self._timeout = timeout
		self.start()
	
	def stop(self):
		if self.is_alive():
			self._abort = True

class Geolocator:
	'''Will fetch from WiGLE API for processor cycles'''
	_CACHE = 'geolocator_cache'
	_NETWORKS = 'networks'
	_DATE = 'last_update'
	_LOCATIONS = 'locations'
	_MAX_AGE = 180 # days of cache validity (6 months)
	_BPC = 4 # geohashing bits per char (base 16)
	_PRECISION = 10 # geohashing precision (~20m at _BPC 4)
	_API_HITS_ERROR_STR = "You've run out of WiGLE API hits for the time being. Try again sometime later or, if you feel like it you can contribute to the WiGLE DB to gain a few extra hits per day or directly pay for COMMAPI. You can still use this software on cached mode."

	# TODO: CODE CLEANUP OF THIS CLASS

	class Outdated(Exception):
		pass
	
	def locate(ssid):
		with shelve.open(Geolocator._CACHE, writeback=True) as cache:
			try:
				if Geolocator._NETWORKS not in cache:
					cache[Geolocator._NETWORKS] = {}
			
				last_update = cache[Geolocator._NETWORKS][ssid][Geolocator._DATE]
				age = date.today() - last_update
				if age.days > Geolocator._MAX_AGE:
					raise Geolocator.Outdated()
				# cache valid
			except (Geolocator.Outdated, KeyError):
				# cache miss or outdated, fetch from WiGLE
				last_update = date.today()
				try:
					# fetch from wigle
					response = pygle_api.search(ssid=ssid)
					locations = {}
					for res in response['results']:
						#print((res['trilat'],res['trilong']))
						geohash = ghh.encode(res['trilong'],
							res['trilat'],
							precision=Geolocator._PRECISION,
							bits_per_char=Geolocator._BPC)
						lon, lat = ghh.decode(geohash, bits_per_char=Geolocator._BPC) # limit precission of stored coords to match geohash
						locations[geohash] = lat, lon
					totalresults = response['totalResults']

					if totalresults:
						if ssid not in cache[Geolocator._NETWORKS]:
							cache[Geolocator._NETWORKS][ssid] = { Geolocator._LOCATIONS : {} }
						cache[Geolocator._NETWORKS][ssid][Geolocator._DATE] = last_update
						for geohash, coords in locations.items():
							cache[Geolocator._NETWORKS][ssid][Geolocator._LOCATIONS][geohash] = coords
					else:
						print('No results for SSID: %s' % ssid)
				except KeyError as e:
					print(_API_HITS_ERROR_STR)
			finally:
				if ssid in cache[Geolocator._NETWORKS]:
					result = cache[Geolocator._NETWORKS][ssid][Geolocator._LOCATIONS].values()
				else: result = None

		return last_update, result

class Observer(Thread):

	_RESULTS = {}

	def __init__(self):
		Thread.__init__(self)
	
	def run(self):
		sleep(10)
		for client, networks in Observer._RESULTS.items():
			print("%s" % get_readable_mac(client))
			for network in networks:
				last_update, locations = Geolocator.locate(network)
				print("\t%s" % network)
				for loc in locations:
					print("\t\t%s" % str(loc))

	def notify(self, event):
		if event[0] == EV_SCAN_RESULTS:
			client, network = event[1]
			if network != '':
				if client not in Observer._RESULTS.keys():
					Observer._RESULTS[client] = []
				if network not in Observer._RESULTS[str(client)]:
					Observer._RESULTS[str(client)].append(network)
		elif event[0] == EV_SCAN_OK:
			print("Scan finished")
			self.start()
		elif event[0] == EV_SCAN_FAILED:
			print("Scan failed")
		else:
			pass

parser = argparse.ArgumentParser(description="Listen to 802.11 radio and discover nearby clients' memorized access points and their possible locations.")

parser.add_argument('-i', '--interface', dest='iface', required=True, help='radio interface for listening')
parser.add_argument('-t', '--timeout', dest='timeout', default=30, type=int, help='duration of the scan (default: 30s)')
parser.add_argument('-g', '--disable-geolocation', dest='geolocate', action='store_false', help='only scan for ProbeRequests, do not query for locations')
parser.add_argument('-c', '--cache-only', dest='connect', action='store_false', help='use only cached results for location, do not query WiGLE API')

args = parser.parse_args()

scanner = Scanner(args.iface)
observer = Observer()

scanner.add_observer(observer)
scanner.scan(args.timeout)

