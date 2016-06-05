#!/usr/bin/python3.4
# -*- coding: utf-8 -*-

from config import *
from bs4 import BeautifulSoup
import requests
import sys
import re
import bencodepy
import threading
import json
import html.parser
import argparse
import os
import urllib
import datetime
import sqlalchemy
import sqlalchemy.ext.declarative
import sqlalchemy.dialects.mysql
import utorrent.connection
import binascii
import base64


if not (gazelle_url.startswith("http://") or gazelle_url.startswith("https://")):
	print("Config error: gazelle_url setting must start with http:// or https://")
	exit()
if gazelle_url.endswith("/"):
	print("Config error: gazelle_url setting must not have a trailing /")
	exit()
if script_mode not in ["file", "rutorrent", "utorrent", "deluge",
					   "transmission"]:
	print("Config error: script_mode must be one of: file, rutorrent, "
		  "utorrent, transmission")
	exit()


Base = sqlalchemy.ext.declarative.declarative_base()

class Artist(Base):
	__tablename__ = "artists"

	artist_id = 	sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	name = 			sqlalchemy.Column(sqlalchemy.String(200), nullable=False)
	image = 		sqlalchemy.Column(sqlalchemy.String(500), nullable=False)
	if use_mysql is True:
		body = 		sqlalchemy.Column(sqlalchemy.dialects.mysql.MEDIUMTEXT, nullable=False)
	else:
		body = 		sqlalchemy.Column(sqlalchemy.Text, nullable=False)
	num_groups = 	sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	num_torrents = 	sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	num_seeders = 	sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	num_leechers = 	sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	num_snatches = 	sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	fetched = 		sqlalchemy.Column(sqlalchemy.DateTime, nullable=False)

class Artist_Similar(Base):
	__tablename__ = "artist_similar"

	artist_id = 		sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	similar_artist_id =	sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	name = 				sqlalchemy.Column(sqlalchemy.String(200), nullable=False)
	score = 			sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	similarId = 		sqlalchemy.Column(sqlalchemy.Integer, nullable=False)

class Artist_Tag(Base):
	__tablename__ = "artist_tags"

	artist_id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	tag = 		sqlalchemy.Column(sqlalchemy.String(200), primary_key=True)
	score = 	sqlalchemy.Column(sqlalchemy.Integer, nullable=False)

class Dump_Artist(Base):
	__tablename__ = "dump_artists"

	artist_id = 	sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	if use_mysql is True:
		data = 		sqlalchemy.Column(sqlalchemy.dialects.mysql.MEDIUMTEXT, nullable=False)
	else:
		data = 		sqlalchemy.Column(sqlalchemy.Text, nullable=False)
	fetched = 		sqlalchemy.Column(sqlalchemy.DateTime, nullable=False)

class Group(Base):
	__tablename__ = "groups"

	group_id = 			sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	title = 			sqlalchemy.Column(sqlalchemy.String(200), nullable=False)
	year = 				sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	record_label = 		sqlalchemy.Column(sqlalchemy.String(200), nullable=False)
	catalogue_number = 	sqlalchemy.Column(sqlalchemy.String(200), nullable=False)
	category_id = 		sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	release_type = 		sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	image = 			sqlalchemy.Column(sqlalchemy.String(500), nullable=False)
	vanity_house = 		sqlalchemy.Column(sqlalchemy.Boolean, nullable=False)
	num_artists = 		sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	fetched = 			sqlalchemy.Column(sqlalchemy.DateTime, nullable=False)

class Group_Artist(Base):
	__tablename__ = "group_artists"

	group_id = 		sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	artist_id = 	sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	artist_type = 	sqlalchemy.Column(sqlalchemy.Enum('main','guest','producer','composer','remixer','dj','conductor'), primary_key=True)
	artist_name = 	sqlalchemy.Column(sqlalchemy.String(200), nullable=False)

class Group_Tag(Base):
	__tablename__ = "group_tags"

	group_id = 	sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	tag = 		sqlalchemy.Column(sqlalchemy.String(200), primary_key=True)

class Search_Cache(Base):
	__tablename__ = "search_cache"

	artist_id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	search = 	sqlalchemy.Column(sqlalchemy.String(200), primary_key=True)

class Torrent(Base):
	__tablename__ = "torrents"

	torrent_id = 			sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	group_id = 				sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	media = 				sqlalchemy.Column(sqlalchemy.String(20), nullable=False)
	format = 				sqlalchemy.Column(sqlalchemy.String(10), nullable=False)
	encoding = 				sqlalchemy.Column(sqlalchemy.String(15), nullable=False)
	remaster_year =			sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	remastered = 			sqlalchemy.Column(sqlalchemy.Boolean, nullable=False)
	remaster_title = 		sqlalchemy.Column(sqlalchemy.String(80), nullable=False)
	remaster_record_label =	sqlalchemy.Column(sqlalchemy.String(80), nullable=False)
	scene = 				sqlalchemy.Column(sqlalchemy.Boolean, nullable=False)
	haslog = 				sqlalchemy.Column(sqlalchemy.Boolean, nullable=False)
	hascue = 				sqlalchemy.Column(sqlalchemy.Boolean, nullable=False)
	log_score = 			sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	file_count = 			sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	free_torrent = 			sqlalchemy.Column(sqlalchemy.Boolean, nullable=False)
	size = 					sqlalchemy.Column(sqlalchemy.BigInteger, nullable=False)
	leechers = 				sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	seeders = 				sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	snatched = 				sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
	time = 					sqlalchemy.Column(sqlalchemy.DateTime, nullable=False)

class Torrent_File(Base):
	__tablename__ = "torrent_file"

	torrent_id = 	sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=False)
	if use_mysql is True:
		file = 			sqlalchemy.Column(sqlalchemy.dialects.mysql.MEDIUMBLOB, nullable=False)
	else:
		file = 			sqlalchemy.Column(sqlalchemy.BLOB, nullable=False)

class User_Album(Base):
	__tablename__ = "user_albums"

	artist = 			sqlalchemy.Column(sqlalchemy.String(200), nullable=False, primary_key=True)
	album = 			sqlalchemy.Column(sqlalchemy.String(200), nullable=False, primary_key=True)
	encoding = 			sqlalchemy.Column(sqlalchemy.String(15), nullable=False)

	def __eq__(self, other): 
		return self.artist == other.artist and self.album == other.album and self.encoding == other.encoding

	def __hash__(self):
		return hash((self.artist, self.album, self.encoding))

# connect to database
def database_init():


	engine = None
	if use_mysql is True:
		engine = sqlalchemy.create_engine("mysql://{0}:{1}@{2}/{3}?charset=utf8".format(mysql_username, mysql_password, mysql_host, mysql_db), encoding='utf-8')
	else:
		engine = sqlalchemy.create_engine("sqlite:///sqlite.db")

	Base.metadata.create_all(engine)

	global db2
	db2 = sqlalchemy.orm.Session(engine)

# login function
def login():

	global gazelle
	if gazelle is not None:
		return

	gazelle = requests.session()

	gazelle.headers.update({'User-Agent': 'gazelle-cli'})
	params = {"username": gazelle_username, "password": gazelle_password, "keeplogged": "1"}
	r = gazelle.post("{0}/login.php".format(gazelle_url), params)

	if """<span class="warning">Your username or password was incorrect.<br /><br /></span>""" in r.text:
		print("Login failed.")
		exit()

	if "Your account has been disabled." in r.text:
		print("Banned.")
		exit()

	print("Logged in as {0}".format(gazelle_username))


def get_torrent_file(torrent_id, return_file=False):

	rows = db2.query(Torrent_File).filter_by(torrent_id=torrent_id).all()

	if len(rows) != 0:
		if return_file is False:
			return
		else:
			return {"file": rows[0].file, "source": "Cached"}

	login()
	r = gazelle.get("{0}/torrents.php?action=download&id={1}".format(gazelle_url, torrent_id))

	try:
		data = bencodepy.decode(r.content)
	except:
		print("Error decoding torrent %d" % torrent_id)
		exit()

	# data[b"announce"] = ""

	db2.merge(Torrent_File(torrent_id=torrent_id, file=bencodepy.encode(data)))
	db2.commit()
	#return {"file": None, "source": ""}

	if return_file is True:
		return {"file": bencodepy.encode(data), "source": "Fetched"}


# pull down the entry for a specific album
def populate_artist(artist_id):

	rows = db2.query(Dump_Artist).filter_by(artist_id=artist_id).all()

	if len(rows) != 0 and always_grab is False:
		if always_reparse is False:
			return
		data = json.loads(rows[0].data)["response"]

	# fetch and behave appropriately
	else:
		# login if required
		login()

		r = gazelle.get("{0}/ajax.php?action=artist&id={1}".format(gazelle_url, artist_id))
		data = json.loads(r.text)

		# we've been redirected, because the artist_id doesn't exist
		if data["status"] == "failure":
			db2.query(Dump_Artist).filter_by(artist_id=artist_id).delete()
			db2.commit()
			print("Invalid artist ID: {0}".format(artist_id))
			return

		db2.merge(Dump_Artist(artist_id=artist_id, data=r.text, fetched=datetime.datetime.utcnow()))
		db2.commit()

		data = data["response"]

		print("Fetched artist %d" % artist_id)

	db2.merge(Artist(	artist_id=artist_id,
								name=data["name"],
								image=data["image"],
								body=data["body"],
								num_groups=data["statistics"]["numGroups"],
								num_torrents=data["statistics"]["numTorrents"],
								num_seeders=data["statistics"]["numSeeders"],
								num_leechers=data["statistics"]["numLeechers"],
								num_snatches=data["statistics"]["numSnatches"],
								fetched=datetime.datetime.utcnow()
							))


	for tag in data["tags"]:
		if tag["name"] == "":
			continue
		db2.merge(Artist_Tag(artist_id=artist_id, tag=tag["name"], score=tag["count"]))

	for similarArtist in data["similarArtists"]:
		db2.merge(Artist_Similar(	artist_id=artist_id,
										similar_artist_id=similarArtist["artistId"],
										name=html.parser.unescape(similarArtist["name"]),
										score=similarArtist["score"],
										similarId=similarArtist["similarId"]
									))

	for group in data["torrentgroup"]:

		if group["artists"] == None:
			group["artists"] = []


		# massively slow
		db2.merge(Group(	group_id=group["groupId"],
									title=html.parser.unescape(group["groupName"]),
									year=group["groupYear"],
									record_label=html.parser.unescape(group["groupRecordLabel"]),
									catalogue_number=html.parser.unescape(group["groupCatalogueNumber"]),
									category_id=group["groupCategoryID"],
									release_type=group["releaseType"],
									image=group["wikiImage"],
									vanity_house=group["groupVanityHouse"],
									num_artists=len(group["artists"]),
									fetched=datetime.datetime.utcnow()
								))

		artist_relationships = [	["1", "main"],
									["2", "guest"],
									["3", "remixer"],
									["4", "composer"],
									["5", "conductor"],
									["6", "dj"],
									["7", "producer"]
								]
		for relationship in artist_relationships:
			if group["extendedArtists"][relationship[0]] is not None:
				for artist in group["extendedArtists"][relationship[0]]:
					# main artists
					db2.merge(Group_Artist(	group_id=group["groupId"],
													artist_id=artist["id"],
													artist_type=relationship[1],
													artist_name=artist["name"]
						))

		# really slow
		for tag in group["tags"]:
			db2.merge(Group_Tag(group_id=group["groupId"], tag=tag))

		# kinda slow
		for torrent in group["torrent"]:
			db2.merge(Torrent(	torrent_id=torrent["id"],
										group_id=group["groupId"],
										media=torrent["media"],
										format=torrent["format"],
										encoding=torrent["encoding"],
										remaster_year=torrent["remasterYear"],
										remastered=torrent["remastered"],
										remaster_title=html.parser.unescape(torrent["remasterTitle"]),
										remaster_record_label=html.parser.unescape(torrent["remasterRecordLabel"]),
										scene=torrent["scene"],
										haslog=torrent["hasLog"],
										hascue=torrent["hasCue"],
										log_score=torrent["logScore"],
										file_count=torrent["fileCount"],
										free_torrent=torrent["freeTorrent"],
										size=torrent["size"],
										leechers=torrent["leechers"],
										seeders=torrent["seeders"],
										snatched=torrent["snatched"],
										time=datetime.datetime.strptime(torrent["time"], "%Y-%m-%d %H:%M:%S")
				))


	db2.commit()

def normalise_artist_name(artist_name):
	res = re.sub(r'([^\s\w]|_)+', '', artist_name)
	res = re.sub(' +',' ',res)
	res = res.lower().strip()

	return res


def get_artist(artist_name):

	cache_name = normalise_artist_name(artist_name)

	results = db2.query(Search_Cache).filter_by(search=cache_name).all()
	if len(results) != 0:
		return results[0].artist_id

	# login if required
	login()
	r = gazelle.get("{0}/artist.php?artistname={1}".format(gazelle_url, artist_name))

	if "<title>Browse Torrents :: " in r.text:
		print("Artist \"{0}\" not found.".format(artist_name))
		exit()

	artist_id = re.search("""id=\"subscribelink_artist([0-9]*)\"""", r.text)

	if not artist_id:
		print("Could not find artist ID")
		exit()

	artist_id = int(artist_id.group(1))

	db2.merge(Search_Cache(artist_id=artist_id, search=cache_name))

	populate_artist(artist_id)

	return artist_id

def encoding_order_func(item):
	if item["encoding"] in encoding_order:
		return encoding_order.index(item["encoding"])
	return 1000

def media_order_func(item):
	if item["media"] in media_order:
		return media_order.index(item["media"])
	return 1000

def fetch_best_albums(artist_id, print_order=False):

	results = []
	artist_name = db2.query(Artist).filter_by(artist_id=artist_id).all()[0].name

	artist_groups_sq = db2.query(Group_Artist.group_id) \
							.filter_by(artist_id=artist_id, artist_type="main")
	groups = db2.query(Group) \
			.filter_by(release_type=1) \
			.filter(Group.group_id.in_(
				db2.query(Group_Artist.group_id) \
					.filter_by(artist_id=artist_id, artist_type="main")
				)) \
			.order_by(Group.year.desc()) \
			.all()


	for group in groups:

		versions = []
		for version in db2.query(Torrent) \
						.filter_by(group_id=group.group_id, format=grab_format) \
						.filter(Torrent.seeders != 0) \
						.all():

			versions.append(dict(version.__dict__)) # without a duplication we get strange crashes


		# order by media field, remastered, encoding field, seeds
		versions = sorted(versions, key=lambda version: version["seeders"], reverse=True)
		versions = sorted(versions, key=lambda version: encoding_order_func(version))
		versions = sorted(versions, key=lambda version: version["remastered"])
		versions = sorted(versions, key=lambda version: media_order_func(version))

		#for version in versions:
		#	print("{0} {1} {2} {3} {4}".format(version["media"].ljust(10), version["encoding"].ljust(10), version["remastered"], str(version["seeders"]).ljust(5), version["remaster_title"]))

		if len(versions) == 0:
			print("No valid torrents found for {0}".format(group.title))
			return

		if print_order is True:
			print("*******************************************")

			for version in versions:
				remaster = ""

				if version["remastered"] == 1:
					remaster = " ({0})".format(version["remaster_title"])
				version["encoding"] = version["encoding"].replace(" (VBR)", "")

				fetched_stats = "Version ({0}/{1}):".format(version["seeders"], version["leechers"])
				print("{0}{1} - {2} - {3}{4} [{5}]".format(	fetched_stats.ljust(22),
															artist_name,
															group.year,
															group.title,
															remaster,
															version["encoding"]))

			print("*******************************************\n")

		selected_version = versions[0]

		remaster = ""
		if selected_version["remastered"] == 1 and selected_version["remaster_title"] != "":
			remaster = " ({0})".format(selected_version["remaster_title"])
		selected_version["encoding"] = selected_version["encoding"].replace(" (VBR)", "")

		torrent_file = get_torrent_file(selected_version["torrent_id"], True)

		curr_result = {
			"seeders" 	: selected_version["seeders"],
			"leechers" 	: selected_version["leechers"],
			"folder" 	: "{0} - {1} - {2}{3} [{4}]".format(	artist_name,
																group.year,
																group.title,
																remaster,
																selected_version["encoding"]
															),
			"file" 		: torrent_file["file"],
			"source"	: torrent_file["source"]
		}

		results.append(curr_result)

	return results

#@profile
def find_and_fetch(artist_name):
	artist_id = get_artist(artist_name)
	results = fetch_best_albums(artist_id)

	for result in results:

		message = "{0}{1}".format(	("{2} ({0}/{1}):".format(result["seeders"], result["leechers"], result["source"])).ljust(22),
									result["folder"]
							)

		print(message)

	return results


def send_to_client(results):

	if script_mode == "file":
		for result in results:

			# convert the folder to be absolute now, for code tidiness
			global torrent_write_path
			torrent_write_path = os.path.abspath(torrent_write_path)

			if not os.path.isdir(torrent_write_path):
				print("Torrent folder {0} does not exist.".format(torrent_write_path))
				exit()

			path = "{0}{1}{2}{3}".format(torrent_write_path, os.path.sep, result["folder"], ".torrent")

			try:
				file = open(path, "wb")
				file.write(result["file"])
				file.close()
			except:
				print("Could not open {0} for writing.".format(path))
				exit()

			print("Wrote {0}".format(path))

	elif script_mode == "rutorrent":

		rutorrent = requests.session()

		for result in results:
			params = {
						"dir_edit": "{0}{1}{2}".format(rutorrent_download_dir, rtorrent_path_sep, result["folder"]),
						"not_add_path": 1,
						"label": rutorrent_label
					}

			if rutorrent_add_stopped is True:
				params["torrents_start_stopped"] = 1

			files = {"torrent_file": result["file"]}
			request_url = "{0}/php/addtorrent.php?{1}".format(rutorrent_url, urllib.parse.urlencode(params))

			try:
				r = rutorrent.post(request_url, params, files=files,
					auth=requests.auth.HTTPDigestAuth(rutorrent_username, rutorrent_password))
			except:
				print("Could not connect to ruTorrent, check your configuration")
				exit()

			if r.status_code == 401:
				print("Unable to authenticate with rutorrent")
				exit()

			if r.text == "log(theUILang.addTorrentFailed);":
				print("Failed to add to rutorrent")
				exit()

			if r.status_code != 200:
				print("There was an error connecting to ruTorrent")
				exit()

			print("Passed \"{0}\" successfully to ruTorrent".format(result["folder"]))

	elif script_mode == "utorrent":

		utorrentconn = utorrent.connection.Connection(utorrent_host, utorrent_username, utorrent_password, False).utorrent("")

		# back up current utorrent settings
		old_torrents_start_stopped = utorrentconn.settings_get( )["torrents_start_stopped"]
		old_dir_torrent_files_flag = utorrentconn.settings_get( )["dir_torrent_files_flag"]
		old_dir_active_download_flag = utorrentconn.settings_get( )["dir_active_download_flag"]
		old_dir_active_download = ""
		if "dir_active_download" in utorrentconn.settings_get( ):
			dir_active_download = utorrentconn.settings_get( )["dir_active_download"]

		# set appropriate settings for our action
		utorrentconn.settings_set({"torrents_start_stopped": utorrent_add_stopped, "dir_torrent_files_flag":False})
		utorrentconn.settings_set({"dir_active_download_flag": True, "dir_active_download":" "})

		for result in results:
			f = open("temp{0}temp.torrent".format(os.path.sep), "wb")
			f.write(result["file"])
			f.close()

			hsh = utorrentconn.torrent_add_file("{0}{1}temp{1}temp.torrent".format(os.getcwd(), os.path.sep), utorrent_download_dir)
			os.remove("{0}{1}temp{1}temp.torrent".format(os.getcwd(), os.path.sep))

			print("Passed \"{0}\" successfully to uTorrent".format(result["folder"]))

		# restore
		utorrentconn.settings_set({	"dir_active_download_flag": old_dir_active_download_flag,
								"torrents_start_stopped": old_torrents_start_stopped,
								"dir_active_download":old_dir_active_download,
								"dir_torrent_files_flag":old_dir_torrent_files_flag})

	elif script_mode == "deluge":
		deluge = requests.session()

		headers = {"Accept": "application/json", "Content-Type": "application/json"}
		data = {
					"id": 1,
					"method": "auth.login",
					"params": [deluge_password]
		}

		try:
			r = deluge.post("{0}/json".format(deluge_url), data=json.dumps(data), headers=headers)
		except(requests.exceptions.ConnectionError):
			print("Unable to connect to deluge on {0}".format(deluge_url))
			exit()


		if r.status_code != 200:
			print("Error communicating with deluge webUI")
			exit()

		resp = json.loads(r.text)

		if resp["result"] != True:
			print("There was an error logging into deluge")

		data["method"] = "web.connected"
		data["params"] = []
		resp = json.loads(deluge.post("{0}/json".format(deluge_url), data=json.dumps(data), headers=headers).text)

		if resp["error"] != None:
			print("Error: {0}".format(resp["error"]["message"]))
			exit()


		for result in results:
			# Upload torrent file
			resp = json.loads(deluge.post("{0}/upload".format(deluge_url),
							  files={'file': result["file"]}).text)

			if resp["success"] != True:
				print("Error: {0}".format(resp["error"]))
				exit()

			add_torrent_data = {
				'id': 1,
				'method': "web.add_torrents",
				'params': [[{
					"path": resp.get('files')[0],
					"options": {
						"download_location": deluge_download_dir,
						"add_paused": deluge_add_stopped
						}
					}]]
				}

			resp = json.loads(deluge.post("{0}/json".format(deluge_url),
				data=json.dumps(add_torrent_data), headers=headers).text)

			if resp["result"] != True:
				print("Error: {0}".format(resp["error"]["message"]))
				exit()

	elif script_mode == "transmission":
		transmission_url = "{0}/transmission/rpc".format(transmission_host)
		transmission = requests.session()

		headers = {
			"Accept": "application/json",
			"Content-Type": "application/json"
		}
		transmission.headers.update(headers)

		if transmission_username and transmission_password:
			transmission.auth = (transmission_username, transmission_password)

		# Get X-Transmission-Session-Id header
		data = {"method": "session-get"}

		r = transmission.post(transmission_url,
			data=json.dumps({"method": "session-get"}))

		session_id = r.headers.get('X-Transmission-Session-Id')

		if r.status_code == 401:
			print("Error authenticating to Transmission interface. "
				  "Is your username and password correct?")
			exit()

		if not session_id:
			print(r.status_code)
			print("Error creating session with Transmission interface")
			exit()

		transmission.headers.update({'X-Transmission-Session-Id': session_id})

		for result in results:
			# Upload torrent file
			upload_data = {
				"method":"torrent-add",
				"arguments":{
					"paused": transmission_add_stopped,
					"download-dir": transmission_download_dir,
					"metainfo": base64.b64encode(
						result['file']).decode('utf-8')
			}}
			r = transmission.post(transmission_url,
				data=json.dumps(upload_data))
			result = json.loads(r.text)

			if result.get('result') is not 'success':
				print("Problem adding torrent: {}".format(result))



try:
	print(u"\u2603 Scraper running...")
except:
	print("""Unicode error - run the program again.""")
	os.system("chcp 65001")
	exit()


parser = argparse.ArgumentParser(description="Automatically download an artist's discography.")

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--artist", type=str, nargs=1, help="The artist's name")
group.add_argument("--from-list", type=str, nargs=1, help="Filename of text file listing multiple artists")

parser.add_argument("--force-artist-refresh", action="store_true", default=False, help="Always redownload an artist's album list")
parser.add_argument('--skip-user-albums', action='store_true', default=False, help="Skip user's existing albums")

args = parser.parse_args()

gazelle = None
database_init()

always_grab = args.force_artist_refresh

user_albums = []

if args.skip_user_albums is True:
	results = db2.query(User_Album).all()

	for ua in results:
		db2.expunge(ua)
		ua.artist = ua.artist.lower()
		ua.album = ua.album.lower()
		user_albums.append(ua)

	user_albums = frozenset(user_albums)

	print(len(user_albums))

	print(user_albums[0] == user_albums[1])


	print("Skipping %d user albums" % len(user_albums))


if args.artist is not None:
	torrents = find_and_fetch(args.artist[0])
	send_to_client(torrents)

elif args.from_list is not None:

	try:
		with open(args.from_list[0]) as f:
			artist_list = f.readlines()

			for i in artist_list:

				# some basic tidyup
				i = ' '.join(i.split()).strip()

				# skip blank lines
				if i is "":
					continue

				print("Looking up %s" % i)
				torrents = find_and_fetch(i)
				send_to_client(torrents)

	except IOError:
		print("Unable to open %s" % args.from_list[0])
		exit()

