# gazelle-cli

gazelle-cli utilises the Gazelle framework's API, allowing additional tasks to be performed from the user's command line. Written for Python 3, compatible with both Windows and Linux.

## Features
gazelle-cli was built primarily to allow automated download of multiple torrents from a gazelle based BitTorrent website. Using a single command, a user can automatically download an entire set of torrent files, and load them into their client via a web interface. By default a sqlite database is used, however MySQL is supported for advanced users.

### Supported modes
* rutorrent (rtorrent) - local or remote
* utorrent 3 - local only
* deluge - local or remote
* transmission - local or remote
* file - writes out files to a local folder

#### rtorrent-specific notes
Unlike any other BitTorrent client, rtorrent allows for the root download folder of the torrent to be specified. Leveraging this, it is possible to set an intelligent download folder for each torrent, ignoring the one set by the .torrent file. This can be modified, but defaults to:
`Artist - Year - Album [Encoder]`

## Installation

A working installation of Python 3 is required. If users wish to use a MySQL database, an appropriate database and MySQL user must be created in advance.

Clone the repository using git, or download and extract a zip file of the latest release.

### Windows
* Install [python3](https://www.python.org/downloads)
* Install [pip3](https://pip.pypa.io/en/stable/installing)
* Open a command prompt
* `pip3 install virtualenv`
* `C:\python34\Scripts\virtualenv venv`
* `venv\Scripts\activate.bat`
* `C:\python34\Scripts\pip3 install -r requirements.txt`
* `copy config.py-dist config.py`
Edit `config.py`, ensuring you at minimum fill in the domain and login details for your gazelle site, and script mode

_Note: Use of Console2 is recommended on Windows. The first time the script is run in a newly opened prompt, the code page is altered to allow for Unicode, and exits. Simply rerun the command to continue._

### Linux
* Install python3, pip3, virtualenv
* `virtualenv venv`
* `source ./venv/scripts/activate`
* `pip3 install -r requirements.txt`
* `cp config.py-dist config.py`
Edit `config.py`, ensuring you at minimum fill in the domain and login details for your gazelle site, and script mode


## Example usage

* Download all torrents with an artist of "Melt-Banana"
``python gazelle-cli --artist "Melt-Banana"

`(venv) python gazelle-cli.py --artist "Melt Banana"`

    ☃ Scraper running...
    Logged in as user
    Fetched artist 12345
    Fetched (10/1):      Melt-Banana - 2013 - Fetch [V0]
    Fetched (11/0):      Melt-Banana - 2007 - Bambi's Dilemma [V0]
    Fetched (12/0):      Melt-Banana - 2003 - Cell-Scape [V0]
    Fetched (13/0):      Melt-Banana - 2000 - Teeny Shiny [V0]
    Fetched (14/3):      Melt-Banana - 1998 - Charlie [V0]
    Fetched (15/0):      Melt-Banana - 1995 - Scratch or Stitch [V0]
    Fetched (44/0):      Melt-Banana - 1994 - Speak Squeak Creak [V0]
    Fetched (99/2):      Melt-Banana - 1994 - Cactuses Come in Flocks [V0]
    Passed "Melt-Banana - 2013 - Fetch [V0]" successfully to ruTorrent
    Passed "Melt-Banana - 2007 - Bambi's Dilemma [V0]" successfully to ruTorrent
    Passed "Melt-Banana - 2003 - Cell-Scape [V0]" successfully to ruTorrent
    Passed "Melt-Banana - 2000 - Teeny Shiny [V0]" successfully to ruTorrent
    Passed "Melt-Banana - 1998 - Charlie [V0]" successfully to ruTorrent
    Passed "Melt-Banana - 1995 - Scratch or Stitch [V0]" successfully to ruTorrent
    Passed "Melt-Banana - 1994 - Speak Squeak Creak [V0]" successfully to ruTorrent
    Passed "Melt-Banana - 1994 - Cactuses Come in Flocks [V0]" successfully to ruTorrent


* Download all torrents from a list of artists contained in artists.txt
`(venv) python gazelle-cli.py --from-list artists.txt`

* Download all torrents with an artist of "Melt-Banana", after a new relase has been added (refreshing the local database)
`(venv) python gazelle-cli.py --artist "Melt Banana" --force-artist-refresh`

It is also possible to skip downloading of torrents which match a user-defined list - users will need to insert them manually into the user_albums table in their database.
`(venv) python gazelle-cli.py --artist "Melt Banana" --skip-user-albums`




## Notes

Currently the script only downloads listed studio albums, however other categories of torrent can be added if there is sufficient interest. Contributions are welcome. Currently artist data is cached in the database.

## License

Released under [GNU GPLv3](http://www.gnu.org/licenses/gpl-3.0.en.html)