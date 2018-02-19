This software:
	* scans selected directory (symlink loops tolerated), and constructs graph in memory
	* watches directory recusively via inotify
	* serves it thru http, as templated html
	* allows reloading rendering templates via SIGHUP
	* is basically autoindexer except it never reads from disk unless inotify event makes it do it

I programmed it for my own needs so don't expect good documentation.

License: MIT; see LICENSE.txt.
