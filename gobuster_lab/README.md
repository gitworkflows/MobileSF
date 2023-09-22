Gobuster v.srlabs.2.0.1 (OJ Reeves @TheColonial)
Modified in SRLabs by Emanuele Vineti
========================================

SRL_Gobuster is a tool used to brute-force and perform web tests:

* URIs (directories and files) in web sites.

### Common Command line options

* `-fw` - force processing of a domain with wildcard results.
* `-np` - hide the progress output.
* `-q` - disables banner/underline output.
* `-t <threads>` - number of threads to run (default: `10`).
* `-u <url/domain>` - full URL (including scheme), or base domain name.
* `-v` - verbose output (show all results).
* `-w <wordlist>` - path to the nikto tests wordlist used for brute forcing.
* `-V` - path to the nikto variable file.
* `-v` - show verbose output.
* `-k` - Skip verification of SSL certificates.
* `-a <user agent string>` - specify a user agent string to send in the request header.
* `-c <http cookies>` - use this to specify any cookies that you might need (simulating auth).
* `-oj <path>` - output file for JSON export.	
* `-o <file>` - specify a file name to write the output to.
* `-p <proxy url>` - specify a proxy to use for all requests (scheme much match the URL scheme).
* `-P <password>` - HTTP Authorization password (Basic Auth only, prompted if missing).
* `-U <username>` - HTTP Authorization username (Basic Auth only).
* `-to <timeout>` - HTTP timeout. Examples: 10s, 100ms, 1m (default: 10s).	


### Building

Since this tool is written in [Go](https://golang.org/) you need install the Go language/compiler/etc. Full details of installation and set up can be found [on the Go language website](https://golang.org/doc/install). Once installed you have two options.

#### Compiling
`gobuster` now has external dependencies, and so they need to be pulled in first:
```
gobuster $ export GOPATH=$(pwd) && go get && go build
```
This will create a `gobuster` binary for you. If you want to install it in the `$GOPATH/bin` folder you can run:
```
gobuster $ go install
```
If you have all the dependencies already, you can make use of the build scripts:
* `make` - builds for the current Go configuration (ie. runs `go build`).
* `make windows` - builds 32 and 64 bit binaries for windows, and writes them to the `build` subfolder.
* `make linux` - builds 32 and 64 bit binaries for linux, and writes them to the `build` subfolder.
* `make darwin` - builds 32 and 64 bit binaries for darwin, and writes them to the `build` subfolder.
* `make all` - builds for all platforms and architectures, and writes the resulting binaries to the `build` subfolder.
* `make clean` - clears out the `build` subfolder.
* `make test` - runs the tests.

#### Running as a script
```
gobuster $ go run main.go <parameters>
```

### Examples

Command line might look like this:
```
$ ./srl_gobuster -k -w ./db_test.txt -V db_variables -u https://example.com

=====================================================
Gobuster v.srlabs.2.0.1 (OJ Reeves @TheColonial)
Modified in SRLabs by Emanuele Vineti
=====================================================
[+] Url/Domain   : https://example.com/
[+] Threads      : 10
[+] Wordlist     : db_test.txt
=====================================================
2019/11/01 11:59:27  Starting gobuster
=====================================================
Found: /.sh_history (Status: 200) [Size: 28]
Found: /.bash_history (Status: 200) [Size: 28]
Found: /kboard/ (Status: 200) [Size: 5]
Found: /users.json (Status: 200) [Size: 3]
Progress: 24034 / 24034 (100.00%)
=====================================================
2019/11/01 12:02:31  Results 
=====================================================
-----------------------------------------------------
- Test Code: 000016
- Description: KBoard Forum 0.3.0 and prior have a security problem in forum_edit_post.php, forum_post.php and forum_reply.php
-----------------------------------------------------

[*] uri: "/kboard/", status: "200" len: 5, body: "Test "

-----------------------------------------------------
- Test Code: 007211
- Description: This might be interesting...
-----------------------------------------------------

[*] uri: "/users.json", status: "200" len: 3, body: "12 "

-----------------------------------------------------
- Test Code: home_directory
- Description: Gobuster classic tests
-----------------------------------------------------

[*] uri: ".sh_history", status: "200" len: 28, body: "curl test.com ping test.com "
[*] uri: ".bash_history", status: "200" len: 28, body: "curl test.com ping test.com "

=====================================================
2019/11/01 12:02:31 Finished
=====================================================

```
Quiet output, with status disabled and expanded mode looks like this ("grep mode"):
```
$ ./srl_gobuster -k -w ./db_test.txt -V db_variables -u https://example.com -q
https://example.com/kboard/
https://example.com/users.json
https://example.com/.sh_history
https://example.com/.bash_history
```

### License

See the LICENSE file.

