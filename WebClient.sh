#!/bin/bash
#==================================================================================================#
# This is a tool used to siplify the use of curl and working with https in general in QA. The tool #
# wrapps aroung CURL and actually creats a CURL aommand using the given arguments.                 #
# Some additions:                                                                                  #
# 	- Abillity to capture the session using a single flag                                          #
# 	- Send the capture file to an FTP server using a single flag                                   #
# 	- Extra features will be added constantly                                                      #
#                                                                                                  #
# This tool was written by:                                                                        #
#                                                                                                  #
#     ########  ########   #######  ########     ##     ##  #######  ##    ##    ###    ##         #
#     ##     ## ##     ## ##     ## ##     ##    ###   ### ##     ##  ##  ##    ## ##   ##         #
#     ##     ## ##     ## ##     ## ##     ##    #### #### ##     ##   ####    ##   ##  ##         #
#     ##     ## ########  ##     ## ########     ## ### ## ##     ##    ##    ##     ## ##         #
#     ##     ## ##   ##   ##     ## ##   ##      ##     ## ##     ##    ##    ######### ##         #
#     ##     ## ##    ##  ##     ## ##    ##     ##     ## ##     ##    ##    ##     ## ##         #
#     ########  ##     ##  #######  ##     ##    ##     ##  #######     ##    ##     ## ########   #
#==================================================================================================#

#++++++++++++++++++++++++++
# Init function           +
#++++++++++++++++++++++++++
function init_flags(){

	destination_flag="false"
	server_port_flag="false"
	local_port_flag="false"
	interface_flag="false"
	cookies_flag="false"
	junk_cookies_flag="false"
	timeout_flag="false"
	url_flag="false"
	user_agent_flag="false"
	no_ssl_sessid_flag="false"
	HTTPS_flag="false"
	loops_flag="false"
	wait_flag="false"
	SSL_Version_flag="false"
	Cipher_flag="false"
	Header_flag="false"
	print_reply_flag="false"
	print_request_flag="false"
	printSSL_flag="false"
	CA_cert_flag="false"
	CA_key_flag="false"
	CA_pass_flag="false"
	capture_flag="false"
	ftp_dump_flag="false"
}

#+++++++++++++++++++++++++++++++++++++++
# Function to print a line in the help +
#+++++++++++++++++++++++++++++++++++++++
function print_help_line(){
	echo "$1" | awk '{ printf "   %-10s ", $1 ; for (i=2; i<=NF; i++) printf $i" "; printf "\n\n"}'
}

#+++++++++++++++++++++++++++++++++++++++++
# Function to print a header in the help +
#+++++++++++++++++++++++++++++++++++++++++
function print_help_header(){
	tput bold
	echo "$1";echo
	tput sgr0
}

#+++++++++++++++++++++++++++++
# Function to print the help +
#+++++++++++++++++++++++++++++
function print_help(){

	echo
	print_help_header "Usage: $0 -i <Host-Address-To-Use> [any other flags...]"
	print_help_header "Important Note: This script will work best with OpenSSL 1.0.1a and higher and CURL 7.41 and higher"
	echo
	print_help_header "HTTP/HTTPS:"
	print_help_line "-i:	Destination ip address or host" 
	print_help_line "--Li:	Specify which interface to use" 
	print_help_line "--Lp:	Specify whic local port range to use" 
	print_help_line "--Rp:	Remote server port" 
	print_help_line "-u:	Set the URL path. Make sure that if you use \"&\" in the path wrap it with \"\"" 
	print_help_line "-S:	Use HTTPS instead of HTTP" 
	print_help_line "-H:	Add header to the request (can be used multiple times. Example - \"Header:Value\")" 
	print_help_line "-C:	Use cookies (will be stored and used from /tmp/cookies.tmp)" 
	print_help_line "--Jc:	\"Forget\" the session cookies - This will cause a like new session without the use of previously learned cookies"  
	print_help_line "-t:	Set the timeout" 
	print_help_line "--UA:	Change the user agent to be used" 
	print_help_line "-l:	How many requests to send. Default is infinite" 
	print_help_line "-w:	Time to wait between each requests (seconds) (integer only)" 
	echo
	print_help_header "SSL:"
	print_help_line "--SV:	SSL version to use. I.E. ssl3, tls10, tls11, tls12" 
	print_help_line "--SC:	Cipher suite to use as listed in \"openssl ciphers\"" 
	print_help_line "--NSID:	Disable SSL SessionID reuse" 
	print_help_line "--cert:	Client CA Cert to use (PEM format)" 
	print_help_line "--key:	Client CA Key to use (PEM format)" 
	print_help_line "--pass:	Client CA Key password" 
	echo
	print_help_header "Stats/Info:"
	print_help_line "--Pr:	Print reply. Use params headers, body or all" 
	print_help_line "--Pq:	Print request headers" 
	print_help_line "--Ps:	Print SSL info" 
	print_help_line "--cap:	Capture the session. Argumets are file name and interface to capture sepreated with :. I.E. --cap test:eth1"  
	print_help_line "--ftp:	Choose FTP server to save the capture file to. Need to add username and pass. Example --ftp 192.168.1.1:user:pass" 
	print_help_line "-V:	Show $0 version and CURL with OpenSSL version" 
	print_help_line "-h:	Help" 
	echo; echo
	print_help_header "Examples:"
	echo "   1. Run 5 HTTPS requests to www.bing.com with 3 seconds delay between requests and store the cookies for next sessions,"
	echo "      also print the SSL session parameters:"
	echo
	echo " 	 $0 -i www.bing.com -S -C -l 5 -w 3 --Ps"
	echo
	echo "   2. Run 1 HTTP request to www.google.com and print the request and replay headers:"
	echo
	echo " 	 $0 -i www.google.com --Pr headers --Pq -l 1"
	echo
	echo "   3. Run 10 HTTPS requests to www.google.com and add 2 HTTP headers to you request - \"FName: dror\" \"LName: Moyal\"."
	echo "      Also use only TLSv1.2 and RSA ciphers and capture the session and when done send it to an FTP server:"
	echo 
	echo " 	 $0 -i www.google.com -H \"FName:Dror\" -H \"LName:Moyal\" --SV tls12 --SC RSA --cap file:int --ftp 1.1.1.1:user:pass"
	echo
	echo
	print_help_header "Written by DrorM"
	print_help_header "      Radware QA"
	echo
}

#+++++++++++++++++++++++++
# Check usage is correct +
#+++++++++++++++++++++++++
function new_checkUsage(){

	# Init all flags
	init_flags
	
	# Init headers number
	numOfHeaders=0
	
	# Call getopt program to use all the flags and break them
	TEMP=$(getopt -o i:u:L:l:w:H:t:rhCSV --long SV:,SC:,Pq,Ps,Pr:,cert:,key:,pass:,Rp:,cap:,ftp:,Li:,Lp:,UA:,NSID,Jc -n '$0' -- "$@")
	
	# Caes getopt failed
	if [ $? != 0 ] ; then 
		echo "Terminating..." >&2; exit 1
	fi
	
	# Note the quotes around `$TEMP': they are essential!
	eval set -- "$TEMP"
	
	# Use all the flags and init flags and variables accordingly
	while true; do
		case "$1" in
			-h ) print_help $0; exit 0;;
			-i ) destination_flag="true"; host=$2; shift 2;;
			--Li ) interface_flag="true"
					# Validate that the interface exist
					if ifconfig | grep -q "$2"; then
						interfaceUse="--interface $2"; shift 2
					else
						echo "Interface doesn't exist"; exit 1
					fi
					;;
			--Lp ) local_port_flag="true"
					# Validate that the port isn't already taken and also is 1<=localPort<=65535 
					if [ "$2" -gt "0" ] && [ "$2" -lt "65536" ] && ! netstat -lntu | grep -q "$2"; then
						localPort="--local-port $2"; shift 2
					else
						echo "Can't used port (not in range or already used)"; exit 1
					fi
					;;
			-u ) url_flag="true"; urlStr="$2"; shift 2;;
			--Rp ) server_port_flag="true"
					# Validate that the number is 1<=srvPort<=65535 
					if [ "$2" -gt "0" ] && [ "$2" -lt "65536" ]; then
						srvPort="$2"; shift 2
					else
						echo "Wrong port used (not in range)"; exit 1
					fi
					;;
			-S ) HTTPS_flag="true"; shift;;
			-l ) loops_flag="true";numLoops=$2; shift 2
					# Make sure the number of loops is bigger than 1
					if [ $numLoops -lt 1 ]; then
						echo "Number of loops must be larger than 0"; exit 1
					fi;;
			-w ) wait_flag="true"; waitBetween=$2; shift 2
					# Make sure the wait arg passed by the user is possitive and an integer
					re='^[0-9]+$'
					if ! [[ $waitBetween =~ $re ]] || [ "$waitBetween" -lt "0" ]; then
						echo "Wait must be an integer number larger or eqaul to 0"; exit 1
					fi;;
			-H ) Header_flag="true"; headerStr[$numOfHeaders]=" -H \""`echo $2| sed 's/:/: /g'`"\""; numOfHeaders=$(( numOfHeaders + 1 )); shift 2;;
			-r ) reuse_flag="true"; shift;;
			-C ) cookies_flag="true"; shift;;
			--Jc ) junk_cookies_flag="true"; shift;;
			-t ) timeout_flag="true"
					# Make sure the timeout is possitive
					if [ $2 -lt 0 ]; then
						echo "Timeout must be larger than 0"; exit 1
					else
						timeoutNum="--max-time $2"; shift 2
					fi;;
			--UA ) user_agent_flag="true"; userAgent="-A \"$2\""; shift 2;;
			--Ps ) printSSL_flag="true"; shift;;
			--SV ) SSL_Version_flag="true"; sslVersion=$2; shift 2
					# Check that the ssl version is valid
					case "$sslVersion" in
						ssl3)   sslVersion="--sslv3";;
						tls10)  sslVersion="--tlsv1.0" ;;
						tls11)  sslVersion="--tlsv1.1" ;;
						tls12)  sslVersion="--tlsv1.2" ;;
						*)		echo "Wrong SSL version"; exit 1;;
					esac;;
			--SC ) Cipher_flag="true"; cipherSuite=$2; shift 2
					# Validate that the cipher suite really exist in openssl
					if openssl ciphers| grep -q "$cipherSuite"; then
						cipherSuite="--ciphers "$cipherSuite
					else
						echo "Wrong Cipher suite"; exit 1
					fi
					;;
			--NSID ) no_ssl_sessid_flag="true"; shift;;
			--Pq )  print_request_flag="true"; shift;;
			--Pr ) print_reply_flag="true"; toPrintReply=$2; shift 2
					# Check that the arg is valid
					if [ "$toPrintReply" != "headers" ] && [ "$toPrintReply" != "body" ] && [ "$toPrintReply" != "all" ]; then
						echo "Wrong print value"; exit 1
					fi;;
			--cert ) CA_cert_flag="true"; CA_CERT=$2; shift 2;;
			--key )  CA_key_flag="true"; CA_KEY=$2; shift 2;;
			--pass ) CA_pass_flag="true"; CA_PASS=$2; shift 2;;
			--cap ) capture_flag="true"; capture_args=$2; shift 2;;
			--ftp ) ftp_dump_flag="true"; ftp_args=$2; shift 2;;
			-V ) 	curlVer=`curl -V | grep curl | awk -F" " '{print $2}'`
					openSslVer=`curl -V | grep curl | awk -F" " '{print $5}'`; openSslVer=`echo "$openSslVer" | awk -F"/" '{print $2}'`
					echo; echo "MyClient version 1.0"; echo "Curl version $curlVer with OpenSSL version $openSslVer"; echo 
					exit 0;;
			* ) break ;;
		esac
		
		# Validate that the client certificate file exist
		if [ ! -f $CA_CERT ] ; then
			echo "$CA_CERT doesn't exist or it's a directory"; exit 1
		fi
		
		# Validate that the client key file exist
		if [ ! -f $CA_KEY ] ; then
			echo "$CA_KEY doesn't exist or it's a directory"; exit 1
		fi
		
	done
	
	# Validate that the user has choosen a destination
	if [ "$destination_flag" == "false" ]; then
		echo "You must specify a desination address or host"; exit 1
	fi
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that builds the curl command to be used               +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function buildCommand(){

	curlCommand="curl "
	
	# Use https
	if [ "$HTTPS_flag" == "true" ]; then
		myUri="\"https://"$host
	# Use http
	else
		myUri="\"http://"$host
	fi
	
	# Use remote server port
	if [ "$server_port_flag" == "true" ]; then
		myUri=$myUri":$srvPort"
	fi
	
	# Use path
	if [ "$url_flag" == "true" ]; then
		myUri=$myUri"/$urlStr"
	fi
	
	# Close the URI string
	myUri=$myUri"\""
	
	# Use the same connection for multiple requests
	if [ "$reuse_flag" == "true" ]; then
		temp=$myUri
		
		for i in `seq 1 $(( $numLoops-1 ))`; do
			myUri=$myUri" $temp"
		done
		numLoops=1
	fi
	
	# Attach the URI to the CURL command
	curlCommand=$curlCommand"$myUri "
	
	# Add local interface to use
	if [ "$interface_flag" == "true" ]; then
		curlCommand=$curlCommand"$interfaceUse "
	fi
	
	# Add local port to use
	if [ "$local_port_flag" == "true" ]; then
		curlCommand=$curlCommand"$localPort "
	fi
	
	# Forget session cookies
	if [ "$junk_cookies_flag" == "false" ]; then
		#curlCommand=$curlCommand"--junk-session-cookies "
		
		# Add use of cookies
		if [ "$cookies_flag" == "true" ]; then
			curlCommand=$curlCommand"--cookie-jar \"/tmp/cookies.tmp\" --cookie \"/tmp/cookies.tmp\" "
		fi
	fi
	
	# Store the reply headers
	if [ "$print_reply_flag" == "true" ]; then
		curlCommand=$curlCommand"--dump-header \"/tmp/rep_headers.tmp\" "
	fi
	
	# Use timeout 
	if [ "$timeout_flag" == "true" ]; then
		curlCommand=$curlCommand"$timeoutNum "
	fi
	
	# Change the user-agent 
	if [ "$user_agent_flag" == "true" ]; then
		curlCommand=$curlCommand"$userAgent "
	fi
	
	# Choose a specific SSL version
	if [ "$SSL_Version_flag" == "true" ]; then
		curlCommand=$curlCommand"$sslVersion "
	fi
	
	# Choose a specific SSL cipher suite
	if [ "$Cipher_flag" == "true" ]; then
		curlCommand=$curlCommand"$cipherSuite "
	fi
	
	# Disable the use of SSL session-id reuse
	if [ "$no_ssl_sessid_flag" == "true" ]; then
		curlCommand=$curlCommand"--no-sessionid "
	fi
	
	# Add custom headers
	if [ "$Header_flag" == "true" ]; then
	
		# Case of multiple use of the header flag
		for i in `seq 0 $numOfHeaders`; do
			curlCommand=$curlCommand"${headerStr[$i]} "
		done
	fi
	
	# Use client certificate
	if [ "$CA_cert_flag" == "true" ] && [ "$CA_key_flag" == "true" ] && [ "$CA_pass_flag" == "true" ]; then
		curlCommand=$curlCommand"--cert $CA_CERT:$CA_PASS --key $CA_KEY "
	# Defualt behaviore - NO client certificate
	elif [ "$CA_cert_flag" == "false" ] && [ "$CA_key_flag" == "false" ] && [ "$CA_pass_flag" == "false" ]; then
		curlCommand=$curlCommand"--insecure "
	# Wrong usage
	else
		echo "When using client certificate you must configure Certificate, Key and password!"; exit 0
	fi
	
	# Case the user have choose looping counter
	if [ "$loops_flag" == "false" ]; then
		numLoops=1
	fi
	
	# Add values used to get all data needed to present timings, request headers, body etc.
	curlCommand=$curlCommand" -v -s -w %{time_total}:%{http_code}:%{local_ip}:%{local_port} -o /tmp/body.tmp"
	
	# Store the command for debug
	echo $curlCommand > /tmp/debug.log
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that prints SSL Session parameters                    +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function print_ssl_session_parameters(){

	echo " SSL Session parameters:"
	echo " ========================="
	
	echo -n " Using:"
	# Use awk to get the SSL session parameters from the verbose printing output
	awk 'BEGIN { RS = "" ; FS = "SSL connection using" } {print $2}' /tmp/headers.tmp | awk 'BEGIN { RS = "" ; FS = "> GET" } {print $1}' | sed 's/\*//g'
	
	echo
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that prints the request headers only                  +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function print_request(){

	echo " Request Headers:"
	echo " ===================="
	
	# Use awk to get the request headers from the verbose printing output
	awk 'BEGIN { RS = "" ; FS = "\r\n> \r\n" } {print $1}'  /tmp/headers.tmp | awk 'BEGIN { RS = "" ; FS = "> " } {$1=""; print}'
	echo
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that prints the reply according to the user selection +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function print_reply(){

	echo " Reply:"
	echo " ===================="
	
	# Print according to the users selection
	case $toPrintReply in
		headers)cat /tmp/rep_headers.tmp | sed 's/^/ /';;
		body)   cat /tmp/body.tmp | sed 's/^/ /' ;;
		all)    cat /tmp/rep_headers.tmp | sed 's/^/ /' 
				echo
				cat /tmp/body.tmp | sed 's/^/ /';;
	esac
	
	echo; echo
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that uses the HTTP code number and returns the corespondig +
# string with code number and string value                            +
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function get_resCode(){

	# Return a string with code and string description according to the numeral value
	case $resultCode in
		100 ) resultCode="100 Continue";;
		101 ) resultCode="101 Switching Protocols";;
		102 ) resultCode="102 Processing";;
		200 ) resultCode="200 OK";;
		201 ) resultCode="201 Created";;
		202 ) resultCode="202 Accepted";;
		203 ) resultCode="203 Non-Authoritative Information";;
		204 ) resultCode="204 No Content";;
		205 ) resultCode="205 Reset Content";;
		206 ) resultCode="206 Partial Content";;
		207 ) resultCode="207 Multi-Status";;
		208 ) resultCode="208 Already Reported";;
		226 ) resultCode="226 IM Used";;
		300 ) resultCode="300 Multiple Choices";;
		301 ) resultCode="301 Moved Permanently";;
		302 ) resultCode="302 Found";;
		303 ) resultCode="303 See Other";;
		304 ) resultCode="304 Not Modified";;
		305 ) resultCode="305 Use Proxy";;
		306 ) resultCode="306 Switch Proxy";;
		307 ) resultCode="307 Temporary Redirect";;
		308 ) resultCode="308 Permanent Redirect";;
		308 ) resultCode="308 Resume Incomplete";;
		400 ) resultCode="400 Bad Request";;
		401 ) resultCode="401 Unauthorized";;
		402 ) resultCode="402 Payment Required";;
		403 ) resultCode="403 Forbidden";;
		404 ) resultCode="404 Not Found";;
		405 ) resultCode="405 Method Not Allowed";;
		406 ) resultCode="406 Not Acceptable";;
		407 ) resultCode="407 Proxy Authentication Required";;
		408 ) resultCode="408 Request Timeout";;
		409 ) resultCode="409 Conflict";;
		410 ) resultCode="410 Gone";;
		411 ) resultCode="411 Length Required";;
		412 ) resultCode="412 Precondition Failed";;
		413 ) resultCode="413 Payload Too Large";;
		414 ) resultCode="414 Request-URI Too Long";;
		415 ) resultCode="415 Unsupported Media Type";;
		416 ) resultCode="416 Requested Range Not Satisfiable";;
		417 ) resultCode="417 Expectation Failed";;
		418 ) resultCode="418 I'm a teapot";;
		419 ) resultCode="419 Authentication Timeout";;
		420 ) resultCode="420 Method Failure";;
		420 ) resultCode="420 Enhance Your Calm";;
		421 ) resultCode="421 Misdirected Request";;
		422 ) resultCode="422 Unprocessable Entity";;
		423 ) resultCode="423 Locked";;
		424 ) resultCode="424 Failed Dependency";;
		426 ) resultCode="426 Upgrade Required";;
		428 ) resultCode="428 Precondition Required";;
		429 ) resultCode="429 Too Many Requests";;
		431 ) resultCode="431 Request Header Fields Too Large";;
		440 ) resultCode="440 Login Timeout";;
		444 ) resultCode="444 No Response";;
		449 ) resultCode="449 Retry With";;
		450 ) resultCode="450 Blocked by Windows Parental Controls";;
		451 ) resultCode="451 Unavailable For Legal Reasons";;
		451 ) resultCode="451 Redirect";;
		494 ) resultCode="494 Request Header Too Large";;
		495 ) resultCode="495 Cert Error";;
		496 ) resultCode="496 No Cert";;
		497 ) resultCode="497 HTTP to HTTPS";;
		498 ) resultCode="498 Token expired/invalid";;
		499 ) resultCode="499 Client Closed Request";;
		499 ) resultCode="499 Token required";;
		500 ) resultCode="500 Internal Server Error";;
		501 ) resultCode="501 Not Implemented";;
		502 ) resultCode="502 Bad Gateway";;
		503 ) resultCode="503 Service Unavailable";;
		504 ) resultCode="504 Gateway Timeout";;
		505 ) resultCode="505 HTTP Version Not Supported";;
		506 ) resultCode="506 Variant Also Negotiates";;
		507 ) resultCode="507 Insufficient Storage ";;
		508 ) resultCode="508 Loop Detected";;
		509 ) resultCode="509 Bandwidth Limit Exceeded";;
		510 ) resultCode="510 Not Extended";;
		511 ) resultCode="511 Network Authentication Required";;
		520 ) resultCode="520 Unknown Error";;
		522 ) resultCode="522 Origin Connection Time-out";;
		598 ) resultCode="598 Network read timeout error";;
		599 ) resultCode="599 Network connect timeout error";;
		*) resultCode=$resultCode" Unknown Code";;
	esac
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that print statisctics and info when a session passed +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function on_session_pass(){

	# store the stats
	stats="$failCounter/$sessCounter"
	
	# create the result code for the HTTP request
	get_resCode
	
	# Case of verbose action
	if [ "$printSSL_flag" == "true" ] || [ "$print_request_flag" == "true" ] || [ "$print_reply_flag" == "true" ]; then
		echo "================================================================================================"
		echo "$stats $totalTime $pageStr $socketInfo $resultCode" | awk '{ printf " %-12s %-8s %-35s %-22s ", $1, $2, $3, $4;for (i=5; i<=NF; i++) printf $i" "; printf "\n"}'
		echo "================================================================================================"
		echo
	# Case of non verbose action
	else
		echo "$stats $totalTime $pageStr $socketInfo $resultCode" | awk '{ printf " %-12s %-8s %-35s %-22s ", $1, $2, $3, $4;for (i=5; i<=NF; i++) printf $i" "; printf "\n"}'
	fi
	
	# Print SSL Session parameters
	if [ "$printSSL_flag" == "true" ] && [ "$HTTPS_flag" == "true" ] ; then
		print_ssl_session_parameters
	fi
	
	# Print request headers
	if [ "$print_request_flag" == "true" ]; then
		print_request
	fi
	
	# Print the reply with the user selection
	if [ "$print_reply_flag" == "true" ]; then
		print_reply
	fi
}

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that uses the CURL exit status and build an error string +
# that matches to the exit status of that command                   +
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function get_error(){

	# Return an error string according to the exit status of the CURL command
	case $cmdRes in
		1)  errStr="Unsupported Protocol";;
		2)  errStr="Failed to init";;
		3)  errStr="Bad URL";;
		6)  errStr="Couldn't resolve host";;
		7)  errStr="Failed to connect";;
		9)  errStr="Access denied";;
		15) errStr="FTP couldn't resolve the host IP";;
		18) errStr="File transfer was shorter or larger than expected";;
		27) errStr="Out of memory";;
		28) errStr="Timeout";;
		34) errStr="Post error";;
		35) errStr="SSL Handshake error";;
		45) errStr="Interface error";;
		47) errStr="Too many redirects";;
		51) errStr="The remote server's SSL certificate or SSH md5 fingerprint was deemed not OK";;
		52) errStr="Nothing was returned from the server";;
		53) errStr="The specified crypto engine wasn't found";;
		54) errStr="Failed setting the selected SSL crypto engine as default!";;
		55) errStr="Failed sending network data";;
		56) errStr="Failure with receiving network data";;
		58) errStr="problem with the local client certificate";;
		59) errStr="Couldn't use specified cipher";;
		60) errStr="Peer certificate cannot be authenticated with known CA certificates";;
		61) errStr="Unrecognized transfer encoding";;
		63) errStr="Maximum file size exceeded";;
		66) errStr="Initiating the SSL Engine failed";;
		67) errStr="The remote server denied login";;
		77) errStr="Problem with reading the SSL CA cert";;
		78) errStr="The resource referenced in the URL does not exist";;
		80) errStr="Failed to shut down the SSL connection";;
		83) errStr="Issuer check failed";;
		*)  errStr="Unknown error";;
	esac
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that print statisctics and info when a session falied +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function on_session_fail(){

	# Increase the failed session counter
	failCounter=$(( failCounter+1 ))
	
	# Get the error string
	get_error
	
	# Case of verbose action
	if [ "$printSSL_flag" == "true" ] || [ "$print_request_flag" == "true" ] || [ "$print_reply_flag" == "true" ]; then
		echo "================================================================================================"
		echo "$failCounter/$sessCounter $totalTime $pageStr $socketInfo $errStr" | awk '{ printf " %-12s %-8s %-35s %-22s ", $1, $2, $3, $4;for (i=5; i<=NF; i++) printf $i" "; printf "\n"}'
		echo "================================================================================================"
		echo
	# Case of non verbose action
	else
		echo "$failCounter/$sessCounter $totalTime $pageStr $socketInfo $errStr" | awk '{ printf " %-12s %-8s %-35s %-22s ", $1, $2, $3, $4;for (i=5; i<=NF; i++) printf $i" "; printf "\n"}'
	fi
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that starts a packet capture                          +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function start_capture(){

	# Get the file name from the passed argument
	fileName=$(echo "$capture_args" | awk -F":" '{print $1}')
	
	# Get the interface name from the passed argument
	ifName=$(echo "$capture_args" | awk -F":" '{print $2}')
	
	# Make sure the interfce exist
	ifExist=$(ip link show | grep mtu | awk -F": " '{print $2}' | grep $ifName)
	
	# Make sure the interfce exist
	if [ "$ifExist" != "$ifName" ]; then
		echo "Capture interface does not exist. Terminating..."
		exit 1
	fi
	
	# Start tshark in the background and store the process id in PID
	(tshark -i "$ifName" -q -w "$fileName".pcap > /dev/null 2>&1 ) & capture_pid=$!
	
	sleep 3s
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that kill the capture process and if needed put the   +
# capture file on a given FTP server                             +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function finish_capture(){
	# Kill the capture process
	kill  -9 $capture_pid
	wait $capture_pid > /dev/null 2>&1
	sleep 1s
	
	# Case the user choose to send the file to an FTP server
	if [ "$ftp_dump_flag" == "true" ]; then
	
		# Get the FTP server ip
		ftp_server=`echo $ftp_args | awk -F":" '{print $1}'`
		
		# Get the FTP username
		ftp_user=`echo $ftp_args | awk -F":" '{print $2}'`
		
		# Get the FTP password
		ftp_pass=`echo $ftp_args | awk -F":" '{print $3}'`
		
		# Put the file on the FTP server
		curl -u "$ftp_user":"$ftp_pass" -T "$fileName".pcap ftp://"$ftp_server" -s > /dev/null 2>&1
		
		cmdRes=$?
		# Error validation
		if [ "$cmdRes" == "0" ]; then
			echo; echo "File was moved to the FTP server successfuly"
		else
			get_error
			echo; echo "Failed to moved the file to the FTP server because of the following error:"; echo "$errStr"
		fi
	fi
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that do all current session necessary work            +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function do_session_loop(){
	# In case the user choose how many loops to do, increase i
	if [ "$loops_flag" == "true" ]; then
		let index+=1
	fi
	# Increase the session counter
	let sessCounter+=1
	
	# Run the CURL command and print the verbose output to /tmp/headers.tmp
	cmdStrRes=`eval $curlCommand 2> /tmp/headers.tmp`
	# Get the exit status of the CURL command
	cmdRes=$?
	# Store the retrieving time
	totalTime=`echo $cmdStrRes | awk -F":" '{print $1}'`
	# Store the HTTP reply code
	resultCode=`echo $cmdStrRes | awk -F":" '{print $2}'`
	socketInfo=`echo $cmdStrRes | awk -F":" '{print $3":"$4}'`
	# Case the session passed
	if [ "$cmdRes" == "0" ]; then
		on_session_pass
	# Case the session had failed
	else
		on_session_fail
	fi
	
	# Handle Ctrl+C:
	# 	- Print the current stats
	#	- If capturing the session then stop the capture
	if [ "$capture_flag" == "true" ]; then
		trap "echo; echo \" Summary\"; echo \"  Fail/Total\"; echo \"  $failCounter/$sessCounter\"; kill -9 $capture_pid; wait $capture_pid > /dev/null 2>&1 ; exit" INT
	else
		trap "echo; echo \" Summary\"; echo \"  Fail/Total\"; echo \"  $failCounter/$sessCounter\"; exit" INT
	fi
	
	# Case using a wait between each session
	# The second condition is for the last session to not wait
	if [ "$wait_flag" == "true" ] && [ $index -lt $numLoops ]; then
		sleep "$waitBetween"s
	fi
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Function that wrapps all the traffic, stats and all the actual +
# work of this script                                            +
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function runTraffic(){
	# Init function related variables
	failCounter=0
	sessCounter=0
	index=0
	
	# Call a function to build the command
	buildCommand
	
	# Case user asked to capture the session
	if [ "$capture_flag" == "true" ]; then
		start_capture
	fi
	
	# Print headlines
	echo "Fail/Total Time Site Socket-Info Result" | awk '{ printf " %-12s %-8s %-35s %-22s %-25s\n", $1, $2, $3 ,$4, $5}'
	echo "---------- ---- ---- ----------- ------" | awk '{ printf " %-12s %-8s %-35s %-22s %-25s\n", $1, $2, $3, $4, $5}'
	
	# Remove the wrapping ""
	pageStr=`echo "$myUri" | sed 's/\"//g'`
	# In case the is a use of a url
	if [ "$url_flag" == "true" ]; then
		# Print only the first 30 characters of the full url
		pageStr=${pageStr:0:30}"..."
	fi
	
	# Traffic loop. Runs until i will reach numOfLoops.
	# In case the user haven't choose number of loops to do
	# the variable will be 1
	until [  $index -eq $numLoops ]; do
		do_session_loop
	done
	
	# Case session was captured, now the session was finished and it's
	# time to stop the capture
	if [ "$capture_flag" == "true" ]; then
		finish_capture
	fi
	
	# Print stats 
	echo; echo " Summary:"; echo "  Fail/Total"; echo "  $failCounter/$sessCounter"
}


#++++++++++++++++++++++++++++++++++++
#                MAIN               +
#++++++++++++++++++++++++++++++++++++
new_checkUsage $@
echo
runTraffic
