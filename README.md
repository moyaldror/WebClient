# WebClient
A bash script that wraps CURL to make it more easy to use. The script also add nice features like on flight capture, detailed and orginaized info prints and more.


Usage: MyClient -i <Host-Address-To-Use> [any other flags...]

Important Note: This script will work best with OpenSSL 1.0.1a and higher and CURL 7.41 and higher


HTTP/HTTPS:

   -i:        Destination ip address or host 

   --Li:      Specify which interface to use 

   --Lp:      Specify whic local port range to use 

   --Rp:      Remote server port 

   -u:        Set the URL path. Make sure that if you use "&" in the path wrap it with "" 

   -S:        Use HTTPS instead of HTTP 

   -H:        Add header to the request (can be used multiple times. Example - "Header:Value") 

   -C:        Use cookies (will be stored and used from /tmp/cookies.tmp) 

   --Jc:      "Forget" the session cookies - This will cause a like new session without the use of previously learned cookies 

   -t:        Set the timeout 

   --UA:      Change the user agent to be used 

   -l:        How many requests to send. Default is infinite 

   -w:        Time to wait between each requests (seconds) (integer only) 


SSL:

   --SV:      SSL version to use. I.E. ssl3, tls10, tls11, tls12 

   --SC:      Cipher suite to use as listed in "openssl ciphers" 

   --NSID:    Disable SSL SessionID reuse 

   --cert:    Client CA Cert to use (PEM format) 

   --key:     Client CA Key to use (PEM format) 

   --pass:    Client CA Key password 


Stats/Info:

   --Pr:      Print reply. Use params headers, body or all 

   --Pq:      Print request headers 

   --Ps:      Print SSL info 

   --cap:     Capture the session. Argumets are file name and interface to capture sepreated with :. I.E. --cap test:eth1 

   --ftp:     Choose FTP server to save the capture file to. Need to add username and pass. Example --ftp 192.168.1.1:user:pass 

   -V:        Show MyClient version and CURL with OpenSSL version 

   -h:        Help 



Examples:

   1. Run 5 HTTPS requests to www.bing.com with 3 seconds delay between requests and store the cookies for next sessions,
      also print the SSL session parameters:

         MyClient -i www.bing.com -S -C -l 5 -w 3 --Ps

   2. Run 1 HTTP request to www.google.com and print the request and replay headers:

         MyClient -i www.google.com --Pr headers --Pq -l 1

   3. Run 10 HTTPS requests to www.google.com and add 2 HTTP headers to you request - "FName: dror" "LName: Moyal".
      Also use only TLSv1.2 and RSA ciphers and capture the session and when done send it to an FTP server:

         MyClient -i www.google.com -H "FName:Dror" -H "LName:Moyal" --SV tls12 --SC RSA --cap file:int --ftp 1.1.1.1:user:pass


Written by DrorM

      Radware QA
