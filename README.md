# peer-to-peer
  This is a p2p messaging implementation through Twisted Python.

## setup
  You need Twisted
    
    pip install twisted
  And anything that says `No module found for blahblahblah` just
    
    pip install blahblahblah
    
## usage
  alice_peer.py and bob_peer.py are the same thing. A Twisted server and client.
  
  This means initially one of them must be the server and the other a client
  To do this open up a terminal and run:
    
    python bob_peer.py
  here bob defaults to being a server
  
  Now open up another terminal and run:
    
    python alice_peer.py --sport 8124 --cport 8123 --ping
  
  This says alice must listen on port 8124, connect to 8123 and start ping the server on 8123.
  
  More exaplanations on flags are available with:
    
    python bob_peer.py -h
  
  You should see something like this:
    
    Should be a p2p service

        optional arguments:
          -h, --help     show this help message and exit
          --sip SIP      the IP Adress you want to connect to, defaults to localhost
          --sport SPORT  specifies the port number that the server listens on,
                         defaults to 8123
          --cport CPORT  specifies the port number that the client connects to,
                         defaults to 8124
          --ping         initiate convo
