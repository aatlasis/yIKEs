# yIKEs
A security assessment tool for IKEv2 implementations

(see below for examples how to use it)

WHAT YOU NEED
-------------
- Python3
- Scapy 
- (preferrably) Linux OS
It needs to run with root privileges

A. Various Parameters
---------------------
  -i <INTERFACE> 		The network interface to use.
  
  -d <IP>			The address of the target (IPv4 addresses only).
  
  -p <port>			The port of the target (default 500).
  
  -sp <port>			The source port of the packet (default 500).
  
  -stimeout <msec> 		The time to sniff when in listen mode, in seconds (default: 10). Useful when in listen  mode.
  
  -kl <KLENGTH>		  	The length of the key. Currently, for IKE_AUTH and Diffie-Helman exchange, only a 256 bits Key Length is supported; A different size key length can be used for recon mode only, or for half-init mode. 

B. Modes of Operation
---------------------
  -recon			Perform recon. Send an INIT packet and print results of the Respone.
  
  -listen 			Initiate a Listener. Listen for INIT packets, print results and respond.
  
  -half-init			Initiates a half-open init attack (potential DoS). In	this option, packets will not be auto-fragmented and	hence, they need to be smaller than the MTU size.

	NOTES:		
	1) If only -listen is used, it acts as a responder and only sends an IKE_INIT message.
      	2) If -recon and -listen are used together, it acts as an Initiator sending up to IKE_AUTH message in response to IKE_INIT from a responder.
	3) If -recon is only used, it acts as an Initiator and sends only an IKE_INIT message

C. Crafting Arbitrary IKEv2 Payload Chains
------------------------------------------
  -pr <PROPOSALS> 		      The Proposals and the included Transformations (e.g. 1.12 means Encryption(1), AES128(12). Transformations included in a Proposal are separated with a ',', whilst proposals themselves are separated with ''. This combination is included in the IKE_INIT message. Example: 1.1,2.1,3.1/1.2,2.1,3.3/1.1,2.1,3.1,2.2/3.4,4.4,4.3
	
  -pr2 <PROPOSALS>		      Same is the -pr switch, but for the IKE_AUTH message. 
	
  -ip <IKE_PAYLOADS>		    A comma-separated list of IKE identifiers Payloads for the IKE_INIT message. Example: SA refers to Security Association, KE refers to Key Exchange, etc.
  
  -ip2 <IKE_PAYLOADS>		    Same as the -ip2 switch, but for the IKE_AUTH message.
  
  -nt <NU_OF_TR>		    The number of transformations >=0 to be included in the corresponding field of the Proposals; when the default value is used, it is auto-calculated based on the rest of the input. HINT: Leave the default value (i.e. do not use the switch), unless you want to try to implement a potential over(under)flow attack.
  
  -li <LENGTH_IKE>		      The length of the ikev2 header, >=0, to be included in the corresponding field of the IKEv2 header; when the default value is used, it is auto-calculated based on the rest of the input. HINT: Leave the default value (i.e. do not use the switch), unless you want to try to implement a potential over(under)flow attack.
  
  -lp <LENGTH_PROPOSAL>	    The length of the proposals payload, >=0, to be included in the corresponding field of the Proposal payload; when the default value is used, it is auto-calculated based on the rest of the input. HINT: Leave the default value (i.e. do not use the switch), unless you want to try to implement a potential over(under)flow attack.
  
  -lt <LENGTH_TRANSFORM>	  The length of the Transformations payload, >=0, to be included in the corresponding field of the Transformations payload; when the default value is used, it is auto-calculated based on the rest of the input. HINT: Leave the default value (i.e. do not use the switch), unless you want to try to implement a potential over(under)flow attack.
  
  -sN <SIZE_NOTIFY_DATA>	  The size of Notify data (for Notify Types in [16440,16449]), >=0
  
  -crt <TYPE_CERT_REQUEST>	The Type of the Certificate Request Payload (if present); it must me combined with CERTREQ. 

D. Fragmentation
----------------
  -fr 			The number of fragments > 0 to be used for IKEv2 fragmentation (in IKE_AUTH messages).
	NOTE: IP fragmentation is auto-performed when necesssary (in all modes except from the half-init).
 
E. Perform succesful Diffie-Helman Exchange and IKE_AUTH Encryption/Decryption
------------------------------------------------------------------------------
To perform successful Diffie-Helman Exchange and IKE_AUTH Encryption/Decryption, currently only the following are supported:
	Diffie Helman Group:		        2
	Encryption Key length:		      256
	Encryption algorithm: 		      AES-CBC
	Integrity protection algorithm: SHA2-256-128
	PRF:				                    PRF_HMAC_SHA2_256

	Therefore, to test a device up to IKE_AUTH exchange, configure the testing device to use the aformentioned parmeters. 
	NOTE: 	Authentication fails on purpose (since currently the objective of the tool is to perform attacks as a non-authenticated device only).

F. How to Use it (examples)
---------------------------
Triggering Legitimate Responses
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce,Notify.16388-16389 -pr 1.12,3.12,2.5,4.2 -kl 256

Triggering Legitimate Responses with Minimum Types of Payloads
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce -pr 1.12,3.12,2.5,4.2 -kl 256

Many Transforms in a Proposal
Using ranges:
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce,Notify.16388-16389 -pr 1.1-135,3.1-40,2.1-40,4.1-40 -kl 256

NOTE: If you intend to use more than 255 transforms, you must manually define the number of transforms field such as to be ≤255 using the -nt switch (see next examples).

Number of Transforms Field = 255 and actual number of Transforms < 255
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce,Notify.16388-16389 -pr 1.12,3.12,2.5,4.2 -kl 256 -nt 255

Actual Number of Transforms = 255 and number of Transforms in the corresponding field = 1
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce,Notify.16388-16389 -pr 1.1-135,3.1-40,2.1-40,4.1-40 -kl 256 -nt 1

Out of Common Order Payloads
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip Notify.16388-16389,Nonce,KE,Notify.16388-16389,SA,Notify.16388-16389 -pr 1.12,3.12,2.5,4.2 -kl 256

Add CERTREQ Payloads
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce,Notify.16388-16389,CERTREQ -crt 6 -pr 1.12,3.12,2.5,4.2 -kl 256

Many Proposals in an SA
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce -pr 1.12,3.12,2.5,4.2`python -c 'print "/1.12,3.12,2.5,4.2" *221'`  -kl 256

Multiple Proposals in an SA and Multiple Transforms per Proposal
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce -pr 1.12-14,3.12,2.5,4.2`python -c 'print "/1.12,3.12,2.5,4.2" *221'`  -kl 256

Too Many Notify Messages
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Notify.16388-16395,Nonce,Notify.16388-16395 -pr 1.12,3.12,2.5,4.2 -kl 256

Several Notify Messages of a Big Size
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce,Notify.16388-16389,Notify.14,Notify.16430-16431,Notify.16440-16449,Notify.16404 -sN 6512 

Creating half-open IKE-INIT SAs
./yikes.py -d 192.168.56.101 -i vboxnet0 -half-init -sub 192.168.56.128/25 -ip SA,KE,Nonce -pr 1.12,3.12,2.5,4.2 -stimeout 120  -rand
==> Auto responds to COOKIES

Perform a succesful IKE_AUTH exchange as Initiator
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce -ip2 IDi,Notify.16384,IDr,AUTH,TSi,TSr -pr 1.12,3.12,2.5,4.2 -kl 256 -listen -pr2 1.12,3.12,5.0

Perform an IKEv2 fragmentation attack at IKE_AUTH exchange
./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce,Notify.16430 -ip2 IDr,Notify.16384,IDi,AUTH,TSi,TSr,Notify.16388-16389,Notify.16440  -pr 1.12,3.12,2.5,4.2 -kl 256 -listen -pr2 1.12,3.12,5.0 -fr 2

./yikes.py -d 192.168.56.101 -i vboxnet0 -recon -ip SA,KE,Nonce,Notify.16430 -ip2 IDr,Notify.16384,IDi,AUTH,TSi,TSr,Notify.16388-16389,Notify.16440  -pr 1.12,3.12,2.5,4.2 -kl 256 -listen -pr2 1.12,3.12,5.0`python -c 'print( "/1.12,3.12,2.5,4.2" *215)'` -fr 20 -sN 10000

APPENDIX
--------
IKEv2AttributeTypes = {"Encryption": (1, {"DES-IV64": 1,
                                          "DES": 2,
                                          "3DES": 3,
                                          "RC5": 4,
                                          "IDEA": 5,
                                          "CAST": 6,
                                          "Blowfish": 7,
                                          "3IDEA": 8,
                                          "DES-IV32": 9,
                                          "AES-CBC": 12,
                                          "AES-CTR": 13,
                                          "AES-CCM-8": 14,
                                          "AES-CCM-12": 15,
                                          "AES-CCM-16": 16,
                                          "AES-GCM-8ICV": 18,
                                          "AES-GCM-12ICV": 19,
                                          "AES-GCM-16ICV": 20,
                                          "Camellia-CBC": 23,
                                          "Camellia-CTR": 24,
                                          "Camellia-CCM-8ICV": 25,
                                          "Camellia-CCM-12ICV": 26,
                                          "Camellia-CCM-16ICV": 27,
                                          }, 0),
                       "PRF": (2, {"PRF_HMAC_MD5": 1,
                                   "PRF_HMAC_SHA1": 2,
                                   "PRF_HMAC_TIGER": 3,
                                   "PRF_AES128_XCBC": 4,
                                   "PRF_HMAC_SHA2_256": 5,
                                   "PRF_HMAC_SHA2_384": 6,
                                   "PRF_HMAC_SHA2_512": 7,
                                   "PRF_AES128_CMAC": 8,
                                   }, 0),
                      "Integrity": (3, {"HMAC-MD5-96": 1,
                                         "HMAC-SHA1-96": 2,
                                         "DES-MAC": 3,
                                         "KPDK-MD5": 4,
                                         "AES-XCBC-96": 5,
                                         "HMAC-MD5-128": 6,
                                         "HMAC-SHA1-160": 7,
                                         "AES-CMAC-96": 8,
                                         "AES-128-GMAC": 9,
                                         "AES-192-GMAC": 10,
                                         "AES-256-GMAC": 11,
                                         "SHA2-256-128": 12,
                                         "SHA2-384-192": 13,
                                         "SHA2-512-256": 14,
                                         }, 0),
                       "GroupDesc": (4, {"768MODPgr": 1,
                                         "1024MODPgr": 2,
                                         "1536MODPgr": 5,
                                         "2048MODPgr": 14,
                                         "3072MODPgr": 15,
                                         "4096MODPgr": 16,
                                         "6144MODPgr": 17,
                                         "8192MODPgr": 18,
                                         "256randECPgr": 19,
                                         "384randECPgr": 20,
                                         "521randECPgr": 21,
                                         "1024MODP160POSgr": 22,
                                         "2048MODP224POSgr": 23,
                                         "2048MODP256POSgr": 24,
                                         "192randECPgr": 25,
                                         "224randECPgr": 26,
                                         }, 0),
                       "Extended Sequence Number": (5, {"No ESN": 0,
                                                        "ESN": 1}, 0),
                       }


	Types of NOTIFY messages can be found at https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml

