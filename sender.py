#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES
import random


def monitor_callback(pkt):
        global cadena
        if ICMPv6EchoRequest in pkt and pkt[ICMPv6EchoRequest].type == 128 and pkt[ICMPv6EchoRequest].id == 0x666 and len(pkt[ICMPv6EchoRequest].data)>0:
                cadena+= pkt[ICMPv6EchoRequest].data[4:]

def randstring(length=10):
	hex_char='0123456789abcdef'
	return ''.join((random.choice(hex_char) for i in xrange(length)))

def padding(texto=''):
        longitud=len(texto)
        resto=longitud%16
        while (16-resto):
                texto=texto+" "
                resto=resto+1
        return texto

def sendmessage(data='',msgsize=2):
	global dst_ip
	global primero
	print "Enviando..."
	first = 0
	flow_id = 0x0666
	last = (msgsize)
	count = (len(data)/msgsize)+1
	for a in range(0, count):
     		payload = "0000"+data[first:last]
     		src_ip = "2001::" + randstring(4) + ":" + randstring(4)
		if len(data[first:last])==0:
			packet = IPv6(dst=dst_ip,src=src_ip)/ICMPv6DestUnreach ()/payload
     		else:
			if primero :
				print "primer"+src_ip
        			packet = IPv6(dst=dst_ip)/ICMPv6EchoRequest(id=flow_id,seq=a)/payload
				primero = 0
			else :
				packet = IPv6(dst=dst_ip,src=src_ip)/ICMPv6EchoRequest(id=flow_id,seq=a)/payload
     		a = send(packet,verbose=0)
     		first += msgsize
     		last += msgsize
	return 1


FLAG=1
cadena = ''
msgsize = 2
aes_key = sys.argv[1]
dst_ip = sys.argv[2]
mensaje = padding(sys.argv[3])
obj=AES.new(aes_key,AES.MODE_CBC,'ivseed16bytes000')
data = obj.encrypt(mensaje)
primero=1
envio=sendmessage(data,msgsize)
primero=0
while (FLAG) :
	print "Escuchando..."
        pkts = sniff(iface="eth0", prn=monitor_callback, stop_filter = lambda x: x.haslayer(ICMPv6DestUnreach))
        obj=AES.new(aes_key,AES.MODE_CBC,'ivseed16bytes000')
        data1 = obj.decrypt(cadena)
        print "*"+data1+"*"
       	mensaje=raw_input('>')
    	if mensaje == 'quit' :
		print "Adios"
               	FLAG=0
        mensaje = padding(mensaje)
       	obj=AES.new(aes_key,AES.MODE_CBC,'ivseed16bytes000')
       	data = obj.encrypt(mensaje)
       	envio=sendmessage(data,msgsize)
	cadena=''

