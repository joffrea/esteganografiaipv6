# steganography using ICMPv6
Usando el protocolo ICMP se crea un canal oculto encriptado. Versión basica
## Instrucciones de uso para programa receptor
python recvricmpccipv6.py "claveprecomparti"
```
python receiver.py "PRESHARED_KEY" 
```
## Instrucciones de uso para programa enviador
python sendericmpccipv6.py "claveprecomparti" "2001::ffff" "Mensaje de inicio"
```
python sender.py "PRESHARED_KEY" "IPv6TARGET" "MESSAGE"
```
