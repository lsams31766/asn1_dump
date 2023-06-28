from decode_asn1 import decode

ASN1_FILE = 'capture.bin'
encoded_bytes = open(ASN1_FILE, 'rb').read()
decode(encoded_bytes)