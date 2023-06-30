from decode_asn1 import decode

# -q: Only show Application Commands, integers, booleans and strings
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-q", "--quiet", action="store_true")

args = parser.parse_args()
print(f'quiet_output is {args.quiet}')

ASN1_FILE = 'capture.bin'
encoded_bytes = open(ASN1_FILE, 'rb').read()
decode(encoded_bytes, args)