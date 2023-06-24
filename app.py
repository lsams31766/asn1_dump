#virtual env setup:
# python3 -m venv venv
# source venv/bin/activate

import asn1

encoded_bytes = open('my_file_old', 'rb').read()
decoder = asn1.Decoder()
decoder.start(encoded_bytes)
while True:
    try:
        tag, value = decoder.read()
        print(tag,value)
    except:
        pass
