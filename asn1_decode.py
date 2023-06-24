#asn1_decode.py
# see https://ldap.com/ldapv3-wire--reference-asn1-ber/?amp

'''
Protocol syntax:
Element is Type, Length and Value
* NOTE: if Type is Constructed, Length is total # octets (bytes), Value is the actual sequence of elements
Parsing strategy
1) Get Type
2) Get Length
3a) If Type is constructed Indent the next Elelments - there is no Value
3b) If Type is primitive, print it's value - using primitive_decode()
4) Offset parsing. If Type is constructed, offset 1.  If TYpe is primitice, offset length of primitive.


type_decode():
bits:
76    5       43211
|     |       |
|     |       --- Tag Number
|     ----------- Primitive or Consructed
----------------- Class
Class 00 = Universal - means the same thing for all applications
Class 01 = Application - meaning depnends on applicaiton
Class 10 = Context Specific - meaning depneds on where it is used in the sequence
Class 11 = Private - Unlikely in LDAP

Primitive/Constructed 0 = Primitive (Null, Boolean, Integer, Octet String, Enumerated)
Primitive/Constructed 1 = Complex - concatenation of 0 or more BER elements

Tag Number - differeetes between different values in this element class

EXAMPLE: 
00000000  30 2d 02 01 01 60 28 02  01 03 04 1a 63 6e 3d 61  |0-...`(.....cn=a|
00000010  64 6d 69 6e 2c 64 63 3d  72 61 68 61 73 61 6b 2c  |dmin,dc=rahasak,|
00000020  64 63 3d 63 6f 6d 80 07  72 61 68 61 73 61 6b     |dc=com..rahasak|
'''
ASN1_FILE = 'my_file_old'

d_types = {
    0:'UNIVERSAL',
    1:'APPLICATION',
    2:'CONTEXT',
    3:'PRIVATE'    
}
d_prim_constructed = {
    0:'PRIMITIVE',
    1:'CONSTRUCTED'
}

d_univeral_types = {
    0x1: 'Boolean',
    0x2: 'Integer',
    0x4: 'Octet String',
    0x5: 'Null',
    0xA: 'Enumerated',
    0x30: 'Sequence',
    0x31: 'Set'
}

d_application_types = {
# partial list ...
    0x60: 'BIND REQUEST',
    0x61: 'BIND RESPONSE',
    0x42: 'UNBIND REQUEST',
    0x63: 'SEARCH REQUEST',
    0x64: 'SEARCH RESULT'
}

d_context_types = { 
    # guessing at these values
    0x80: 'PASSWORD'
}



def decode_type(data):
    # returns type, primitive/constructed, tag number
    asn_class = (data & 0xC0) >> 6
    prim_constructed = (data & 0x30 ) >> 5
    tag_number = data & (0x1f)
    return asn_class, prim_constructed, tag_number

encoded_bytes = open(ASN1_FILE, 'rb').read()
data = [int(x) for x in encoded_bytes]

def print_primitive(data, pos, u_type, asn_length):
    if u_type == 'Integer':
        for i in range(asn_length):
            print(data[pos + i], end = ' ')
    if u_type == 'Octet String':
        s = ''
        for i in range(asn_length):
            s += chr(data[pos + i])
        print(s, end = ' ')
    print()

def parse_next(data, pos):
    a,p,t = decode_type(data[pos])
    #print (hex(data[pos]),a,p,t)
    asn_length = data[pos+1]
    if data[pos] in d_univeral_types:
        u_type = d_univeral_types[data[pos]]
        #print('u_tupe is ',u_type)
        if u_type == 'Sequence':    
            print(f'Type: {u_type} - Length: {asn_length}')
            return pos + 2
        if u_type in ['Boolean','Integer','Octet String']:
            print(f'Type: {u_type} - Length: {asn_length} - Value: ', end = '')
            print_primitive(data,pos+2,u_type,asn_length)
            return pos + 2 + asn_length

    if d_types[a] == 'APPLICATION':
        u_type = d_application_types[data[pos]]
        print(f'Application Type: {u_type} - Length: {asn_length}')
        return pos + 2

    if d_types[a] == 'CONTEXT':
        u_type = d_context_types[data[pos]]
        if u_type == 'PASSWORD':
            print(f'Application Type: {u_type} - ', end = '')
            print_primitive(data,pos+2,'Octet String',asn_length)
            return pos + 2 + asn_length 
        print(f'Application Type: {u_type} - Length: {asn_length}')
        return pos + 2

    print(f'Type: {d_types[a]} - {d_prim_constructed[p]} - Tag #: {t} - length: {asn_length}')
    return pos + 2

next_pos = 0
while next_pos < len(data):    
    next_pos = parse_next(data,next_pos)

