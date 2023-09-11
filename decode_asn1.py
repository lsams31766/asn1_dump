#asn1_decode.py
# see https://ldap.com/ldapv3-wire--reference-asn1-ber/?amp

'''
Command line options
None - verbose output to terminal
-q: Only show Application Commands, integers, booleans and strings


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
#ASN1_FILE = 'my_file'
from _ast import If
quiet_output = False
prev_cmd = 'MISSING'

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
    0x60: 'BIND REQUEST',
    0x61: 'BIND RESPONSE',
    0x42: 'UNBIND REQUEST',
    0x63: 'SEARCH REQUEST',
    0x64: 'SEARCH RESULT',
    0x65: 'SEARCH_RESULT_DONE_PROTOCOL',
    0x66: 'MODIFY_REQUEST_PROTOCOL',
    0x67: 'MODIFY_RESPONSE_PROTOCOL',
    0x68: 'ADD_REQUEST_PROTOCOL',
    0x69: 'ADD_RESPONSE_PROTOCOL',
    0x4a: 'DELETE_REQUEST_PROTOCOL',
    0x6b: 'DELETE_RESPONSE_PROTOCOL',
    0x6c: 'MODIFY_DN_REQUEST_PROTOCOL',
    0x6d: 'MODIFY_DN_RESPONSE_PROTOCOL',
    0x6e: 'COMPARE_REQUEST_PROTOCOL',
    0x6f: 'COMPARE_RESPONSE_PROTOCOL',
    0x50: 'ABANDON_REQUEST_PROTOCOL',
    0x73: 'SEARCH_RESULT_REFERENCE_PROTOCOL',
    0x77: 'EXTENDED_REQUEST_PROTOCOL',
    0x78: 'EXTENDED_RESPONSE_PROTOCOL',
    0x79: 'INTERMEDIATE_RESPONSE_PROTOCOL',
    0x6A: 'UNKNOWN_APP_TYPE_0X6A',
    0X43: 'UKNOWN_APP_TYPE_0X43',
    0X75: 'UKNOWN_APP_TYPE_0X75',
    0X53: 'UKNOWN_APP_TYPE_0X53',
}


d_context_types = { 
    # guessing at these values
    0x80: 'PASSWORD',
    0x87: "UNKNOWN_CONTEXT_0X87",
    0xA3: 'SEARCH_CRITERIA'
}

d_response_codes = {
    0x0: 'SUCCESS'
}

d_search_req_1_codes = {
  0: 'SCOPE_BASE_OBJECT',
  1: 'SCOPE_ONE_LEVEL',
  2: 'SCOPE_SUBTREE',
}

d_search_req_2_codes = {
  0: 'NEVER_DEREF_ALIASES',
  1: 'DEREF_IN_SEARCHING',
  2: 'DEREF_BASE_OBJECT',
  3: 'DEREF_ALWAYS',
}

d_search_req_3_codes = {
  0xa0: 'FILTER_AND',
  0xa1: 'FILTER_OR',
  0xa2: 'FILTER_NOT',
  0xa3: 'FILTER_EQUALITY',
  0xa4: 'FILTER_SUBSTRINGS',
  0xa5: 'FILTER_GE',
  0xa6: 'FILTER_LE',
  0xa7: 'FILTER_PRESENT',
  0xa8: 'FILTER_APPROX',
  0xa9: 'FILTER_EXT'
}


def decode_type(data):
    # returns type, primitive/constructed, tag number
    asn_class = (data & 0xC0) >> 6
    prim_constructed = (data & 0x30 ) >> 5
    tag_number = data & (0x1f)
    return asn_class, prim_constructed, tag_number

def u_type_to_int(u_type):
    #d_univeral_types
    for k,v in d_univeral_types.items():
        if v == u_type:
            return k 
    return 0

old_buffer = [] # inter packet saving of data
old_type = 0
old_length = 0
def print_primitive(data, pos, u_type, asn_length, new_line=True):
    # ISSUE - if packet ends before printing all chars, we have chars left over in next packt
    # need some way to stick old pack to new packet - save old_buffer concept?
    global old_buffer, old_type, old_length
    if pos + asn_length > len(data):
        old_buffer = data[pos:]
        old_type = u_type_to_int(u_type)
        old_length = asn_length
        return

    try:
        if asn_length == 0:
            return
        if u_type == 'Integer':
            for i in range(asn_length):
                print(data[pos + i], end = ' ')
        if u_type == 'Octet String':
            s = ''
            for i in range(asn_length):
                s += chr(data[pos + i])
            print(s, end = ' ')
        if u_type == 'Boolean':
            for i in range(asn_length):
                print(data[pos + i], end = ' ')
        if new_line:
            print()
    except:
        print('-->BAD data for print_primitive')
        print('u_type',u_type,'asn_length',asn_length)
        #data, pos, u_type, asn_length
        last = pos + asn_length
        while (pos < last) and (pos < len(data)): 
            print(hex(data[pos]),end = ' ')
            pos += 1
        print()
    
def get_asn1_length(data,pos):
    # if bit 8 of data[pos] == 0, simpole 1 byte length
    # if bit 8 of data[bos] == 1, multi bye length
    #    next byte is number of length bytes,  
    #    next n bytes are total length
    if data[pos] >> 7 == 0: # simple length
        return data[pos],1
    nbr_bytes = data[pos] - 0x80
    length_list = data[pos + 1:pos + nbr_bytes + 1]
    total = 0
    mult = 1
    for x in length_list[::-1]:
        total += mult * x
        mult = mult * 256
    # return asn_length and number of bytes this length took up
    return total + 1,nbr_bytes + 1 # need to add the nbr_of_length_bytes byte

def get_enumated_value(data, pos):
    global prev_cmd
    value = 'UNKNOWN'
    if prev_cmd == 'BIND RESPONSE':
        value = d_response_codes.get(data[pos],'UNKNOWN')
        return value
    if prev_cmd == 'SEARCH REQUEST':
        value = d_search_req_1_codes.get(data[pos],'UNKNOWN') 
        prev_cmd = 'SR1' # indicate get next enum
        return value
    if prev_cmd == 'SR1':
        value = d_search_req_2_codes.get(data[pos],'UNKNOWN') 
        prev_cmd = 'SR2' # indicate get next enum
        return value
    if prev_cmd == 'SR2':
        value = d_search_req_3_codes.get(data[pos],'UNKNOWN') 
        prev_cmd = 'SR3' # indicate get next enum
        return value
    if prev_cmd =='SEARCH_RESULT_DONE_PROTOCOL':
        value = d_response_codes.get(data[pos],'UNKNOWN')
    return value

def print_search_criteria(data, pos, asn_length):
    print('SEARCH_CRITERIA: ',end='')
    processed = 0
    end = pos + asn_length
    first = pos 
    while pos < end:
        #print(hex(data[pos]), end=' ')
        u_type = d_univeral_types[data[first]]
        u_length = data[pos + 1]
        pos += 2
        print_primitive(data, pos, u_type, u_length, new_line=False)
        pos += u_length
    print('')

def parse_next(data, pos):
    global prev_cmd
    a,p,t = decode_type(data[pos])
    #print (hex(data[pos]),a,p,t)
    try:
        asn_length, asn_nbr_bytes = get_asn1_length(data,pos+1)
    except:
        print('END OF FILE')
        exit(0)
    if data[pos] in d_univeral_types:
        u_type = d_univeral_types[data[pos]]
        # print('u_type is ',u_type)
        if u_type == 'Sequence':    
            if not quiet_output:
                print(f'Type: {u_type} - Length: {asn_length}')
            return pos + 1 + asn_nbr_bytes
        if u_type == 'Set':
            if not quiet_output:
                print(f'Type: {u_type} - Length: {asn_length}')
            return pos + 1 + asn_nbr_bytes
        if u_type in ['Boolean','Integer','Octet String']:
            if not quiet_output:
                print(f'Type: {u_type} - Length: {asn_length} - Value: ', end = '')
            else:
                if asn_length > 0:
                    if u_type != 'Octet String':
                        print(f'   {u_type}: ',end='')
                    else:
                        print('   ',end='')
            print_primitive(data,pos+2,u_type,asn_length)
            return pos + 1 + asn_nbr_bytes + asn_length
        if u_type == 'Enumerated':
            value = get_enumated_value(data, pos+2)
            if not quiet_output:
                print(f'Type: {u_type} Value: {value}')
            else:
                print(f'   {u_type}: {value}')
            return pos + 1 + asn_nbr_bytes + asn_length

    if d_types[a] == 'APPLICATION':
        u_type = d_application_types.get(data[pos],'MISSING')
        prev_cmd = u_type
        if u_type == 'MISSING':
            print('MISSING APP TYPE',hex(data[pos]))
            return pos + 1 + asn_nbr_bytes
        print(f'Application Type: {u_type}', end=' ')
        if quiet_output:
            print()
        else:
            print(f'- Length: {asn_length}')
        return pos + 1 + asn_nbr_bytes
    
    if d_types[a] == 'CONTEXT':
        u_type = d_context_types.get(data[pos],'MISSING')
        if u_type == 'MISSING':
            print('MISSING context type',data[pos])
            # just parse as if known
            return pos + 2
            # print('LEN',data[pos+1])
            # # print the data
            # for i in range(asn_length):
            #     print(hex(data[pos + 2 + i]),end=' ')
            # print()
            # return pos + 2 + asn_length
        if u_type == 'SEARCH_CRITERIA':
            print_search_criteria(data, pos+2, asn_length)
            return pos + 2 + asn_length
        if u_type == 'PASSWORD':
            if not quiet_output:
                print(f'Application Type: {u_type} - ', end = '')
            else:
                print('   PASSWORD',end = ' ')
            print_primitive(data,pos+2,'Octet String',asn_length)
            return pos + 2 + asn_length 
        print(f'Application Type: {u_type}', end = ' ')
        if quiet_output:
            print()
        else: 
            print('- Length: {asn_length}')
        return pos + 2 + asn_length
    
    if d_types[a] == 'PRIVATE':
        value_list = data[pos + 2:pos+2+asn_length]
        print(f'Type: {d_types[a]} Length: {asn_length} value: {value_list}')
        return pos + 2 + asn_length

    print(f'Type: {d_types[a]} - {d_prim_constructed[p]} - Tag #: {t} - length: {asn_length}')
    return pos + 2


# Input data is bytearray form the socket
def decode(encoded_bytes, args):
    count = 0
    next_pos = 0
    global quiet_output, old_buffer
    quiet_output = args.quiet
    if True:
    #try:
        data = [int(x) for x in encoded_bytes]
        # for TS print first 3 byte
        #print('NEW BYTES',hex(data[0]),hex(data[1]),hex(data[2]))
        if len(old_buffer) > 0:
            # prepend old_buffer before new buffer
            #print('----> APPEND OLD BUFFER <-----')
            #print('old_buffer',old_buffer)
            #print('old_type',old_type,'old_length',old_length)
            temp = [old_type, old_length]
            temp.extend(old_buffer)
            #print('NEW TEMP',temp)
            #print('append temp',len(temp),' to data',len(data))
            temp.extend(data)
            data = temp
            #print('--> new data',data) 
            #print('now NEW BYTES',hex(data[0]),hex(data[1]),hex(data[2]),hex(data[3]))
            old_buffer = []
            #print('----- APPEND DONE <-----')
        next_pos = 0
        while next_pos < len(data):    
            if not quiet_output:
                print(f'{count}: addr:{hex(next_pos)} ',end='')
            #if count == 44:
                #print('check this')
            next_pos = parse_next(data,next_pos)
            count += 1
    #except:
    #    print('Bad asn1 encoded_bytes')
    #    print(f'Total commands: {count}')
        #exit(1) # keep going anyway
    print('DONE')
    print(f'Total commands: {count}')
        
