import argparse

# Read specified file in as bytes; return byte array
def read_pcapng(filename):
    print(f'[+] Opening file \'{filename}\'')
    
    capture = b''
    with open(filename, 'rb') as file:
        capture = file.read()
    
    return capture

# Iterate through a byte array and extract occurences of usb packets with urb type of interrupt in
def parse_urb_interrupts(capture):
    print('[+] Parsing packet capture and extracting data packets')
    
    # Identifies USB packets with URB type of interrupt in (contains data; length of each packet should be 72 bytes)
    URB_INTERRUPT_IN = b'\x80\xc1\x89\xaf\x28\x93\xff\xff\x43\x01'
    PACKET_LENGTH = 72
    
    # Find first occurence of an interrupt in, then iterate until no other occurences are found (find() returns -1)
    usb_packets = []
    start_index = capture.find(URB_INTERRUPT_IN)
    while start_index != -1:
        full_packet = capture[start_index : start_index + PACKET_LENGTH]    # Take everything from the USB ID bytes through the usb capdata (64 + 8 bytes)
        usb_packets.append(full_packet)
        start_index = capture.find(URB_INTERRUPT_IN, start_index + 1)       # Get next index of a URB interrupt in packet
    
    return usb_packets

# Extract data bytes from usb packets, removing any which have null data (0x0000000000000000) indicating a key was released
def extract_data(packets, endianness):
    print('[+] Extracting USB key press bytes')

    data_bytes = []
    for packet in packets:
        data = packet[63:71]                        # Data bytes start at byte number 64 (index 63) and contain 8 bytes total (index 71 would therefore be the end of data)
        int_rep = int.from_bytes(data, endianness)
        if int_rep != 0:                            # If the data is 0 when represented as an integer, then all bits are set to 0 
            data_bytes.append(data)
    
    return data_bytes

def evaluate_data_bytes(data):
    print('[+] Evaluating data bytes')
    # An ascii 'a' is represented as 97; an 'a' in the data bytes is stored as a 4 within the 4th byte.
    # Using an offset of 93, we can convert the 4th byte data by adding the integer representation
    # with the offset and then casting to a character.

    keystrokes = []
    std_offset = 93
    for keystroke in data:
        additional_offset = 0               # Will change output based of if SHIFT is held down (value of 0x02 in byte 1)
        int_rep = keystroke[0]
        if int_rep == 2:
            additional_offset = -32         # When added to the standard offset, will make letters uppercase
        offset = std_offset + additional_offset
        
        int_rep = keystroke[3]                   # 4th byte (index 3) stores keystrokes such as a-z
        character = chr(offset + int_rep)   # Cast to character based off ascii value
        keystrokes.append(character)
    
    message = ''.join(keystrokes)
    return message
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser('KeyParse: extract keystrokes from a USB pcapng file')
    parser.add_argument('file', help='PCAPNG file to read from')
    parser.add_argument('-e', '--endianness', default='little', required=False, help='Endianness to use. Defaults to little')
    args = parser.parse_args()

    capture = read_pcapng(args.file)
    usb_packets = parse_urb_interrupts(capture)
    data_bytes = extract_data(usb_packets, args.endianness)
    message = evaluate_data_bytes(data_bytes)
    print(f'[=] Extracted keystrokes will be displayed on subsequent lines\n\n{message}\n')


# id_urb_type_interrupt_in = b'\x80\xc1\x89\xaf\x28\x93\xff\xff\x43\x01'
# urb_complete_packet_length = 72

# packets = []
# packet_data = []

# with open('./initial_capture.pcapng', 'rb') as file:
#     arr = file.read()
#     start_index = arr.find(id_urb_type_interrupt_in)
#     while start_index != -1:    
#         urb_packet = arr[start_index : start_index + urb_complete_packet_length]
#         start_index = arr.find(id_urb_type_interrupt_in, start_index + 1)
#         packets.append(urb_packet)
#         packet_data.append(urb_packet[63:71])

# for capture in packet_data:
#     if capture == b'\x00\x00\x00\x00\x00\x00\x00\x00': # Keystroke was released rather than entered
#         packet_data.remove(capture)

# def convert(byte_array):
#     std_offset = 93 # difference between ascii 'a' and urb 'a' in the 4th data byte (97 vs 4)
#     letter = byte_array[3] # 4 - 29 == a - z
    
#     offset = std_offset
#     return chr(offset + letter)


# msg = ''
# for capture in packet_data:
#     msg += convert(capture)
    
# print(msg)


# Wireshark filter: !(usb.capdata == 00:00:00:00:00:00:00:00) && usb.urb_type == URB_COMPLETE && usb.transfer_type == URB_INTERRUPT

# Packets containing data have the type URB_INTERRUPT in
# These are designated by the byte sequence 0xffff9328af89c180

# Next step is to determine if data is present. This is determined by byte 16 ( 00 indicates data, 3c indicates no data)
