import argparse, re

config = { # Values correlating 
    'CAPS_LOCK': 57,
    'BACKSPACE': 42,
    'CTRL': 1,
    'SHIFT': 2,
    'ALPHABETICS': range(4, 30),
    'NUMERICS': {
        30: { 'Shift': '!', 'Regular': '1' },
        31: { 'Shift': '@', 'Regular': '2' },
        32: { 'Shift': '#', 'Regular': '3' },
        33: { 'Shift': '$', 'Regular': '4' },
        34: { 'Shift': '%', 'Regular': '5' },
        35: { 'Shift': '^', 'Regular': '6' },
        36: { 'Shift': '&', 'Regular': '7' },
        37: { 'Shift': '*', 'Regular': '8' },
        38: { 'Shift': '(', 'Regular': '9' },
        39: { 'Shift': ')', 'Regular': '0' },   
    },
    'MISC_KEY_MAPPINGS': {
        40: { 'Shift': '\n', 'Regular': '\n' }, # Enter
        43: { 'Shift': '\t', 'Regular': '\t' }, # Tab
        44: { 'Shift': ' ', 'Regular': ' ' },   # Space
        45: { 'Shift': '_', 'Regular': '-' }, 
        46: { 'Shift': '+', 'Regular': '=' },
        47: { 'Shift': '{', 'Regular': '[' },
        48: { 'Shift': '}', 'Regular': ']' },
        49: { 'Shift': '|', 'Regular': '\\' },

        51: { 'Shift': ':', 'Regular': ';' },
        52: { 'Shift': '"', 'Regular': '\'' },
        53: { 'Shift': '~', 'Regular': '`' },
        54: { 'Shift': '<', 'Regular': ',' },
        55: { 'Shift': '>', 'Regular': '.' },
        56: { 'Shift': '?', 'Regular': '/' },
    },
    'Whitespace': {

    }
}

# Read specified file in as bytes; return byte array
def read_pcapng(filename):
    print(f'[+] Opening file \'{filename}\'')
    
    capture = b''
    with open(filename, 'rb') as file:
        capture = file.read()
    
    return capture

# Iterate through a byte array and extract occurences of usb packets with urb type of interrupt in
def parse_urb_interrupts(capture, urb_id):
    print('[+] Parsing packet capture and extracting data packets')
    # Byte value designators for the associated URB header fields
    URB_COMPLETE = b'\x43'
    URB_INTERRUPT = b'\x01'
    
    # Identifies the beginning of relecant packets (urb type complete, event type interrupt, and related urb device id)
    relevant_packet = urb_id + URB_COMPLETE + URB_INTERRUPT
    PACKET_LENGTH = 72
    
    # Find first occurence of an interrupt in, then iterate until no other occurences are found (find() returns -1)
    usb_packets = []
    start_index = capture.find(relevant_packet)
    while start_index != -1:
        full_packet = capture[start_index : start_index + PACKET_LENGTH]    # Take everything from the USB ID bytes through the usb capdata (64 + 8 bytes)
        usb_packets.append(full_packet)
        start_index = capture.find(relevant_packet, start_index + 1)       # Get next index of a URB interrupt in packet
    
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

# An ascii 'a' is represented as 97; an 'a' in the data bytes is stored as a 4 within the 4th byte.
# Using an offset of 93, we can convert the 4th byte data by adding the integer representation
# with the offset and then casting to a character.
def evaluate_data_bytes(data):
    print('[+] Evaluating data bytes')


    keystrokes = []
    caps = False # outside of loop because this is toggled for capitalization
    for keystroke in data:
        shift = False   # Held
        character = ''
        additional_offset = 0  # Determines capitalization

        # Modifiers: Shift, Control, CAPS, backspace
        if keystroke[3] == config['CAPS_LOCK']:              # Caps lock toggled
            caps = not caps
            continue
        if keystroke[3] == config['BACKSPACE']:              # Backspace typed - remove last element in the keystrokes list
            del keystrokes[-1]
            continue
        
        if keystroke[1] == config['CTRL']:               # Ctrl held down
            character = 'C^'
        elif (keystroke[1] == config['SHIFT']):           # Shift held down
            shift = True

        # Must verify shift not held while caps toggled (32 is the difference between ascii 'a' and 'A')
        if (caps and shift) or (not (caps or shift)):
            additional_offset = 0
        elif caps or shift:
            additional_offset = -32
        
        # key entered is a-z
        if keystroke[3] in config['ALPHABETICS']:
            std_offset = 93 # difference between ascii 'a' and usb 'a'
            offset = std_offset + additional_offset
            character = character + chr(offset + keystroke[3])   # Cast to character based off ascii value
            keystrokes.append(character)
        
        # key entered is 0-9. In this case, it is easier to map the shift values directly
        elif keystroke[3] in config['NUMERICS'].keys():
            version = 'Shift' if shift else 'Regular'
            symbol = config['NUMERICS'][keystroke[3]][version]
            keystrokes.append(symbol)
        
        # Key matches the miscellaneous mapped keystrokes defined at the top of the file
        elif keystroke[3] in config['MISC_KEY_MAPPINGS'].keys():
            version = 'Shift' if shift else 'Regular'
            symbol = config['MISC_KEY_MAPPINGS'][keystroke[3]][version]
            keystrokes.append(symbol)

    message = ''.join(keystrokes)
    return message


if __name__ == '__main__':
    parser = argparse.ArgumentParser('KeyParse: extract keystrokes from a USB pcapng file')
    parser.add_argument('file', help='PCAPNG file to read from')
    parser.add_argument('-e', '--endianness', default='little', required=False, help='Endianness to use. Defaults to little')
    parser.add_argument('--urb-id', default=None, required=False, help='URB ID of the relevant device. E.g., 0x0123456789abcdef')
    args = parser.parse_args()

    if not args.urb_id:
        args.urb_id = input('Enter URB device Id (e.g., 0x007fa5ac6697ffff): ')
    
    if re.match('^0x[0-9a-fA-F]{16,16}$', args.urb_id): # string must begin with 0x and then contain 16 hex-valid characters
        args.urb_id = bytes.fromhex(args.urb_id[2:])
    else:
        print('[!] Invalid URB ID format')
        exit()

    if not (args.endianness == 'little' or args.endianness == 'big'):
        print('[!] Invalid endianness! Should be \'little\' or \'big\'')
        exit()
    

    capture = read_pcapng(args.file)
    usb_packets = parse_urb_interrupts(capture, args.urb_id)
    data_bytes = extract_data(usb_packets, args.endianness)
    message = evaluate_data_bytes(data_bytes)
    print(f'[=] Extracted keystrokes will be displayed on subsequent lines\n{message}')


# Wireshark filter: !(usb.capdata == 00:00:00:00:00:00:00:00) && usb.urb_type == URB_COMPLETE && usb.transfer_type == URB_INTERRUPT
# Packets containing data have the type URB_INTERRUPT in
# These are designated by the byte sequence 0xffff9328af89c180
