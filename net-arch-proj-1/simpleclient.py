# CS4254 - Project 1

import re
import socket
from argparse import ArgumentParser

# Parse arguments provided
def argparse(): 
    parser = ArgumentParser(prog='simpleclient.py',
                            description='Simple TCP Client for Project 1')
    
    # Define arguments
    parser.add_argument('-p', '--port', type=int, default=27993)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('hostname', type=str)
    parser.add_argument('username', type=str)
    
    return parser.parse_args()

# Get message type
def msg_type(msg):
    
    pass    

# Take a status message and process the equation
def process_status_msg(msg, verbose=False):
    if verbose:
        print('Processing STATUS message...')

    status_regex = r'^cs4254fall2026 STATUS ' + \
                   r'([0-9]|[1-9][0-9]|[1-9][0-9][0-9]|1000) ' + \
                   r'(\+|\-|\/|\*) ' + \
                   r'([0-9]|[1-9][0-9]|[1-9][0-9][0-9]|1000)\n$'

    match = re.findall(status_regex, msg)

    num1_str, op, num2_str = match[0]
    num1 = int(num1_str)
    num2 = int(num2_str)

    val = 0
    if op == '+':
        val = num1 + num2
    
    elif op == '-':
        val = num1 - num2

    elif op == '*':
        val = num1 * num2

    elif op == '/':
        val = num1 // num2

    else:
        raise ValueError("Status message contains invalid operand!")

    if verbose:
        print(f"{num1} {op} {num2} = {val}")

    return val

# Main function
def main():
    args = argparse()

    # create socket
    if args.verbose:
        print(f"Creating socket at {args.hostname}:{args.port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.hostname, args.port))
    
    # Send HELLO
    sock.sendall(f'cs4254fall2026 HELLO {args.username}\n'.encode())
    reader = sock.makefile('r', encoding='utf-8')
    while True:
        resp = reader.readline()
        if not resp:
            print("Server closed the connection.")
            break
        if 'BYE' in resp.split():
            break
        val = process_status_msg(resp, args.verbose)
        sock.sendall(f'cs4254fall2026 {val}\n'.encode())
    print(f"Server responded: {repr(resp)}")
    



if __name__ == "__main__":
    main();


