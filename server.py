import socket
import sys
import threading


def init_socket(ip_version, ip, port):
    if ip_version:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket for IPv4
    else:
        server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)  # TCP socket for IPv6

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    
    print(f"Server running on {ip}:{port}")
    return server_socket


def handle_request(req):
    headers = req.split('\n')
    if 'HTTP/1.1' not in headers[0]:
        return 'HTTP/1.1 500 Internal Server Error\n\nHTTP/1.1 Required'

    if 'GET' in headers[0]:
        return 'HTTP/1.1 200 OK\n\nHello, world!'
    elif 'POST' in headers[0]:
        return 'HTTP/1.1 200 OK\n\nPOST request received.'
    elif 'UPDATE' in headers[0]:
        return 'HTTP/1.1 200 OK\n\nUPDATE request received.'
    else:
        return 'HTTP/1.1 400 Bad Request\n\nUnsupported request method.'


def client_handler(client_socket, client_address):
    print(f"Connection established from {client_address}")
    
    try:
        req = client_socket.recv(1024).decode()
        if req:
            response = handle_request(req)
            client_socket.sendall(response.encode())
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()


def main():
    ip_v4_or_v6 = True  # True = IPv4, False = IPv6
    ip_address = "127.0.0.1"
    port = 8080

    if len(sys.argv) > 1 and sys.argv[1] == 'edit':
        ip_v4_or_v6 = input('IPV4? (Y/N) ') == 'Y'
        ip_address = input('IP Address (0.0.0.0 or 127.0.0.1) ')
        port = int(input('Port '))

    server_socket = init_socket(ip_v4_or_v6, ip_address, port)

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            thread = threading.Thread(target=client_handler, args=(client_socket, client_address), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
