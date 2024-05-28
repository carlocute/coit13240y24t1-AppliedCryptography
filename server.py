
import socket
import base64
from diffie_hellman import generate_dh_keypair, generate_shared_secret
from aes_encryption import encrypt, decrypt

ipAddr = '66.228.58.29' 
port   = 45678

def server():
    while True:
        try:
            # Create a socket object
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Bind the socket to the address and port
            server_socket.bind((ipAddr, port))
            
            # Listen for incoming connections
            server_socket.listen(1)
            print('Waiting for a connection...')
            
            # Accept an incoming connection
            client_socket, addr = server_socket.accept()
            print(f'Connected by {addr}')
            
            # Generate a Diffie-Hellman key pair for the server
            server_private_key, server_public_key = generate_dh_keypair()
            
            # Receive the client's public key
            client_public_key = client_socket.recv(1024)
            
            # Send the server's public key to the client
            client_socket.send(server_public_key)
            
            # Generate a shared secret using the server's private key and the client's public key
            shared_secret = generate_shared_secret(server_private_key, client_public_key)
            
            # Enter a loop to send and receive messages with the client
            while True:
                # Receive an encrypted message from the client
                encrypted_message = client_socket.recv(1024)
                
                # Decrypt the message using the shared secret
                decrypted_message = decrypt(base64.b64decode(encrypted_message), shared_secret).decode()
                
                # Print the message from the client
                print(f"Received message from client: {decrypted_message}")
                
                # Check if the client wants to exit
                if decrypted_message.lower() == "exit":
                    break
                
                # Get a response from the user
                response = input("Enter a response to send to the client: ")
                
                # Encrypt the response using the shared secret
                encrypted_response = encrypt(response.encode(), shared_secret)
                
                # Send the encrypted response to the client
                client_socket.send(base64.b64encode(encrypted_response))
            
            # Close the connection
            print("Closing connection...")
            client_socket.close()
            server_socket.close()
            print("Connection closed.")
        
        except socket.error as e:
            print(f"Error: {e}. Waiting for a new connection...")
            continue

if __name__ == "__main__":
    server()
