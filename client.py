
import socket
import base64
from diffie_hellman import generate_dh_keypair, generate_shared_secret
from aes_encryption import encrypt, decrypt

ipAddr = '66.228.58.29' 
port   = 45678

def client():
    while True:
        try:
            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Try to connect to the server
            print("Trying to connect to the server...")
            client_socket.connect((ipAddr, port))
            print("Connected to the server!")
            
            # Generate a Diffie-Hellman key pair for the client
            client_private_key, client_public_key = generate_dh_keypair()
            
            # Send the client's public key to the server
            client_socket.send(client_public_key)
            
            # Receive the server's public key
            server_public_key = client_socket.recv(1024)
            
            # Generate a shared secret using the client's private key and the server's public key
            shared_secret = generate_shared_secret(client_private_key, server_public_key)
            
            # Enter a loop to send and receive messages with the server
            while True:
                # Get a message from the user
                message = input("Enter a message to send to the server (or 'exit' to quit): ")
                
                # Check if the user wants to exit
                if message.lower() == "exit":
                    break
                
                # Encrypt the message using the shared secret
                encrypted_message = encrypt(message.encode(), shared_secret)
                
                # Send the encrypted message to the server
                client_socket.send(base64.b64encode(encrypted_message))
                
                # Receive the response from the server
                encrypted_response = client_socket.recv(1024)
                
                # Decrypt the response using the shared secret
                decrypted_response = decrypt(base64.b64decode(encrypted_response), shared_secret).decode()
                
                # Print the response from the server
                print(f"Received response from server: {decrypted_response}")
            
            # Close the connection
            print("Closing connection...")
            client_socket.close()
            print("Connection closed.")
        
        except socket.error as e:
            print(f"Error: {e}. Reconnecting...")
            continue

if __name__ == "__main__":
    client()
