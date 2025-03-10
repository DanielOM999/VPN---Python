# Importerer nødvendige biblioteker
import socket
import threading
import signal
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Krypteringsnøkkel, initialiseringsvektor og blokkstørrelse for AES
KEY = 'Din32tegnshemmelignøkkk'.encode('utf-8')
IV = b'16tegninitialvek'
BLOCK_SIZE = AES.block_size

def handle_client(client_sock):
    """
    Håndterer en innkommende tilkobling fra en VPN-klient.
    
    Utfører følgende:
      1. Leser og dekrypterer målinformasjonen (vert og port).
      2. Etablerer en tilkobling til målserveren.
      3. Starter to tråder for toveis dataoverføring:
         - Fra VPN-klient til målserver (dekryptering).
         - Fra målserver til VPN-klient (kryptering).
    
    Parametre:
        client_sock (socket.socket): Socketen for den innkommende VPN-klienten.
    """
    try:
        # Mottar lengde og deretter kryptert målinformasjon
        target_len = int.from_bytes(client_sock.recv(4), 'big')
        encrypted_target = client_sock.recv(target_len)
        
        # Dekrypterer målinformasjonen (f.eks. "example.com:80")
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        target_info = unpad(cipher.decrypt(encrypted_target), BLOCK_SIZE).decode()
        target_host, target_port = target_info.split(':', 1)
        target_port = int(target_port)

        # Kobler til målserveren
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            target_sock.connect((target_host, target_port))
            print(f"Connected to {target_host}:{target_port}")
        except Exception as e:
            print(f"Connection failed: {e}")
            client_sock.close()
            return

        # Starter to tråder for toveis dataoverføring:
        # - Data fra klienten til målserveren skal dekrypteres.
        # - Data fra målserveren til klienten skal krypteres.
        threading.Thread(target=forward, args=(client_sock, target_sock, False)).start()
        threading.Thread(target=forward, args=(target_sock, client_sock, True)).start()

    except Exception as e:
        print(f"Server error: {e}")
        client_sock.close()

def forward(src, dst, encrypt=False):
    """
    Overfører data mellom to sockets med valgfrie krypterings-/dekrypteringsoperasjoner.
    
    Parametre:
        src (socket.socket): Kildesocket.
        dst (socket.socket): Destinasjonssocket.
        encrypt (bool): Hvis True, krypterer data før sending; hvis False, dekrypterer mottatt data.
    """
    try:
        if encrypt:
            # Krypteringsgren: leser klartekst, krypterer og sender med lengdeheader.
            while True:
                data = src.recv(4096)
                if not data:
                    break
                cipher = AES.new(KEY, AES.MODE_CBC, IV)
                encrypted = cipher.encrypt(pad(data, BLOCK_SIZE))
                dst.send(len(encrypted).to_bytes(4, 'big'))
                dst.send(encrypted)
        else:
            # Dekrypteringsgren: leser lengdeheader, mottar nøyaktig angitt antall bytes og dekrypterer.
            while True:
                header = src.recv(4)
                if not header:
                    break
                length = int.from_bytes(header, 'big')
                encrypted_data = b''
                while len(encrypted_data) < length:
                    chunk = src.recv(min(length - len(encrypted_data), 4096))
                    if not chunk:
                        break
                    encrypted_data += chunk
                if len(encrypted_data) < length:
                    break
                cipher = AES.new(KEY, AES.MODE_CBC, IV)
                decrypted = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)
                dst.send(decrypted)
    except Exception as e:
        print("Forward error:", e)
    finally:
        src.close()
        dst.close()

def start_server():
    """
    Hovedfunksjonen for VPN-serveren.
    
    - Setter opp en signalhåndterer for CTRL+C (SIGINT).
    - Oppretter en server-socket på port 5000 som aksepterer innkommende VPN-klienttilkoblinger.
    - For hver tilkobling startes en ny tråd som håndterer klienten.
    """
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 5000))
    server.listen(5)
    print("VPN Server running on port 5000 (CTRL+C to exit)...")

    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client,)).start()
    except KeyboardInterrupt:
        server.close()
        print("\nServer shutdown")

if __name__ == "__main__":
    start_server()
