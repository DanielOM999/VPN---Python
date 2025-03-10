# Importerer nødvendige biblioteker
import socket
import threading
import time
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def convert_size(size_bytes):
    """
    Konverterer byte-størrelse til et mer lesbart format (B, KB, MB eller GB).
    
    Parametre:
        size_bytes (int): Størrelsen i byte.
        
    Returnerer:
        str: Størrelsen formatert med passende enhet.
    """
    if size_bytes == 0:
        return "0B"
    units = ("B", "KB", "MB", "GB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    return f"{size_bytes / (1024 ** i):.2f} {units[i]}"

class SpeedTest:
    """
    Klasse for å måle overføringshastigheten for data.
    """
    def __init__(self):
        """
        Initialiserer objektet med starttid og total byte-telling.
        """
        self.start_time = None
        self.total_bytes = 0
    
    def start(self):
        """
        Starter tidsmålingen.
        """
        self.start_time = time.time()
    
    def update(self, bytes_transferred):
        """
        Oppdaterer den totale byte-tellingen.
        
        Parametre:
            bytes_transferred (int): Antall bytes som nylig ble overført.
        """
        self.total_bytes += bytes_transferred
    
    def results(self):
        """
        Beregner og returnerer gjennomsnittlig overføringshastighet.
        
        Returnerer:
            str: Hastigheten i et lesbart format (f.eks. "XX.XX MB/s").
        """
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return "N/A"
        speed = self.total_bytes / elapsed
        return f"{convert_size(speed)}/s"

# Krypteringsnøkler og initialiseringsvektor (IV)
KEY = 'Din32tegnshemmelignøkkk'.encode('utf-8')
IV = b'16tegninitialvek'

def handle_client(client_socket):
    """
    Håndterer kommunikasjonen med en tilkoblet klient.
    
    Utfører følgende:
      - Starter en speed test for å måle overføringshastigheten.
      - Mottar og dekrypterer data fra klienten.
      - Svarer klienten med kryptert melding.
    
    Parametre:
        client_socket (socket.socket): Tilsvarende socket for klienten.
    """
    speed_test = SpeedTest()
    speed_test.start()

    try:
        while True:
            # Mottar kryptert data fra klienten
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                break # Avslutt hvis ingen data mottas

            # Oppdaterer speed test med antall mottatte bytes og skriver ut gjeldende hastighet
            speed_test.update(len(encrypted_data))
            print(f"Server - Current speed: {speed_test.results()}")
            
            # Dekrypterer dataen
            cipher_dec = AES.new(KEY, AES.MODE_CBC, IV)
            decrypted_data = unpad(cipher_dec.decrypt(encrypted_data), AES.block_size)
            print(f"Mottatt: {decrypted_data.decode()}")

            # Krypterer svar og sender det tilbake til klienten
            response = pad(b"Server svar", AES.block_size)
            cipher_enc = AES.new(KEY, AES.MODE_CBC, IV)
            client_socket.send(cipher_enc.encrypt(response))
    finally:
        # Lukker tilkoblingen til klienten
        client_socket.close()

def start_server():
    """
    Setter opp serveren, lytter etter tilkoblinger og håndterer hver klient i en egen tråd.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5000))
    server.listen(5)
    print("Server startet...")
    
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_server()
