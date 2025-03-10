# Importerer nødvendige biblioteker
import socket
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

def encrypt_message(message):
    """
    Krypterer en melding med AES i CBC-modus.
    
    Parametre:
        message (str): Meldingen som skal krypteres.
        
    Returnerer:
        bytes: Kryptert melding.
    """
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(message.encode(), AES.block_size))

def main():
    """
    Hovedfunksjonen for klienten som etablerer tilkobling til serveren og håndterer kommunikasjonen.
    
    Utfører følgende:
      - Kobler til serveren på 'localhost' og port 5000.
      - Leser inn brukerens input, krypterer meldingen og sender den.
      - Mottar kryptert svar, dekrypterer og skriver ut svaret.
      - Oppdaterer og viser overføringshastigheten kontinuerlig.
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5000))
    
    speed_test = SpeedTest()
    speed_test.start()
    
    while True:
        message = input("Melding: ")
        encrypted = encrypt_message(message)
        client.send(encrypted)
        speed_test.update(len(encrypted))
        
        # Mottar svar fra serveren
        response = client.recv(4096)
        speed_test.update(len(response))
        
        # Dekrypterer svar fra serveren
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted_response = unpad(cipher.decrypt(response), AES.block_size).decode()
        print("Svar:", decrypted_response)
        print("Client - Current speed:", speed_test.results())

if __name__ == "__main__":
    main()