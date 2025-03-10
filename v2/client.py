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

def parse_target(data):
    """
    Analyserer mottatt data for å finne mål-vert og port.
    
    Funksjonen støtter:
      - CONNECT-forespørsler: f.eks. b'CONNECT host:port ...'
      - Vanlige HTTP-forespørsler med en "Host:" header
    
    Parametre:
        data (bytes): Rå data mottatt fra klienten.
    
    Returnerer:
        tuple: (host (str), port (int)) eller (None, None) ved feil.
    """
    try:
        if data.startswith(b'CONNECT'):
            parts = data.split(b' ')[1].split(b':')
            return parts[0].decode(), int(parts[1])
        for line in data.split(b'\r\n'):
            if line.startswith(b'Host: '):
                host_part = line[6:].decode()
                if ':' in host_part:
                    host, port = host_part.split(':', 1)
                    return host, int(port)
                return host_part, 80
    except Exception as e:
        print(f"Parse error: {e}")
    return None, None

def handle_local_connection(local_conn, vpn_socket):
    """
    Håndterer tilkoblingen fra den lokale klienten.
    
    Utfører følgende:
      1. Mottar og analyserer den første forespørselen fra klienten.
      2. Krypterer målinformasjonen og sender den til VPN-serveren.
      3. Ved HTTPS (port 443) sender den en "Connection Established"-melding til klienten.
      4. Krypterer og videresender evt. ytterligere data fra klienten.
      5. Starter to tråder for toveis dataoverføring med kryptering og dekryptering.
    
    Parametre:
        local_conn (socket.socket): Socketen for lokal klient.
        vpn_socket (socket.socket): Socketen tilkoblet VPN-serveren.
    """
    try:
        # Mottar den første forespørselen fra klienten
        initial_data = local_conn.recv(4096)
        if not initial_data:
            return

        # Analyserer forespørselen for å hente mål-vert og port
        target_host, target_port = parse_target(initial_data)
        if not target_host:
            raise Exception("Could not determine target from request")

        # Krypterer målinformasjonen (f.eks. "example.com:80")
        target_info = f"{target_host}:{target_port}".encode()
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        encrypted_target = cipher.encrypt(pad(target_info, BLOCK_SIZE))
        # Sender først lengden på den krypterte meldingen (4 bytes) og deretter selve meldingen
        vpn_socket.send(len(encrypted_target).to_bytes(4, 'big'))
        vpn_socket.send(encrypted_target)

        # Ved HTTPS CONNECT sender vi en bekreftelse til klienten
        if target_port == 443:
            local_conn.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            # Krypterer og sender den opprinnelige forespørselen til VPN-serveren
            cipher = AES.new(KEY, AES.MODE_CBC, IV)
            encrypted_data = cipher.encrypt(pad(initial_data, BLOCK_SIZE))
            vpn_socket.send(len(encrypted_data).to_bytes(4, 'big'))
            vpn_socket.send(encrypted_data)

        # Starter to tråder for toveis dataoverføring:
        # - En for å kryptere data fra lokal klient til VPN-server
        # - En for å dekryptere data fra VPN-server til lokal klient
        threading.Thread(target=forward, args=(local_conn, vpn_socket, True)).start()
        threading.Thread(target=forward, args=(vpn_socket, local_conn, False)).start()

    except Exception as e:
        print(f"Connection error: {e}")
        local_conn.close()
        vpn_socket.close()

def forward(src, dst, encrypt=False):
    """
    Overfører data mellom to sockets med valgfrie krypterings-/dekrypteringsoperasjoner.
    
    Når encrypt er True:
      - Leses klartekst fra kilden, krypteres og sendes med en 4-bytes lengdeheader.
      
    Når encrypt er False:
      - Leses en 4-bytes lengdeheader, mottas nøyaktig den angitte mengden data,
        dekrypteres og sendes som klartekst.
    
    Parametre:
        src (socket.socket): Kildesocket.
        dst (socket.socket): Destinasjonssocket.
        encrypt (bool): Bestemmer om data skal krypteres (True) eller dekrypteres (False).
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

def main():
    """
    Hovedfunksjonen for den lokale proxyen.
    
    - Setter opp en signalhåndterer for CTRL+C (SIGINT).
    - Oppretter en server-socket på 127.0.0.1:8080.
    - Aksepterer tilkoblinger og starter en ny tråd for hver tilkobling til VPN-serveren.
    """
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    
    local_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_proxy.bind(('127.0.0.1', 8080))
    local_proxy.listen(5)
    print("Local proxy running on 127.0.0.1:8080 (CTRL+C to exit)...")

    try:
        while True:
            local_conn, addr = local_proxy.accept()
            try:
                vpn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                vpn_sock.connect(('10.1.120.179', 5000))
                threading.Thread(target=handle_local_connection, args=(local_conn, vpn_sock)).start()
            except ConnectionRefusedError:
                print("Server unavailable. Start server.py first.")
                local_conn.close()
    except KeyboardInterrupt:
        local_proxy.close()
        print("\nClient shutdown")

if __name__ == "__main__":
    main()
