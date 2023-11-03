import sys
from scapy.all import *
from scapy.all import rdpcap, Ether, Raw, STP, HSRP, Dot3, LLC, STP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
from scapy.layers.l2 import SNAP, Ether
from scapy.layers.inet import IP
from scapy.layers.vrrp import VRRP
from scapy.contrib.cdp import CDPAddrRecordIPv4
from scapy.layers.vrrp import IPPROTO_VRRP, VRRP, VRRPv3
from scapy.contrib.macsec import MACsec
from colorama import Fore, Style
import requests
import pyshark

def resolve_mac_address(mac_address):
    api_key = "at_fdSVq1okmEVuCYWZR3Taix1kpUH6T"
    url = f"https://api.macaddress.io/v1?apiKey={api_key}&output=json&search={mac_address}"
    response = requests.get(url)
    if response.ok:
        data = response.json()
        return data.get("vendorDetails", {}).get("companyName")

def is_macsec_packet(packet):
    return Ether in packet and packet[Ether].type == 0x88E5

def detect_macsec(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing MACSec frames in file: " + pcap_file + "...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "[!] File not found.")
        return 0

    macsec_frames = [pkt for pkt in packets if is_macsec_packet(pkt)]

    if not macsec_frames:
        print(Fore.RED + Style.BRIGHT + "[!] Error. MACSec not detected.")
        return 0

    # first macsec frame
    macsec_frame = macsec_frames[0]

    print(Fore.GREEN + Style.BRIGHT + "[*] Info: " + Fore.YELLOW + Style.BRIGHT + "Detected MACSec")
    print(Fore.YELLOW + Style.BRIGHT + "[!] You can try to bypass MACSec")

    # analize Secure Channel Identifier (SCI)
    if MACsec in macsec_frame:
        macsec_sci_identifier = macsec_frame[MACsec].sci
        print(Fore.GREEN + Style.BRIGHT + "[*] MACSec SCI Identifier: " + Fore.YELLOW + Style.BRIGHT + str(macsec_sci_identifier))
    else:
        print(Fore.RED + Style.BRIGHT + "[!] MACSec layer not found in the frame.")

    return 0

def detect_cdp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Reading CDP packets from pcap file...")
    
    packets = rdpcap(pcap_file)
    cdp_frames = [pkt for pkt in packets if pkt.haslayer(SNAP) and pkt[SNAP].code in [0x2000, 0x2004]]

    if not cdp_frames:
        print(Fore.RED + Style.BRIGHT + "[!] Error. CDP isn't detected.")
        return

    for cdp_frame in cdp_frames:
        snapcode = cdp_frame[SNAP].code
        if snapcode == 0x2000:
            print(Fore.GREEN + Style.BRIGHT + "[*] Info: Detected CDP")
            print(Fore.GREEN + Style.BRIGHT + "[!] Impact: Information Gathering, CDP Flooding")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: Yersinia, Scapy, Wireshark")
            
            try:
                # Extracting and printing details from the CDP frame
                # Add your code here to process the CDP frame and extract information
                # ...

                # Uncomment the following lines if you know the structure of your CDP packets
                cdphostname = cdp_frame['Device ID'].val
                print(Fore.GREEN + Style.BRIGHT + "[!] System Name: " + Fore.YELLOW + Style.BRIGHT + str(cdphostname.decode()))
                # ...

            except Exception as e:
                print(Fore.RED + "Error processing CDP packet: " + str(e))

        elif snapcode == 0x2004:
            print(Fore.RED + "[!] Detected DTP. Skipping...")

        # MAC Address Resolution
        mac_from_cdp_frame = cdp_frame.src
        macinfo = resolve_mac_address(mac_from_cdp_frame)
        if macinfo:
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
        else:
            print(Fore.RED + "[!] Vendor information not found.")

def detect_nbns(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing NBNS packets in pcap file...")
    
    packets = rdpcap(pcap_file)
    nbns_packets = [pkt for pkt in packets if UDP in pkt and pkt[UDP].dport == 137]

    if not nbns_packets:
        print(Fore.RED + Style.BRIGHT + "[!] Error. NBNS isn't detected.")
        return
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected NBNS")
        print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " NBNS Spoofing, NetNTLMv2-SSP hashes intercept")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Responder, Metasploit")

        for nbns_packet in nbns_packets:
            try:
                nbns_sender_mac = nbns_packet[Ether].src
                nbns_sender_ip = nbns_packet[IP].src
                print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Sender IP: " + Fore.YELLOW + Style.BRIGHT + str(nbns_sender_ip))
                print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Sender MAC: " + Fore.YELLOW + Style.BRIGHT + str(nbns_sender_mac))
            except Exception as e:
                print(Fore.RED + "Error processing NBNS packet: " + str(e))

def detect_lldp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing LLDP packets in pcap file...")

    packets = rdpcap(pcap_file)
#    lldp_frames = [pkt for pkt in packets if pkt.haslayer(LLDP)]
    lldp_frames = [pkt for pkt in packets if Ether in pkt and pkt[Ether].type == 0x88cc]
    if not lldp_frames:
        print(Fore.RED + Style.BRIGHT + "[!] Error. LLDP isn't detected.")
        return

    print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected LLDP")

    for lldp_frame in lldp_frames:
        try:
            # Parsing LLDP content. 
            # You may need to adjust these depending on the structure of the LLDP packets in your pcap.
            if Raw in lldp_frame:
                lldp_payload = lldp_frame[Raw]
                # Adjust the following print statements based on how LLDP data is structured in your packets
                print(Fore.GREEN + Style.BRIGHT + "[*] LLDP Payload: " + Fore.YELLOW + Style.BRIGHT + str(lldp_payload))
        except Exception as e:
            print(Fore.RED + "Error processing LLDP packet: " + str(e))

        # MAC Address Resolution
        if 'args.resolve_mac' in globals() and args.resolve_mac:  # Check if args.resolve_mac is defined and true
            mac_from_lldp_frame = lldp_frame.src
            macinfo = resolve_mac_address(mac_from_lldp_frame)
            if macinfo:
                print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
            else:
                print(Fore.RED + "[!] Vendor information not found.")

def detect_dtp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing DTP packets in pcap file...")

    packets = rdpcap(pcap_file)
    dtp_frames = [pkt for pkt in packets if pkt.haslayer(SNAP) and pkt[SNAP].code == 0x2004]

    if not dtp_frames:
        print(Fore.RED + Style.BRIGHT + "[!] Error. DTP isn't detected.")
        return

    for dtp_frame in dtp_frames:
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected DTP")
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " VLAN Segmentation Bypass")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Yersinia, Scapy")
            
            # Assuming DTPNeighbor layer contains the 'neighbor' field
            # This might need to be adjusted depending on actual packet structure
            if DTPNeighbor in dtp_frame:
                dtp_neighbor = dtp_frame[DTPNeighbor].neighbor
                print(Fore.GREEN + Style.BRIGHT + "[*] DTP Neighbor MAC: " + Fore.YELLOW + Style.BRIGHT + str(dtp_neighbor))

            # MAC Address Resolution
            if 'args.resolve_mac' in globals() and args.resolve_mac:  # Check if args.resolve_mac is defined and true
                mac_from_dtp_frame = dtp_frame.src
                macinfo = resolve_mac_address(mac_from_dtp_frame)
                if macinfo:
                    print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
                else:
                    print(Fore.RED + "[!] Vendor information not found.")
        
        except Exception as e:
            print(Fore.RED + "Error processing DTP packet: " + str(e))

def detect_mndp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing MNDP packets in pcap file...")

    packets = rdpcap(pcap_file)
    mndp_frames = [pkt for pkt in packets if UDP in pkt and pkt[UDP].dport == 5678 and pkt[IP].dst == '255.255.255.255']

    if not mndp_frames:
        print(Fore.RED + Style.BRIGHT + "[!] Error. MNDP not detected.")
        return

    for mndp_frame in mndp_frames:
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected MNDP")
            # Extract information here, be cautious with direct attribute access as it might cause exceptions
            # if the attribute does not exist.
            mndp_fields = ['identity', 'board', 'platform', 'version', 'uptime']
            for field in mndp_fields:
                if hasattr(mndp_frame, field):
                    print(Fore.GREEN + Style.BRIGHT + f"[*] {field.title()}: " + Fore.YELLOW + Style.BRIGHT + str(getattr(mndp_frame, field)))

            # Additional checks for IP and MAC, assuming these are not always present in mndp_frame
            mndpipv4addr = mndp_frame[IP].src if IP in mndp_frame else "N/A"
            mndpmac = mndp_frame[Ether].src if Ether in mndp_frame else "N/A"

            print(Fore.GREEN + Style.BRIGHT + "[*] Device IP Address: " + Fore.YELLOW + Style.BRIGHT + mndpipv4addr)
            print(Fore.GREEN + Style.BRIGHT + "[*] Device MAC Address: " + Fore.YELLOW + Style.BRIGHT + mndpmac)

            # Resolve MAC Address
            if 'args.resolve_mac' in globals() and args.resolve_mac:
                macinfo = resolve_mac_address(mndpmac)
                if macinfo:
                    print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
                else:
                    print(Fore.RED + "[!] Vendor information not found.")
        except Exception as e:
            print(Fore.RED + "Error processing MNDP packet: " + str(e))

def detect_edp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing EDP packets in pcap file...")

    packets = rdpcap(pcap_file)
    edp_packets = [pkt for pkt in packets if Ether in pkt and pkt[Ether].src.startswith("00:e0:2b:00:00:00")]

    if not edp_packets:
        print(Fore.RED + Style.BRIGHT + "[!] Error. EDP not detected.")
        return
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected EDP")

        # Only for the first EDP package
        edp_packet = edp_packets[0]
        if hasattr(edp_packet, 'edp'):
            if edp_packet.edp.version:
                print(Fore.GREEN + Style.BRIGHT + "[*] EDP Version: " + Fore.YELLOW + Style.BRIGHT + str(edp_packet.edp.version))
            if edp_packet.edp.midmac:
                print(Fore.GREEN + Style.BRIGHT + "[*] MAC: " + Fore.YELLOW + Style.BRIGHT + str(edp_packet.edp.midmac))
            if edp_packet.edp.info_slot:
                print(Fore.GREEN + Style.BRIGHT + "[*] Slot Number: " + Fore.YELLOW + Style.BRIGHT + str(edp_packet.edp.info_slot))
            if edp_packet.edp.info_port:
                print(Fore.GREEN + Style.BRIGHT + "[*] Port Number: " + Fore.YELLOW + Style.BRIGHT + str(edp_packet.edp.info_port))
            if edp_packet.edp.display_string:
                print(Fore.GREEN + Style.BRIGHT + "[*] Device System Name: " + Fore.YELLOW + Style.BRIGHT + str(edp_packet.edp.display_string))
        if args.resolve_mac:
            macinfo = resolve_mac_address(edp_packet[Ether].src)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)

def detect_esrp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing ESRP packets in pcap file...")

    packets = rdpcap(pcap_file)
    esrp_packets = [pkt for pkt in packets if Ether in pkt and pkt[Ether].src.startswith("00:e0:2b:00:00:02")]

    if not esrp_packets:
        print(Fore.RED + Style.BRIGHT + "[!] Error. ESRP not detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected ESRP")

        states = []
        prios = []

        for i in range(min(5, len(esrp_packets))):
            esrp_packet = esrp_packets[i]
            if hasattr(esrp_packet, 'edp') and hasattr(esrp_packet.edp, 'esrp_state'):
                state = int(esrp_packet.edp.esrp_state)
                states.append(state)
                print(Fore.GREEN + Style.BRIGHT + f"[*] ESRP State for packet {i+1}: " + Fore.YELLOW + Style.BRIGHT + str(state))
            if hasattr(esrp_packet, 'edp') and hasattr(esrp_packet.edp, 'esrp_prio'):
                prio = int(esrp_packet.edp.esrp_prio)
                prios.append(prio)
                print(Fore.GREEN + Style.BRIGHT + f"[*] ESRP Priority for packet {i+1}: " + Fore.YELLOW + Style.BRIGHT + str(prio))
            if i == 0 and hasattr(esrp_packet.edp, 'esrp_virtip'):
                esrpvirtualip = esrp_packet.edp.esrp_virtip
                print(Fore.GREEN + Style.BRIGHT + "[*] ESRP Virtual IP Address: " + Fore.YELLOW + Style.BRIGHT + esrpvirtualip)
        
        # Проверка состояний и приоритетов ESRP
        if any(state == 1 for state in states) and all(prio < 255 for prio in prios):
            print(Fore.YELLOW + Style.BRIGHT + "[*] Detected vulnerable ESRP Configuration. Vector for ESRP Hijacking Attack.")
            print(Fore.YELLOW + Style.BRIGHT + "[!] There are currently no tools to attack ESRP. Use this message as a network security alert.")
        else:
            print(Fore.RED + Style.BRIGHT + "ESRP is not vulnerable")

        # Если нужно разрешить MAC адрес
        # Тут нужна дополнительная функция resolve_mac_address
        if args.resolve_mac:
            macinfo = resolve_mac_address(esrp_packets[0][Ether].src)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)

def detect_pvst(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing PVST packets in pcap file...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + "File not found. Please check the file path.")
        return

    pvst_frames = [pkt for pkt in packets if pkt.haslayer(STP) and "01:00:0c:cc:cc:cd" in pkt[Ether].dst]

    if not pvst_frames:
        print(Fore.RED + Style.BRIGHT + "[!] Error. PVST not detected.")
        return

    print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected PVST")

# Process only the first PVST packet for simplicity, can be adapted to process all packets    pvst_frame = pvst_frames[0]
    try:
        pvstvlan = pvst_frame[STP].vlan
        pvstrootpriority = pvst_frame[STP].root_prio
        pvstrootpathcost = pvst_frame[STP].root_cost
        print(Fore.GREEN + Style.BRIGHT + "VLAN ID: ", Fore.YELLOW + Style.BRIGHT + str(pvstvlan))
        print(Fore.GREEN + Style.BRIGHT + "PVST Root Priority: ", Fore.YELLOW + Style.BRIGHT + str(pvstrootpriority))
        print(Fore.GREEN + Style.BRIGHT + "PVST Root Path Cost: " + Fore.YELLOW + Style.BRIGHT + str(pvstrootpathcost))

    except Exception as e:
        print(Fore.RED + "Error processing PVST packet: " + str(e))


def detect_glbp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing GLBP packets in pcap file...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + "File not found. Please check the file path.")
        return

    glbp_frames = [pkt for pkt in packets if pkt.haslayer(IP) and pkt.haslayer(UDP) and
                   pkt[IP].dst == "224.0.0.102" and pkt[UDP].dport == 3222]

    if len(glbp_frames) == 0:
        print(Fore.RED + Style.BRIGHT + "[!] Error. GLBP not detected.")
        return

    print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected GLBP")
    for i in range(min(5, len(glbp_frames))):
        glbp_frame = glbp_frames[i]
        # Обязательно проверьте, соответствует ли структура пакетов GLBP вашим файлам pcap
        glbp_state = int(glbp_frame.glbp.hello_vgstate)
        glbp_priority = int(glbp_frame.glbp.hello_priority)
        glbp_group_number = int(glbp_frame.glbp.group)
        glbp_virtual_ip = glbp_frame.glbp.hello_virtualipv4

        print(Fore.GREEN + Style.BRIGHT + f"[*] GLBP Frame {i+1} - State: {glbp_state}, Priority: {glbp_priority}, Group: {glbp_group_number}, Virtual IP: {glbp_virtual_ip}")

        # GLBP State and GLBP Priority Checking...
        if glbp_state == 32 and glbp_priority < 255:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Detected vulnerable GLBP AVG/AVF priority values")
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " MITM, DoS, Blackhole")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Loki")
            print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Group Number: " + Fore.YELLOW + Style.BRIGHT + str(
                glbp_group_number))
            print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Virtual IP Address: " + Fore.YELLOW + Style.BRIGHT + str(
                glbp_virtual_ip))
        else:
            print(Fore.RED + Style.BRIGHT + "GLBP is not vulnerable")
            # GLBP Authentication checking
            if hasattr(glbp_frame, 'glbp'):
                field_names = glbp_frame.glbp._all_fields
                if 'glbp.auth.authtype' in field_names:
                    print(Fore.RED + Style.BRIGHT + "[!] GLBP Authentication detected. There is not yet a tool that works with GLBP authentication. An attack is not possible at this time")
                    glbpauthtype = int(glbp_frame.glbp.auth_authtype)
                    # GLBP MD5 Auth checking
                    if glbpauthtype == 2:
                        print(glbpauthtype)
                        print(Fore.RED + Style.BRIGHT + "GLBP MD5 Authentication detected")
                    # GLBP Plaintext
                    if glbpauthtype == 1:
                        print(Fore.RED + Style.BRIGHT + "GLBP Plaintext Authentication detected")
                        plainpass = glbp_frame.glbp.auth_plainpass
                        print(Fore.RED + Style.BRIGHT + plainpass)

def detect_hsrp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing HSRP packets in pcap file...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + "File not found. Please check the file path.")
        return

    hsrp_frames = [pkt for pkt in packets if pkt.haslayer(HSRP)]

    if len(hsrp_frames) == 0:
        print(Fore.RED + Style.BRIGHT + "[!] Error. HSRP not detected.")
        return

    print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected HSRP")
    for i in range(min(5, len(hsrp_frames))):
        hsrp_frame = hsrp_frames[i]
        hsrp_state = hsrp_frame[HSRP].state
        hsrp_priority = hsrp_frame[HSRP].priority
        hsrp_group_number = hsrp_frame[HSRP].group
        hsrp_virt_ip = hsrp_frame[HSRP].virtualIP

        print(Fore.GREEN + Style.BRIGHT + f"[*] HSRP Frame {i+1} - State: {hsrp_state}, Priority: {hsrp_priority}, Group: {hsrp_group_number}, Virtual IP: {hsrp_virt_ip}")

        # HSRP State and Priority Checking
        if hsrp_state == 16 and hsrp_priority < 255:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Detected vulnerable HSRP priority values")
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " MITM, Dos, Blackhole")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Loki")
        else:
            print(Fore.RED + Style.BRIGHT + "HSRP is not vulnerable")

        # Simple HSRP Authentication Checking
        if hsrp_frame[HSRP].auth:
            auth_data = hsrp_frame[HSRP].auth
            if auth_data.startswith(b'cisco\x00\x00\x00'):
                simplehsrppass = auth_data.decode("UTF-8").strip("\x00")
                print(Fore.WHITE + Style.BRIGHT + "[!] Simple HSRP Authentication is used.")
                print(Fore.WHITE + Style.BRIGHT + "[!] HSRP Plaintext Password: " + Fore.BLUE + Style.BRIGHT + simplehsrppass)

        # HSRP MD5 Authentication Checking
        if hsrp_frame.haslayer(HSRPmd5):
            print(Fore.YELLOW + Style.BRIGHT + "[!] HSRP MD5 Authentication is used. You can bruteforce it.")
            print(Fore.YELLOW + Style.BRIGHT + "[!] Tools for bruteforce: hsrp2john.py, John the Ripper")

# Hex to string (For OSPF plaintext password)
def hex_to_string(hex):
    if hex[:2] == '0x':
        hex = hex[2:]
    string_value = bytes.fromhex(hex).decode('utf-8')
    return string_value

def detect_ospf(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing OSPF packets in pcap file...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + "File not found. Please check the file path.")
        return

    ospf_packets = [pkt for pkt in packets if IP in pkt and pkt[IP].dst == "224.0.0.5" and pkt.haslayer(OSPF_Hdr)]

    if not ospf_packets:
        print(Fore.RED + Style.BRIGHT + "[!] Error. OSPF isn't detected.")
        return
    else:
        ospf_packet = ospf_packets[0]
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected OSPF")
        areaID = ospf_packet[OSPF_Hdr].area
        authtype = ospf_packet[OSPF_Hdr].authtype
        ospfkeyid = ospf_packet[OSPF_Hdr].keyid
        authdatalength = ospf_packet[OSPF_Hdr].authdatalen
        authseq = ospf_packet[OSPF_Hdr].seq
        hellosource = ospf_packet[IP].src
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF area ID: " + Fore.YELLOW + Style.BRIGHT + str(areaID))
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor: " + Fore.YELLOW + Style.BRIGHT + str(hellosource))
        
        # Handling Authentication Types
        if authtype == 0:
            print(Fore.GREEN + Style.BRIGHT + "[!] OSPF Authentication isn't used.")
        elif authtype == 1:
            print(Fore.GREEN + Style.BRIGHT + "[!] Simple OSPF Authentication is used.")
            ospf_auth_data = ospf_packet[OSPF_Hdr].authdata
            # Assuming authdata is in a readable format; may need conversion depending on implementation
            print(Fore.GREEN + Style.BRIGHT + "[!] Plaintext Password: " + Fore.YELLOW + Style.BRIGHT + ospf_auth_data)
        elif authtype == 2:
            print(Fore.GREEN + Style.BRIGHT + "[!] MD5 Auth is detected. Bruteforce it.")
            print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Key ID: " + Fore.YELLOW + Style.BRIGHT + str(ospfkeyid))
            print(Fore.GREEN + Style.BRIGHT + "[*] Crypt data length: " + Fore.YELLOW + Style.BRIGHT + str(authdatalength))
            print(Fore.GREEN + Style.BRIGHT + "[*] Crypt Auth Sequence Number: " + Fore.YELLOW + Style.BRIGHT + str(authseq))
        # Additional analysis can be added here as per requirements

def detect_eigrp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing EIGRP packets in pcap file...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + "File not found. Please check the file path.")
        return

    eigrp_packets = [pkt for pkt in packets if IP in pkt and pkt[IP].dst == "224.0.0.10" and pkt.haslayer(EIGRP)]

    if not eigrp_packets:
        print(Fore.RED + Style.BRIGHT + "[!] Error. EIGRP isn't detected.")
        return
    else:
        eigrp_packet = eigrp_packets[0]
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected EIGRP")
        asnumber = eigrp_packet[EIGRP].asn
        eigrpneighborip = eigrp_packet[IP].src
        print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP AS Number: " + Fore.YELLOW + Style.BRIGHT + str(asnumber))
        print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor: " + Fore.YELLOW + Style.BRIGHT + str(eigrpneighborip))
        
        # Check for EIGRP Authentication Data
        if eigrp_packet.haslayer(EIGRPAuthData):
            print(Fore.RED + Style.BRIGHT + "[!] There is EIGRP Authentication")
            if eigrp_packet[EIGRPAuthData].authtype == 2:
                print(Fore.RED + Style.BRIGHT + "[!] There is EIGRP MD5 Authentication. You can crack this with eigrp2john.py")
                eigrpauthkeyid = eigrp_packet[EIGRPAuthData].keyid
                print(Fore.WHITE + Style.BRIGHT + "[*] EIGRP Authentication Key ID: " + Fore.YELLOW + Style.BRIGHT + str(eigrpauthkeyid))
            else:
                print("There's no EIGRP Auth")

def detect_vrrp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing VRRP packets from '" + pcap_file + "'...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "[!] File not found.")
        return 0

    found_vrrp = False

    for packet in packets:
        if VRRP in packet:
            found_vrrp = True
            print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected VRRP")

            vrrppriority = packet[VRRP].priority
            vrrpauthtype = packet[VRRP].authtype
            ipsrcpacket = packet[IP].src
            vrrpmacsender = packet[Ether].src
            vrrp_group_id = packet[VRRP].vrid
            vrrp_virt_ip = packet[VRRP].addrlist

            if vrrppriority <= 255:
                print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + 
                      " Detected vulnerable VRRP Value. Even the priority of 255 does not save.")
                print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " MITM, DoS, Blackhole")
                print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Scapy, Loki")
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Group Number (VRID): " + Fore.YELLOW + Style.BRIGHT + str(vrrp_group_id))
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Virtual IP Address: " + Fore.YELLOW + Style.BRIGHT + ', '.join(vrrp_virt_ip))

            if vrrpauthtype == 0:
                print(Fore.YELLOW + Style.BRIGHT + "[!] VRRP Authentication is not used")
            elif vrrpauthtype == 1:
                print(Fore.YELLOW + Style.BRIGHT + "[*] Plaintext VRRP Authentication is used")
                vrrp_plaintext_string = packet[VRRP].auth_data.decode()
                print(Fore.YELLOW + Style.BRIGHT + "[!] VRRP Plaintext Key: " + vrrp_plaintext_string)
            elif vrrpauthtype == 2:
                print(Fore.YELLOW + Style.BRIGHT + "[!] VRRP MD5 Auth is used")

            print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Sender IP: " + Fore.YELLOW + Style.BRIGHT + ipsrcpacket)
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Sender MAC: " + Fore.YELLOW + Style.BRIGHT + vrrpmacsender)

    if not found_vrrp:
        print(Fore.RED + Style.BRIGHT + "[!] No VRRP packets found in the file.")

    return 0

def detect_stp(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing STP frames in file: " + pcap_file + "...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "[!] File not found.")
        return 0

    found_stp = False

    for packet in packets:
        if packet.haslayer(STP):
            found_stp = True
            print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected STP")
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " Partial MITM, DoS")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Yersinia, Grit by Caster")

            stp_vlan_id = packet[STP].bridge_id
            stp_root_prio = packet[STP].root_id
            stp_root_cost = packet[STP].root_path_cost

            print(Fore.GREEN + Style.BRIGHT + "[*] VLAN ID: " + Fore.YELLOW + Style.BRIGHT + str(stp_vlan_id))
            print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Priority: " + Fore.YELLOW + Style.BRIGHT + str(stp_root_prio))
            print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Path Cost: " + Fore.YELLOW + Style.BRIGHT + str(stp_root_cost))

    if not found_stp:
        print(Fore.RED + Style.BRIGHT + "[!] No STP frames found in the file.")
    
    return 0

def detect_llmnr(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing LLMNR frames in file: " + pcap_file + "...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "[!] File not found.")
        return 0

    found_llmnr = False

    for packet in packets:
        if packet.haslayer(IP) and packet[IP].dst == "224.0.0.252":
            found_llmnr = True
            print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected LLMNR")
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " LLMNR Spoofing, NetNTLMv2-SSP hashes intercept")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Inveigh, Responder, Metasploit")

            llmnr_sender_mac = packet[Ether].src
            llmnr_sender_ip = packet[IP].src

            print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Sender IP: " + Fore.YELLOW + Style.BRIGHT + str(llmnr_sender_ip))
            print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Sender MAC: " + Fore.YELLOW + Style.BRIGHT + str(llmnr_sender_mac))
            break  # Assuming we only need the first detected LLMNR packet

    if not found_llmnr:
        print(Fore.RED + Style.BRIGHT + "[!] No LLMNR packets found in the file.")
    
    return 0

def detect_mdns_pyshark(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing MDNS packets from " + pcap_file + "...")
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="mdns")

        found = False
        for pkt in capture:
            found = True
            print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Packet Found")
            try:
                print("\t[*] Full Packet Details:\n" + str(pkt))
            except Exception as e:
                print("\t[!] Error printing packet details: " + str(e))
            
            try:
                mdns_query_name = pkt.mdns.qry_name
                print(Fore.GREEN + Style.BRIGHT + "\t[*] Captured MDNS Query Name: " + Fore.YELLOW + Style.BRIGHT + str(mdns_query_name))
            except AttributeError:
                print(Fore.YELLOW + Style.BRIGHT + "\t[!] MDNS Query Name Unavailable")
            
            try:
                mdns_sender_mac = pkt.eth.src
                mdns_sender_address = pkt.ip.src
                print(Fore.GREEN + Style.BRIGHT + "\t[*] MDNS Sender MAC: " + Fore.YELLOW + Style.BRIGHT + str(mdns_sender_mac))
                print(Fore.GREEN + Style.BRIGHT + "\t[*] MDNS Sender IP Address: " + Fore.YELLOW + Style.BRIGHT + str(mdns_sender_address))
            except AttributeError:
                print(Fore.YELLOW + Style.BRIGHT + "\t[!] MDNS Sender Information Not Available")

        if not found:
            print(Fore.RED + Style.BRIGHT + "[!] No MDNS packets detected.")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[!] An error occurred: {e}")

def detect_mdns(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing MDNS frames in file: " + pcap_file + "...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "[!] File not found.")
        return 0

    found_mdns = False

    for packet in packets:
        if packet.haslayer(IP) and packet[IP].dst == "224.0.0.251":
            found_mdns = True
            print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected MDNS")

            # Extract MDNS details
            # Note: Ensure your PCAP file has the necessary MDNS details or adapt these lines accordingly.
            mdns_qry_name = "Query Name Unavailable"  # Placeholder, since Scapy does not parse MDNS fields by default like pyshark
            mdns_sender_mac = packet[Ether].src
            mdns_sender_address = packet[IP].src

            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " MDNS Spoofing, NetNTLMv2-SSP hashes intercept")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Responder")
            print(Fore.GREEN + Style.BRIGHT + "[*] Captured MDNS Query Name: " + Fore.YELLOW + Style.BRIGHT + mdns_qry_name)
            print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Sender MAC: " + Fore.YELLOW + Style.BRIGHT + mdns_sender_mac)
            print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Sender IP Address: " + Fore.YELLOW + Style.BRIGHT + mdns_sender_address)
            break  # Assuming we only need the first detected MDNS packet

    if not found_mdns:
        print(Fore.RED + Style.BRIGHT + "[!] No MDNS packets found in the file.")
    
    return 0

def dhcpv6_sniff(pkt):
    dhcpv6_dst_addr = "ff02::1:2"
    if IPv6 in pkt and pkt[IPv6].dst == dhcpv6_dst_addr:
        return True
    return False

def detect_dhcpv6(pcap_file):
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Analyzing DHCPv6 frames in file: " + pcap_file + "...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "[!] File not found.")
        return 0

    dhcpv6_packets = [pkt for pkt in packets if dhcpv6_sniff(pkt)]

    if not dhcpv6_packets:
        print(Fore.RED + Style.BRIGHT + "[!] Error. DHCPv6 isn't detected.")
        return 0

    # first dhcpv6 packet
    dhcpv6_packet = dhcpv6_packets[0]

    print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected DHCPv6")
    print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " DNS Spoofing over IPv4 network")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " mitm6")

    dhcpv6_mac_address_sender = dhcpv6_packet[Ether].src
    dhcpv6_packet_sender = dhcpv6_packet[IPv6].src

    print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Request Sender IP: " + Fore.YELLOW + Style.BRIGHT + dhcpv6_packet_sender)
    print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Request Sender MAC: " + Fore.YELLOW + Style.BRIGHT + dhcpv6_mac_address_sender)

    return 0


def main():
    if len(sys.argv) > 1:
        print("opening " + sys.argv[1])
        pcap_file = sys.argv[1]
    else:
        print("trying open test1.pcap")
        pcap_file = "test1.pcap"

#    pcap_file = "test1.pcap"  # Specify your pcap file name or path here
    #detect_mdns_pyshark(pcap_file)
    detect_mdns(pcap_file)
    detect_macsec(pcap_file)
    detect_cdp(pcap_file)
    detect_nbns(pcap_file)
    detect_lldp(pcap_file)
    detect_dtp(pcap_file)
    detect_mndp(pcap_file)
    detect_edp(pcap_file)
    detect_esrp(pcap_file)
    detect_pvst(pcap_file)
    detect_glbp(pcap_file)
    detect_hsrp(pcap_file)
    detect_ospf(pcap_file)
    detect_eigrp(pcap_file)
    detect_vrrp(pcap_file)
    detect_stp(pcap_file)
    detect_llmnr(pcap_file)
    detect_dhcpv6(pcap_file)
if __name__ == "__main__":
    main()
