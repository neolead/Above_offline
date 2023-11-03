# Above_offline

## Description
This is an offline modification of the utility [Above](https://github.com/wearecaster/Above), which allows for the analysis of tcpdump pcap files in an offline mode. It is also capable of extracting sensitive data such as login credentials from pcap files, similar to the functionality provided by Pcredz and net_creds.

## Features
- **Offline Analysis**: Analyze tcpdump pcap files without the need for an active internet connection.
- **Data Extraction**: Extract sensitive information such as usernames and passwords from pcap files.

## Example Files
- **1.zip**: Contains concatenated pcap files with different types of packets for testing.
- **1.pcap.log**: Contains a test report in the example folder.

## Beta for Multithreading
Execute in the background:
\```bash
python3 above_offline_multythread.py analize.pcap > analize.pcap.log&
\```

Read the log in the background:
\```bash
tail -f analize.pcap.log
\```

Read the log after execution:
\```bash
nano analize.pcap.log
\```

## Prerequisites
For Python 3:
\```bash
pip3 install -r requirements.txt
apt-get install libpcap-dev
pip3 install Cython
pip3 install python-libpcap
\```

## Usage
**Executing**:

For example traffic can be sniffed for 10 minutes at interface eth0 with command:

```timeout 600 tcpdump -s0 --immediate-mode -w 1.pcap -S -i eth0 port not 22```

By default, the file for analysis is `test1.pcap`.

Tool can take a long time to execute with large pcap files. The pcap can be split using the following command (where `-C 10` will split into ~10MB chunks):
\```bash
tcpdump -r old_file -w new_files -C 10
\```

To analyze a pcap file:
\```bash
python3 above_offline.py analize.pcap
\```

Using pcreds to extract information:
\```bash
python3 pcreds.py -f test1.pcap -v
\```

Using net_creds to extract information:
\```bash
python2 net_creds.py --pcap test1.pcap -v
\```

Running with multithreading:
\```bash
python3 above_offline_multythread.py analize.pcap > analize.pcap.log
\```

## Data Sniffing
Thoroughly sniff passwords and hashes from an interface or pcap file, concatenating fragmented packets without relying on ports for service identification.

### Sniffs
- URLs visited.
- POST loads sent.
- HTTP form logins/passwords.
- HTTP basic auth logins/passwords.
- HTTP searches.
- FTP logins/passwords.
- IRC logins/passwords.
- POP logins/passwords.
- IMAP logins/passwords.
- Telnet logins/passwords.
- SMTP logins/passwords.
- SNMP community strings.
- NTLMv1/v2 across all supported protocols like HTTP, SMB, LDAP, etc.
- Kerberos credentials.
