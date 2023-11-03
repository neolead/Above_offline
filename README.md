# Above_offline
1) Offline modification of https://github.com/wearecaster/Above
2) Copy of Pcredz extraction sensitive data from pcap(logins passwds)
3) Copy of net_creds extraction sensitive data from pcap(logins passwds)



* Модифицированная Оффлайн версия утилиты от caster (above) - Позволяет проанализировать tcpdump pcap файл, и посмотеть его в режиме offline.

* Modified Offline version of the utility from caster (above) - Allows you to analyze the tcpdump pcap file and view it offline.

* In file 1.zip in example folder test file with pcap files concatinated in one with different type of a packets for test
* In file 1.pcap.log in example folder test report

## BETA for multy threading
```
For executing in background: python 3 above_offline_multythread.py analize.pcap > analize.pcap.log&
For reading log in background: tail -f analize.pcap.log
For just a read log after: nano analize.pcap.log
```

For python3 

Prerequests
```
pip3 install -r requrements.txt
apt-get install libpcap-dev
pip3 install Cython
pip3 install python-libpcap
```

Tool created to offline analize pcap files.
```Executing:
By default file for analize : test1.pcap

Tool can take long time for executing with large pcap files.. so pcap can be splitted with command below.. 
``` -C 10 will split ~10mb ```

```tcpdump -r old_file -w new_files -C 10```


```python3 above_offline.py analize.pcap```


```python3 pcreds.py -f test1.pcap -v```


#Net_creds
Additionally tool net_creds with analizing pcap

Running:

```python2 net_creds.py  --pcap test1.pcap -v ```

Thoroughly sniff passwords and hashes from an interface or pcap file. 
Concatenates fragmented packets and does not rely on ports for service 
identification. 

###Sniffs

* URLs visited * POST loads sent * HTTP form logins/passwords * HTTP basic auth logins/passwords
* HTTP searches * FTP logins/passwords * IRC logins/passwords * POP logins/passwords
* IMAP logins/passwords * Telnet logins/passwords * SMTP logins/passwords
* SNMP community string * NTLMv1/v2 all supported protocols like HTTP, SMB, LDAP, etc * Kerberos

