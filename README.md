# Above_offline
Offline modification of https://github.com/wearecaster/Above
and a copy of Pcredz

Модифицированная Оффлайн версия утилиты от caster (above) - Позволяет проанализировать tcpdump pcap файл, и посмотеть его в режиме offline.
Modified Offline version of the utility from caster (above) - Allows you to analyze the tcpdump pcap file and view it offline.

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

python3 offline_above.py analize.pcap```


```python3 pcreds.py -f test1.pcap -v```
