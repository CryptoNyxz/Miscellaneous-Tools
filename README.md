# Miscellaneous Tools
 A collection of miscellaneous tools made in Python 3

## File Transfer
Tools that are used for transferring files to a remote system

#### Flyter
Flyter is used to transfer files between two machines on the same network.
A directory structure is generated where the received files are stored.

An example on how to use Flyter in a terminal to send and receive files

###### Receiver
```
flyter.py recv -i 123.123.123.123 -p 12345
```
In this example, the receiver will listen in on the host address `123.123.123.123:12345`
###### Sender
```
flyter.py send -i 123.123.123.123 -p 12345 -f sample.txt
```
This will start sending the file `sample.txt` to the receiver's host address at `123.123.123.123:12345`

The same result can also be achieved in Python

###### Receiver
```python
import flyter
flyter.receive('123.123.123.123', 12345)
```

###### Sender
```python
import flyter
flyter.send('123.123.123.123', 12345, 'sample.txt')
```

By importing `flyter.py` as a module, Flyter can be integrated into various Python scripts


## Port Scanning
Tools that are used for scanning open ports on a system

#### Priem Scan
Priem Scan is used to scan open TCP ports.
A port is considered open when an SYN-ACK handshake is completed

An example on how to use Priem Scan in a terminal to scan open ports on localhost

```
pscan.py -H localhost
```
This will start scanning open TCP ports on localhost in a linear scan order

The same result can also be achieved in Python

```python
import pscan
pscan.port_scan('localhost', pretty_print=True)
```
The `pretty_print` parameter is set to display the open TCP ports in a more readable format

By importing `pscan.py` as a module, Priem Scan can be integrated into various Python scripts
