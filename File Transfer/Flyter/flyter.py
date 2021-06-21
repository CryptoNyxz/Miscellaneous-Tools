"""
Flyter

Tool for transferring files on the same network using raw sockets.
Doesn't use encryption.
"""


__version__ = (0, 0, 0)
__author__ = "CryptoNyxz"
__license__ = """
MIT License

Copyright (c) 2021 Jaymund Cyrus F. Floranza

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


from argparse import ArgumentParser
from base64 import b64encode
from datetime import timedelta
from math import log
from os import altsep, sep, \
    mkdir, stat, unlink
from os.path import dirname, exists, join
from random import randint
from secrets import token_bytes
from shutil import get_terminal_size
from socket import \
    socket, error, timeout, \
    ntohs, ntohl, htons, htonl, \
    gethostname, \
    AF_INET, SOCK_STREAM
from threading import Thread
from time import time
from warnings import warn
from sys import argv, exit, version_info


if version_info < (3, 6):
    warn('[!] Some features are not be compatible with the version of your '
         'python interpreter')


FROMTERMINAL = False


# Utility Functions


def random_port(host):
    """Return a random available TCP port."""
    while True:
        port = randint(10_000, 65536)
        with socket(AF_INET, SOCK_STREAM) as sock:
            try:
                sock.bind((host, port))
            except error:
                continue
            else:
                return port


def printerror(errormsg):
    """Print an error message."""
    global FROMTERMINAL
    if FROMTERMINAL:
        print(f'\n[x] {errormsg}')
        exit(-1)
        exit(-1)
        exit(-1)
        exit(-1)
    else:
        warn(errormsg)


def printalert(alert):
    """Print an alert message."""
    global FROMTERMINAL
    print(f'[!] {alert}')


def int_to_bytes_s(integer):
    """Convert 16 - bit integer to bytes for packing."""
    res = ntohs(integer)
    res = hex(res)[2:]
    res = '0'*(len(res) % 2) + res
    return bytes.fromhex(res)


def bytes_to_int_s(byteseq):
    """Convert byte sequence to 16 - but integer for unpacking."""
    res = bytes.hex(byteseq)
    res = int(res, 16)
    return htons(res)


def int_to_bytes_l(integer):
    """Convert 32 - but integer to bytes for packing."""
    res = ntohl(integer)
    res = hex(res)[2:]
    res = '0'*(len(res) % 2) + res
    return bytes.fromhex(res)


def bytes_to_int_l(byteseq):
    """Convert byte sequence to 32 - but integer for unpacking."""
    res = bytes.hex(byteseq)
    res = int(res, 16)
    return htonl(res)


def pack_str(string):
    """Pack a string into a byte sequence."""
    return string.encode()


def unpack_str(byteseq):
    """Unpack a byte sequence into a string."""
    return byteseq.decode()


# Utility Classes


class ProgressBar:
    """
    For displaying progress bars.

    Parameters
    ----------
    max_value : int, float
        The upper limit of the progress bar.
    length : :obj:`int`, optional
        The length of the progress bar.
    """

    @staticmethod
    def byte_rescale(data, precision=1):
        scale = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

        p = int(log(data, 2)/10) if data else 0

        r_bytes = round(data/pow(2, 10*p), precision)

        return f"{r_bytes}{scale[p]}"

    def __init__(self, max_value, length=50):
        self.max_value = max_value
        self.current_val = 0

        self.length = length

        self.rate = None
        self.start_time = None
        self.start_value = None

        self.stopped = False

    @property
    def done(self):
        """Return if already finished."""
        return self.current_val >= self.max_value or self.stopped

    def start(self):
        """Start the progress bar."""
        self.stopped = False
        self.start_time = time()
        self.start_value = self.current_val

    def stop(self):
        """Stop the progress bar."""
        self.stopped = True

    def add_progress(self, value):
        """
        Count new progress.

        Parameter
        ---------
        value : int, float
            Added progress value.
        """
        if self.stopped:
            return
        self.current_val += value

    def display(self):
        """Display the current progress."""
        if self.stopped:
            return
        d_value = self.current_val - self.start_value
        d_max_value = self.max_value - self.start_value
        d_time = time() - self.start_time

        per = d_value/d_max_value

        prog = int(self.length*per)
        extra = self.length*round(per) > prog

        prog_bar = '█'*prog + '▌'*extra
        spaces = ' '*(self.length - (prog + extra))

        rate = d_value/d_time if d_time else float('inf')

        eta_s = round((d_max_value - d_value)/rate) if rate else \
            None
        eta = timedelta(seconds=eta_s) if eta_s is not None else '?'

        clear_line = " "*(get_terminal_size().columns - 1)

        print(f"{clear_line}\r"
              "Progress: "
              f"|{prog_bar}{spaces}| "
              f"{100*per:.1f}% "
              f"({ProgressBar.byte_rescale(d_value)}) "
              f"[{ProgressBar.byte_rescale(rate)}/s] "
              f"ETA: {eta}", end="\r")


# Flyter Classes


class FlyterSender:
    """
    Handles Flyter file sending processes.

    Note: Sends to FlyterReceiver instances.

    Parameterss
    ----------
    recver_ip : str
        The IP address of the receiver.
    main_port : int
        The main TCP port of the receiver.
    """

    DEFAULT_PACKET_SIZE = 1024

    def __init__(self, recver_ip, main_port):
        self.recver_ip = recver_ip
        self.main_port = main_port
        self.token = token_bytes(6)

        self._recver_hostname = None
        self._recver_token = None
        self._transfer_type = None
        self._worker_ports = None

        self._packet_size = FlyterSender.DEFAULT_PACKET_SIZE
        self._sending_file = False
        self._workers_active = 0

        self._progress_bar = None

        try:
            self.socket = socket(AF_INET, SOCK_STREAM)
            self.socket.settimeout(60)
        except:
            printerror('Error initializing sockets')
        self.param_set = False

    def __del__(self):
        if isinstance(self.socket, socket):
            self.socket.close()

    def _send_s(self, filepath, file_size):
        """
        Send a file with a single worker.

        Parameters
        ----------
        filepath : str
            The filepath to the file to be sent.
        """
        if not self.param_set:
            return printerror("Not yet set with receiver's parameters")
        if not exists(filepath):
            return printerror("File doesn't exist")

        self._sending_file = True
        try:
            fs = file_size
            with open(filepath, 'br') as f:
                while self._sending_file and fs:
                    packet = f.read(self._packet_size)
                    if not packet:
                        break

                    self.socket.send(packet)
                    assert self.socket.recv(1) == b'\x06'  # ACK

                    self._progress_bar.add_progress(len(packet))
                    fs -= len(packet)
        except AssertionError:
            self._progress_bar.stop()
            return printerror("Receiver rejected packet")
        except FileNotFoundError:
            self._progress_bar.stop()
            return printerror("Couldn't access file")
        except PermissionError:
            self._progress_bar.stop()
            return printerror("Couldn't access file due to permission error")
        except timeout:
            self._progress_bar.stop()
            return printerror("Operation timed out")
        except:
            self._progress_bar.stop()
            return printerror(f"Error while sending file")
        else:
            self._sending_file = False
            return True

    def _send_m(self, filepath, file_sizes):
        """
        Send a file with multiple workers.

        Speeds up transmission rate by using multiple workers.

        Parameters
        ----------
        filepath : str
            The filepath to the file to be sent.
        file_sizes : list(int)
            The sizes of the split-up file to be sent.
        """
        if not self.param_set:
            return printerror("Not yet set with receiver's parameters")
        if not exists(filepath):
            printerror("File doesn't exist")

        def threadfunc(worker_num, fpath, start, end):
            self._workers_active += 1

            try:
                with socket(AF_INET, SOCK_STREAM) as sock:
                    sock.connect(
                        (self.recver_ip, self._worker_ports[worker_num])
                    )

                    sock.send(self.token)
                    assert sock.recv(1) == b'\x06'  # ACK

                    fs = end - start

                    with open(fpath, 'br') as f:
                        f.seek(start)
                        while self._sending_file and fs:
                            end_size = f.tell() + self._packet_size
                            size = (self._packet_size - max(0, end_size - end))
                            packet = f.read(size)
                            if not packet:
                                break

                            sock.send(packet)
                            assert sock.recv(1) == b'\x06'  # ACK

                            self._progress_bar.add_progress(len(packet))
                            fs -= len(packet)
            except KeyboardInterrupt:
                self._progress_bar.stop()
                self._sending_file = False
                return printerror("User aborted operation")
            except AssertionError:
                self._progress_bar.stop()
                self._sending_file = False
                return printerror(f"Receiver rejected packet")
            except FileNotFoundError:
                self._progress_bar.stop()
                self._sending_file = False
                return printerror("Couldn't access file")
            except PermissionError:
                self._progress_bar.stop()
                self._sending_file = False
                return printerror("Couldn't access file due to permission "
                                  "error")
            except timeout:
                self._progress_bar.stop()
                self._sending_file = False
                return printerror("Operation timed out")
            except:
                self._progress_bar.stop()
                self._sending_file = False
                return printerror(f"Error while sending file")
            finally:
                self._workers_active -= 1

        num_workers = len(self._worker_ports)

        self._sending_file = True
        try:
            size = 0
            for w in range(num_workers):
                Thread(
                    target=threadfunc,
                    args=(
                        w, filepath,
                        size, size + file_sizes[w]
                    ),
                ).start()
                size += file_sizes[w]
        except FileNotFoundError:
            return printerror("Couldn't access file")
        except PermissionError:
            return printerror("Couldn't access file due to permission error")
        except:
            return printerror("Error while starting to send file")

        while self._workers_active:
            try:
                pass
            except KeyboardInterrupt:
                self._progress_bar.stop()
                self._sending_file = False
                return printerror("User aborted operation")

        self._sending_file = False

        return True

    def send_file(self, filepath):
        """
        Send a file.

        Parameters
        ----------
        filepath : str
            The filepath of the file to be sent.
        """
        if not self.param_set:
            return printerror("Not yet set with receiver's parameters")
        if not exists(filepath):
            return printerror("File doesn't exist")

        # Headers
        try:
            tok = self.token

            num_w = max(1, len(self._worker_ports))

            fpath = filepath.replace(altsep, sep)
            fname = fpath.split(sep)[-1]
            fsize = stat(fpath).st_size
            fsizes = [fsize//num_w for w in range(num_w)]
            fsizes[-1] += fsize - sum(fsizes)

            fn = pack_str(fname)
            len_fn = int_to_bytes_s(len(fn))

            fs = [int_to_bytes_l(s) for s in fsizes]
            fs = b''.join(fs)
            len_fs = int_to_bytes_s(num_w)

            headers = b''.join([tok, len_fn, fn, len_fs, fs])
        except:
            return printerror("Error while preparing headers")

        try:
            b64_tok = b64encode(self._recver_token).decode()
            printalert(f"Sending to {self._recver_hostname}-{b64_tok}:"
                       f" [ {fname} ]")
            self.socket.send(headers)

            print("Waiting for receiver to accept file")
            assert self.socket.recv(1) == b'\x06'  # ACK
        except KeyboardInterrupt:
            return printerror("User aborted operation")
        except AssertionError:
            return printerror("Receiver rejected")
        except timeout:
            return printerror("Operation timed out")
        except Exception:
            return printerror("Error while sending headers to receiver")

        print(f"[ {gethostname()}-{b64encode(self.token).decode()} ] "
              f"is now sending file ({ProgressBar.byte_rescale(fsize)})")

        # Progress bar thread
        self._progress_bar = ProgressBar(fsize, 40)
        self._progress_bar.start()

        def progress_thread():
            try:
                # Wait until sending file
                while not self._sending_file:
                    pass
                # Display until file is sent
                while not self._progress_bar.done:
                    self._progress_bar.display()
            except:
                return printerror("Error with progress thread")
        Thread(target=progress_thread).start()

        # Start sending
        res = None
        try:
            if self._transfer_type == 'S':
                res = self._send_s(fpath, fsize)
            elif self._transfer_type == 'M':
                res = self._send_m(fpath, fsizes)

            assert self.socket.recv(1) == b'\x06'  # ACK
        except:
            self._progress_bar.stop()
            self._sending_file = False
            return printerror(f"Sending file was unsuccessful")
        else:
            # Wait for progress bar
            while not self._progress_bar.done:
                pass
            self._progress_bar.display()

            print(f"\nSuccessfully sent: {fname}")
            return res

    def recv_param_set(self):
        """
        Receive and unpack Receiver's parameter settings.

        Used to set Sender's parameter settings used during data
        transmissions.
        """
        try:
            self.socket.connect((self.recver_ip, self.main_port))
        except error:
            return printerror("Can't connect to "
                              f"{self.recver_ip}:{self.main_port}")

        try:
            sender_hn = pack_str(gethostname())
            len_sender_hn = int_to_bytes_s(len(sender_hn))

            self.socket.send(b''.join([len_sender_hn, sender_hn]))

            assert self.socket.recv(1) == b'\x06'  # ACK
        except AssertionError:
            return printerror("Receiver rejected handshake")
        except timeout:
            return printerror('Operation timed out')
        except:
            return printerror("Error during handshake")

        try:
            len_hn = bytes_to_int_s(self.socket.recv(2))
            self._recver_hostname = unpack_str(self.socket.recv(len_hn))

            self._recver_token = self.socket.recv(6)

            self._transfer_type = unpack_str(self.socket.recv(1))

            len_wp = bytes_to_int_s(self.socket.recv(2))
            self._worker_ports = [bytes_to_int_s(self.socket.recv(2))
                                  for w in range(len_wp)]

            self.socket.send(b'\x06')  # ACK
        except error:
            return printerror("Error getting connected with socket")
        except:
            self.socket.send(b'\x15')  # NAK
            return printerror("Error getting parameters from receiver")
        else:
            self.param_set = True


class FlyterReciever:
    """
        Handles Flyter file receiving processes.

        Note: Receives from FlyterSender instances.

        Parameters
        ----------
        host_ip : str
            The Host IP address to be used.
        main_port : int
            The main TCP port to be used.
        num_workers : int
            The amount of workers to be used during transmission.
        """

    @staticmethod
    def storage_dir(hostname=None):
        """
        Return the path of the storage dir for received files.

        If storage directory doesn't exist, creates it first.

        Parameters
        ----------
        hostname : str
            The name of the subdirectory where that
            host's sent files are stored.
        """
        app_dirname = dirname(__file__)

        appfiles_dirname = join(app_dirname, 'Flyter')
        if not exists(appfiles_dirname):
            mkdir(appfiles_dirname)

        storage_dirname = join(appfiles_dirname, 'Received Files')
        if not exists(storage_dirname):
            mkdir(storage_dirname)

        if hostname:
            host_storage_dirname = join(storage_dirname, hostname)
            if not exists(host_storage_dirname):
                mkdir(host_storage_dirname)

            return host_storage_dirname
        else:
            return storage_dirname

    DEFAULT_PACKET_SIZE = 512

    def __init__(self, host_ip, main_port, num_workers):
        self.host_ip = host_ip
        self.main_port = main_port
        self.token = token_bytes(6)

        self.transfer_type = 'S' if num_workers == 1 else 'M'
        self.worker_ports = [
            random_port(self.host_ip) for w in range(num_workers)
        ] if num_workers > 1 else []

        self._sender_socket = None
        self._sender_hostname = None
        self._sender_token = None
        self._sender_filename = None
        self._sender_filesizes = None

        self._packet_size = FlyterSender.DEFAULT_PACKET_SIZE
        self._recving_file = False
        self._workers_active = 0

        self._progress_bar = ProgressBar(None)

        try:
            self.socket = socket(AF_INET, SOCK_STREAM)
            self.socket.bind((self.host_ip, self.main_port))
            self.socket.settimeout(60)

            self.workers = [
                socket(AF_INET, SOCK_STREAM) for w in range(num_workers)
            ] if num_workers > 1 else []

            if self.workers:
                for w in range(num_workers):
                    self.workers[w].bind((self.host_ip, self.worker_ports[w]))
                    self.workers[w].settimeout(60)
        except:
            printerror('Error initializing sockets')
        self.param_set = False

    def __del__(self):
        if isinstance(self.__dict__.get('socket'), socket):
            self.socket.close()
        if self.__dict__.get('workers'):
            for w in self.workers:
                w.close()

    def _recv_s(self):
        """Receive a file with a single worker."""
        if not self.param_set:
            return printerror("Sender not yet set with parameters")

        try:
            self._recving_file = True

            path = join(
                FlyterReciever.storage_dir(self._sender_hostname),
                self._sender_filename
            )
            fs = self._sender_filesizes[0]
            with open(path, 'bw') as f:
                while self._recving_file and fs:
                    packet = self._sender_socket.recv(self._packet_size)
                    f.write(packet)

                    self._progress_bar.add_progress(len(packet))
                    fs -= len(packet)

                    self._sender_socket.send(b'\x06')  # ACK
        except timeout:
            self._progress_bar.stop()
            return printerror("Operation timed out")
        except FileNotFoundError:
            self._progress_bar.stop()
            return printerror("Downloading file has been deleted")
        except PermissionError:
            self._progress_bar.stop()
            return printerror("Couldn't access storage directory")
        except error:
            self._progress_bar.stop()
            return printerror("Error with socket")
        except:
            self._progress_bar.stop()
            return printerror("Error receiving file")
        else:
            self._recving_file = False
            return True

    def _recv_m(self):
        """
        Receive a file with multiple workers.

        Speeds up transmission rate by using multiple workers.
        """
        if not self.param_set:
            return printerror("Sender not yet set with parameters")

        def threadfunc(worker_num, fpath):
            self._workers_active += 1

            try:
                recver_socket = self.workers[worker_num]
                recver_socket.listen(1)
                sender_socket, hostaddr = recver_socket.accept()

                send_tok = sender_socket.recv(6)
                if send_tok == self._sender_token:
                    sender_socket.send(b'\x06')  # ACK
                else:
                    sender_socket.send(b'\x15')  # NAK

                fs = self._sender_filesizes[worker_num]

                with open(fpath, 'bw') as f:
                    while self._recving_file and f.writable() and fs:
                        packet = sender_socket.recv(self._packet_size)
                        f.write(packet)

                        self._progress_bar.add_progress(len(packet))
                        fs -= len(packet)

                        sender_socket.send(b'\x06')  # ACK
            except KeyboardInterrupt:
                self._progress_bar.stop()
                self._recving_file = False
                return printerror("User aborted operation")
            except timeout:
                self._progress_bar.stop()
                self._recving_file = False
                return printerror("Operation timed out")
            except error:
                self._progress_bar.stop()
                self._recving_file = False
                return printerror("Error with sockets")
            except:
                self._progress_bar.stop()
                self._recving_file = False
                return printerror("Error while receiving file")
            finally:
                self._workers_active -= 1

        num_workers = len(self.workers)

        self._recving_file = True
        try:
            for w in range(len(self.worker_ports)):
                wpath = join(
                    FlyterReciever.storage_dir(self._sender_hostname),
                    f"{w}_{self._sender_filename}"
                )
                Thread(
                    target=threadfunc,
                    args=(w, wpath),
                ).start()
        except FileNotFoundError:
            return printerror("Couldn't access file")
        except PermissionError:
            return printerror("Couldn't access file due to permission error")

        while self._workers_active:
            try:
                pass
            except KeyboardInterrupt:
                self._progress_bar.stop()
                self._recving_file = False
                printerror("User aborted operation")

        self._recving_file = False

        try:
            # Build the file
            path = join(
                FlyterReciever.storage_dir(self._sender_hostname),
                self._sender_filename
            )
            with open(path, 'bw') as output:
                for w in range(num_workers):
                    wpath = join(
                        FlyterReciever.storage_dir(self._sender_hostname),
                        f"{w}_{self._sender_filename}"
                    )
                    with open(wpath, 'br') as temp:
                        packet = True
                        while packet:
                            packet = temp.read(self._packet_size)
                            output.write(packet)

                    # Clear the contents of the temp file
                    open(wpath, 'bw').close()

            # Delete the temp files
            for w in range(num_workers):
                wpath = join(
                    FlyterReciever.storage_dir(self._sender_hostname),
                    f"{w}_{self._sender_filename}"
                )
                unlink(wpath)
        except PermissionError:
            self._sender_socket.send(b'\x15')  # NAK
            return printerror("Couldn't save file due to permissions")
        except error:
            return printerror("Error with sockets")
        except:
            self._sender_socket.send(b'\x15')  # NAK
            return printerror("Error while saving file")
        else:
            return True

    def recv_file(self):
        """Receive a file."""
        if not self.param_set:
            return printerror("Not yet set with receiver's parameters")

        # Headers
        try:
            tok = self._sender_socket.recv(6)
            b64_tok = b64encode(tok).decode()

            len_fn = bytes_to_int_s(self._sender_socket.recv(2))
            fn = unpack_str(self._sender_socket.recv(len_fn))

            len_fs = bytes_to_int_s(self._sender_socket.recv(2))
            fs = [bytes_to_int_l(self._sender_socket.recv(4))
                  for s in range(len_fs)]
            fs_all = sum(fs)

            answer = input(f"{self._sender_hostname}-{b64_tok}"
                           f" wants to send: {fn} "
                           f"({ProgressBar.byte_rescale(fs_all)}). "
                           "Accept? (y/n) ")
            if answer.lower() == 'y':
                self._sender_socket.send(b'\x06')  # ACK
            else:
                self._sender_socket.send(b'\x06')  # NAK
                return printalert("Rejected file transfer")
        except error:
            return printerror("Sender isn't available anymore")
        except:
            self._sender_socket.send(b'\x15')  # NAK
            return printerror("Error while receiving headers")

        print(f"[ {gethostname()}-{b64encode(self.token).decode()} ] "
              f"is now receiving file ({ProgressBar.byte_rescale(fs_all)})")

        # Progress bar thread
        self._progress_bar = ProgressBar(fs_all, 35)
        self._progress_bar.start()

        def progress_thread():
            try:
                # Wait until receiving file
                while not self._recving_file:
                    pass
                # Display until file is received
                while not self._progress_bar.done:
                    self._progress_bar.display()
            except:
                return printerror("Error with progress thread")
        Thread(target=progress_thread).start()

        self._sender_token = tok
        self._sender_filename = fn
        self._sender_filesizes = fs

        # Start receiving
        try:
            if self.transfer_type == 'S':
                res = self._recv_s()
            elif self.transfer_type == 'M':
                res = self._recv_m()
            else:
                res = None
        except:
            self._progress_bar.stop()
            self._recving_file = False
            return printerror("Receiving file was unsuccessful")
        else:
            self._sender_socket.send(b'\x06')  # ACK

            # Wait for progress bar
            while not self._progress_bar.done:
                pass
            self._progress_bar.display()

            print(f"\nSuccessfully received: {self._sender_filename}")
            return res

    def send_param_set(self):
        """
        Pack and send Receiver's parameter settings.

        Used to set Sender's parameter settings used during
        data transmissions.
        """
        try:
            printalert("Waiting for sender")

            self.socket.listen(1)
            self._sender_socket, addrport = self.socket.accept()
        except timeout:
            return printerror("No sender available")
        except:
            return printerror("Error while waiting for sender")

        try:
            len_sender_hn = bytes_to_int_s(self._sender_socket.recv(2))
            sender_hn = self._sender_socket.recv(len_sender_hn)
            self._sender_hostname = unpack_str(sender_hn)

            self._sender_socket.send(b'\x06')  # ACK
        except timeout:
            return printerror("Operation timed out")
        except:
            return printerror("Error during handshake")

        try:
            hn = pack_str(gethostname())
            len_hn = int_to_bytes_s(len(hn))

            tok = self.token

            tr_type = pack_str(self.transfer_type)

            len_wp = int_to_bytes_s(len(self.worker_ports))
            wp = [int_to_bytes_s(port)
                  for port in self.worker_ports]
            wp = b''.join(wp)

            headers = b''.join([len_hn, hn, tok, tr_type, len_wp, wp])
        except:
            return printerror("Error building headers")

        try:
            self._sender_socket.send(headers)
            assert self._sender_socket.recv(1) == b'\x06'  # ACK
        except:
            return printerror("Error while sending headers to sender")
        else:
            self.param_set = True


# Simplified Functions


def send(ip_address, port, filepath):
    """
    Send file to receiver on the same network.

    Parameters
    ----------
    ip_address : str
        The target receiver's IP address.
    port : int
        The target receiver's main TCP port.
    filepath : str
        The path to the file to be sent.
    """
    sender = FlyterSender(ip_address, port)
    sender.recv_param_set()
    return sender.send_file(filepath)


def receive(host_ip_address, port, workers=1):
    """
    Receive a file from sender on the same network.

    Parameters
    ----------
    host_ip_address : str
        The receiver's host IP address.
    port : int
        The receiver's host port to listen on.
    workers : :obj:`int`, optional
        The number of workers to use.
    """
    receiver = FlyterReciever(host_ip_address, port, workers)
    receiver.send_param_set()
    receiver.recv_file()


if __name__ == '__main__':
    parser = ArgumentParser(
        prog="Flyter",
        epilog="See '<command> --help' to read about a specific sub-command."
    )

    subparsers = parser.add_subparsers(
        dest="action",
        help="The action to be performed"
    )

    send_parser = subparsers.add_parser("send")
    recv_parser = subparsers.add_parser("recv")

    send_parser.add_argument('-i', '--ip',
                             required=True,
                             help="Target receiver's IP address")
    send_parser.add_argument('-p', '--port',
                             type=int,
                             required=True,
                             help="Target receiver's TCP port number")
    send_parser.add_argument('-f', '--file',
                             required=True,
                             help="Path to the file to be sent")

    recv_parser.add_argument('-i', '--ip',
                             required=True,
                             help="Host IP address")
    recv_parser.add_argument('-p', '--port',
                             type=int,
                             required=True,
                             help="TCP port to listen on")
    recv_parser.add_argument('-w', '--workers',
                             type=int,
                             default=1,
                             help="TCP port to listen on")

    if len(argv) > 1:
        FROMTERMINAL = True

        args = parser.parse_args()

        if args.action == "send":
            send(args.ip, args.port, args.file)
        elif args.action == "recv":
            receive(args.ip, args.port, args.workers)
    else:
        parser.print_help()
