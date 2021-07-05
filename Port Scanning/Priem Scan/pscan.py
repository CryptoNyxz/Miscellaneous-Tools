from argparse import ArgumentParser
from math import ceil, log
from re import match
from random import shuffle
from shutil import get_terminal_size
from socket import socket
from socket import AF_INET, SOCK_STREAM
from socket import error
from sys import argv, exit
from threading import Thread
from time import sleep, time
from typing import List, Optional
from datetime import timedelta


__author__ = "Jaymund Cyrus Floranza (CryptoNyxz)"
__version__ = (0, 1, 0)
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


# Classes


class ProgressBar:
    """
    For displaying progress bars.
    :param max_value: The upper limit of the progress bar.
    """

    @staticmethod
    def rescale(num: int or float, precision: Optional[int] = 1) -> str:
        """
        Rescale the number by 10^3 to make it easier to read.
        :param num: The number to be rescaled.
        :param precision: The amount of precision of the
        :return: The string representation of the rescaled number.
        """
        scale = ['', 'K', 'M', 'B', 'T']

        index = int(log(num, 1000)) if num and num != float("inf") else 0

        rounded = round(num/pow(10, index), precision)

        return f"{rounded}{scale[index]}"

    def __init__(self, max_value: int or float):
        self.max_value = max_value
        self.current_val = 0

        self.rate = None
        self.start_time = None
        self.start_value = None

        self.stopped = True

    @property
    def done(self) -> bool:
        """
        Return if already finished.
        :return: The boolean value.
        """
        return self.current_val >= self.max_value or self.stopped

    def start(self):
        """Start the progress bar."""
        self.stopped = False
        self.start_time = time()
        self.start_value = self.current_val

    def stop(self):
        """Stop the progress bar."""
        self.stopped = True

    def add_progress(self, value: int or float):
        """
        Count new progress.
        :param value: Added progress value.
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
        length = int(0.35 * get_terminal_size().columns)

        per = d_value/d_max_value

        prog = int(length*per)
        extra = length*round(per) > prog

        prog_bar = '█'*prog + '▌'*extra
        spaces = ' '*(length - (prog + extra))

        rate = d_value/d_time if d_time else float('inf')

        eta_s = round((d_max_value - d_value)/rate) if rate else \
            None
        eta = timedelta(seconds=eta_s) if eta_s is not None else '?'

        clear_line = " "*(get_terminal_size().columns - 1)

        print(f"{clear_line}\r"
              "Progress: "
              f"|{prog_bar}{spaces}| "
              f"{100*per:.1f}% "
              f"({ProgressBar.rescale(d_value)}) "
              f"[{ProgressBar.rescale(rate)}/s] "
              f"ETA: {eta}", end="\r")

    def cont_display(self):
        """Continuously display progress bar using a separate Thread."""
        def inner():
            while not self.done and not self.stopped:
                self.display()
                sleep(5e-3)
            self.display()

        Thread(target=inner, daemon=False).start()


class PortScanner:
    """
    The port scanner class.
    :param randomized: If the port scan order should be randomized.
    :param delay: The amount of delay in seconds between each port scan.
    """

    @staticmethod
    def pprint_port(host: str, ports: List[int],
                    duration: float or int) -> None:
        """
        Display TCP ports in a more readable form.
        :param host: The target host's address, IP address or domain name.
        :param ports: The TCP ports to be displayed.
        :param duration: The total duration of the scan.
        """
        table_width = (get_terminal_size().columns // 7) - 2
        table_height = ceil(len(ports) / table_width)

        table_top = (
            7 * ' '
            + '┌'
            + '─'*(table_width * 7)
            + '┐\r\n'
        )
        row_sep = '\r\n' + 7*' ' + '├' + '-'*(table_width * 7) + '┤\r\n'
        table_bottom = (
            '\r\n'
            + 7 * ' '
            + '└'
            + '─' * (table_width * 7)
            + '┘'
        )

        rows = [
            7 * ' '
            + '│'
            + f"Open TCP Ports at {host} ({len(ports)})".center(7*table_width)
            + '│\r\n'
            + 7 * ' '
            + '│'
            + f"Scan took: {timedelta(seconds=duration)}".center(7*table_width)
            + '│'
        ]
        rows += [
            7 * ' '
            + '│'
            + ''.join([
                str(port).center(7)
                for port in ports[r*table_width: (r + 1)*table_width]
            ])
            + 7*' ' * (
                    table_width
                    - len(ports[r*table_width: (r + 1)*table_width])
            )
            + '│'
            for r in range(table_height)
        ]

        print(table_top + row_sep.join(rows) + table_bottom)

    def __init__(self, randomized: Optional[bool] = False,
                 delay: Optional[int or float] = 0):
        self.randomized = randomized
        self.delay = delay

        # Last scan results
        self.open_ports = []
        self.scan_duration = 0

        self.progress_bar = None

    def check_open(self, host: str, port: int) -> int or None:
        """
        Check if the host:port pair is open to TCP Connections.
        :param host: The target host's address, IP address or domain name.
        :param port: The target port to be checked.
        :return: The port if open, None if not.
        """
        try:
            with socket(AF_INET, SOCK_STREAM) as sock:
                sock.connect((host, port))

            self.open_ports.append(port)
        except error:
            pass
        finally:
            if isinstance(self.progress_bar, ProgressBar):
                self.progress_bar.add_progress(1)

    def scan(self, host: str,
             port_range: Optional[range] = range(1, 65536)) -> List[int]:
        """
        Scan for open ports.
        :param host: The target host's address, IP address or domain name.
        :param port_range: The range of ports to scan.
        :return: The list of open TCP ports.
        """
        if not (port_range and
                port_range.start >= 1 and port_range.stop <= 65536):
            raise ValueError("Port number must be within range (1, 65536)")

        time_init = time()

        # Reset previous scan results
        self.open_ports = []

        # Initialize threads
        threads = []
        for i in range(len(port_range)):
            threads.append(Thread(
                target=self.check_open,
                args=(host, port_range[i]),
                daemon=False
            ))

        # Shuffle thread order if randomized scan option is set
        if self.randomized:
            shuffle(threads)

        # Display progress bar
        self.progress_bar = ProgressBar(len(port_range))
        self.progress_bar.start()
        self.progress_bar.cont_display()

        # Start the scan
        for thread in threads:
            thread.start()
            sleep(self.delay)

        # Wait while still scanning
        while not self.progress_bar.done:
            pass

        # A little cooldown to make sure progress bar finishes
        # before displaying results
        sleep(5e-2)

        # Determine Scan Duration
        self.scan_duration = time() - time_init

        # Sort the results because it might not be in order due to
        # the nature of multithreaded programs, or maybe the scan order
        # was randomized
        self.open_ports.sort()

        return self.open_ports


# Shortened Functions

def port_scan(host: str, randomized: Optional[bool] = False,
              delay: Optional[float or int] = 0,
              port_range: Optional[range] = range(1, 65536),
              pretty_print: Optional[bool] = False) -> List[int] or None:
    """
    Scan target host for open TCP ports.
    :param host: The target host's address, IP address or domain name.
    :param randomized: If the port scan order should be randomized.
    :param delay: The amount of delay in seconds between each port scan.
    :param port_range: The range of ports to scan.
    :param pretty_print: If the results should be pretty-printed instead of
    returning the list of open ports.
    :return: If pretty-printed, return None, if not, return the list of
    open ports
    """
    ps = PortScanner(randomized, delay)
    open_ports = ps.scan(host, port_range)

    if pretty_print:
        PortScanner.pprint_port(host, open_ports, ps.scan_duration)
    else:
        return open_ports


if __name__ == "__main__":
    parser = ArgumentParser(
        prog="Priem Scan",
        epilog="Scan for open TCP ports.\nMade by CryptoNyxz"
    )

    parser.add_argument('-r', '--random',
                        action='store_true',
                        help="Randomize the port scan order.")
    parser.add_argument('-d', '--delay',
                        required=False,
                        type=float,
                        default=0,
                        help="The delay between each port scan.")
    parser.add_argument('-P', '--portrange',
                        required=False,
                        type=str,
                        help="Port range, for example:\n"
                             "For ports 24 to 1024:\n"
                             "-p 24-1024")

    parser.add_argument('-H', '--host',
                        required=True,
                        type=str,
                        help="The target host's address, "
                             "IP address or domain name")

    if len(argv) > 1:
        args = parser.parse_args()

        if isinstance(args.portrange, str):
            if not match(r'\d+-+\d', args.portrange):
                print("Port range argument must follow the format: a-b")
                exit(-2)

            args.portrange = map(int, args.portrange.split('-'))
            args.portrange = range(*args.portrange)

            if not (args.portrange
                    and args.portrange.start >= 1
                    and args.portrange.stop <= 65536):
                print("Port number must be within range (1, 65536)")
                exit(-3)
        else:
            args.portrange = range(1, 65536)

        port_scan(args.host, args.random, args.delay, args.portrange, True)
    else:
        parser.print_help()
