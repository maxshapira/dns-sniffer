# dns-sniffer

## Installation and Usage

To install and run the program, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/maxshapira/dns-sniffer.git

2. Navigate to the project directory:
    ```bash
    cd dns-sniffer/

3. Compile the program:
    ```bash
    make

4.  Run the program with the desired network interface:
    ```bash
    sudo ./dns-sniffer <interface>

    Example:
    sudo ./dns-sniffer eth0

5. Test the Program Using dig Commands

You can test the program by generating DNS traffic using the following dig commands:

IPv4 Query: dig @8.8.8.8 openai.com  
IPv6 Query: dig @8.8.8.8 www.google.com AAAA  
CNAME Query: dig @8.8.8.8 www.youtube.com  
CNAME Recursive Query:dig @8.8.8.8 www.gov.uk  
CNAME Compressed Query:dig @8.8.8.8 www.microsoft.com  

## Prerequisites
Ensure the following dependencies are installed:
- `libpcap` (for packet capturing)
- A Linux-based system with root privileges

