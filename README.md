# TunnelBot

Automates creation of reverse SSH tunnels for forwarding connections from 
Metasploit payloads. 

Steps included in script:

1. Nmap scan for vulnerable SSH servers
2. Find login credentials using Hydra brute force attack
3. Create reverse SSH tunnels between the attacker's machine and the victim
    machines
4. Launch Meterpreter session on single host

## Getting Started

### Prerequisites

[Metasploit](https://metasploit.help.rapid7.com/docs/installing-the-metasploit-framework) 
and [Hydra](https://github.com/vanhauser-thc/thc-hydra) must be installed. 

We recommend running the script on Kali Linux as Metasploit and Hydra are included
by default. 

### Setup

1. Download repository 

2. Install dependencies using pip

    ```
    pip install -r requirements.txt
    ```

## Usage
Display help 

```
./finalproject.py -h
```

Create SSH tunnel for single host with known credentials
```
./finalproject.py -l <ssh_username> -p <ssh_password> <host ip>
```

Launch Meterpreter session after tunnel establishment
```
./finalproject.py -l <ssh_username> -p <ssh_password> -e <host ip>
```

Use wordlists for username and password cracking
```
./finalproject.py -L <username file> -p <password file> <host ip(s)>
``` 


