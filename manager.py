import socket
import os
import os.path
import policy_pb2
import signal
import sys
import json
import datetime
import subprocess
import argparse
from timeit import default_timer as timer
from google.protobuf.json_format import Parse
PORT=8992
DESCRIPTION = "goahead"
WORKSPACE ="/home/ashton/experiments/goahead/"
CONTAINERS_BASE = '/usr/local/var/lib/lxc/'
LEGIT_CONTAINER_NAME = 'c3'
MALWARE_CONTAINER_NAME= 'c4'
CUR_ROOT_PATH = CONTAINERS_BASE + LEGIT_CONTAINER_NAME + '/rootfs'
BACKUP_ROOT_PATH = CONTAINERS_BASE + LEGIT_CONTAINER_NAME + '/rootfs.backup'
BACKUP_SAFE_PATH = CONTAINERS_BASE + LEGIT_CONTAINER_NAME + '/rootfs.backup.safe'
DISCARD_INFECTED_TARGET = CONTAINERS_BASE + LEGIT_CONTAINER_NAME + '/infectedfs'
MALWARE_INFECTED_TARGET = CONTAINERS_BASE + MALWARE_CONTAINER_NAME + '/rootfs'
MALWARE_RESTORE_IMGS = '/home/ashton/u1604_backup/manager/restore_files'
MALWARE_RESTORE_IMGS_BACKUP = '/home/ashton/u1604_backup/manager/restore_files_backup'
CONTAINER_IP = "192.168.122.113"
MAL_CONTAINER_MAC = "00:16:3e:1e:d5:e7"
LEGIT_CONTAINER_MAC = "00:16:3e:2b:00:03"


class Restorer():
    def __init__(self):
        self.cur_workspace = None
        self.checkpoint_path = None
        self.policy_path = None
        self.container_name = LEGIT_CONTAINER_NAME
        self.mal_container_name = MALWARE_CONTAINER_NAME
        # all times except start are AFTER the event completed
        self.time_start = None
        self.time_preparation = None
        self.time_checkpoint = None
        self.time_fsswap = None
        self.time_restore = None


    def restore_system(self, policy_json):
        # these need to exist for this to work
        assert(os.path.exists(BACKUP_ROOT_PATH))
        assert(os.path.exists(CUR_ROOT_PATH))
        assert(not os.path.exists(DISCARD_INFECTED_TARGET))

        self.time_start = timer()
        self.prepare_workspace();
        self.create_policy(policy_json);
        self.time_preparation = timer()

        #self.start_routing(["192.168.122.126"])
        self.start_routing([policy_json['src_ip']] if policy_json else ['192.168.122.126'])
        self.exec_criu()
        self.dump_times()

        self.cleanup()

    def start_routing(self, blacklist):
        # log traffic from malicious container
        subprocess.check_call(["ebtables", "-t", "nat", "-I", "PREROUTING", "-s", "0:16:3e:1e:d5:e7", 
            "--log", "--log-prefix", "outbound malicious: ", "-j", "CONTINUE"])

        # array of strings of IPs to send to c4
        for b in blacklist:
            # reroute traffic from blacklisted address to malicious container
            subprocess.check_call(["ebtables",  "-t", "nat", "-I", "PREROUTING", "-i", "enp0s3",  "-p", "IPv4", 
                "--ip-dst", CONTAINER_IP, "--ip-source", b, "-j", "dnat", 
                "--to-destination", MAL_CONTAINER_MAC, "--log", "--log-prefix", "dnat blacklist: "])

    def prepare_workspace(self):
        self.cur_workspace = WORKSPACE + 'restore-' + datetime.datetime.now().strftime('%Y-%m-%dT%H-%M-%S') + '/'
        subprocess.check_call(['mkdir', self.cur_workspace])
        self.checkpoint_path = self.cur_workspace + 'checkpoint/'
        subprocess.check_call(['mkdir', self.checkpoint_path])
        # this is configuring the ip address for the container, but this is statically allocated
        os.system('killall dhclient');

    def cleanup(self):
        # restore the backup
        print('restoring backup...')
        subprocess.check_call(['cp', '-r', BACKUP_SAFE_PATH, BACKUP_ROOT_PATH])
        if args.discard_infected:
            subprocess.check_call(['rm', '-rf', DISCARD_INFECTED_TARGET])
        else:
            print("removing " + MALWARE_INFECTED_TARGET + '.\~*')
            #subprocess.check_call(['rm', '-rf', MALWARE_INFECTED_TARGET + '.\\~*'])
            os.system('rm -rf ' + MALWARE_INFECTED_TARGET + ".\\~*");
            print("restoring malware image files...")
            #subprocess.check_call(['cp', MALWARE_RESTORE_IMGS_BACKUP + '/*', 
            #    MALWARE_RESTORE_IMGS])
            os.system("cp " + MALWARE_RESTORE_IMGS_BACKUP + "/* " + MALWARE_RESTORE_IMGS)

    def exec_criu(self):
        # checkpoint dump
        try:
            print("checkpointing...")
            subprocess.check_call(['lxc-checkpoint', '-s', '-v',
                '-D', self.checkpoint_path, 
                '-n', self.container_name,
                '-o', self.cur_workspace + '/lxc-dump.log',
                '-l', 'DEBUG',
                '--policy', self.policy_path])
            self.time_checkpoint = timer()
            # reset filesystem (mv operation)
            print("resetting file path...")
            if args.discard_infected:
                subprocess.check_call(['mv', CUR_ROOT_PATH, DISCARD_INFECTED_TARGET])
            else:
                # move infected files to the malicious container
                subprocess.check_call(['mv', '--backup=numbered', CUR_ROOT_PATH, CONTAINERS_BASE + '/' + self.mal_container_name])
            subprocess.check_call(['mv', BACKUP_ROOT_PATH, CUR_ROOT_PATH])
            self.time_fsswap = timer()
            # checkpoint restore
            print("restoring legitimate container...")
            subprocess.check_call(['lxc-checkpoint', '-r', '-v',
                '-D', self.checkpoint_path, 
                '-n', self.container_name,
                '-o', self.cur_workspace + '/lxc-restore.log',
                '-l', 'DEBUG',
                '--base-path', CONTAINERS_BASE + '/' + self.container_name + '/rootfs/'])
            self.time_restore = timer()
            if not args.discard_infected:
                print("preparing restore files...")
                # replacing these files will keep the IP but change the MAC
                for f in ['ifaddr-9.img', 'netdev-9.img', 'route6-9.img', 'route-9.img']:
                    subprocess.check_call(['mv', MALWARE_RESTORE_IMGS + '/' + f, self.checkpoint_path])
                # don't need to omit any files
                subprocess.check_call(['mv', self.checkpoint_path + '/omit.img', self.checkpoint_path + '/omit.img.backup'])
                # save the old restore file
                subprocess.check_call(['mv', self.checkpoint_path + '/restore.log', self.checkpoint_path + '/restore.legit.log'])
                print("restoring malicious container...")
                subprocess.check_call(['lxc-checkpoint', '-r', '-v',
                    '-D', self.checkpoint_path, 
                    '-n', self.mal_container_name,
                    '-o', self.cur_workspace + '/lxc-restore-malware.log',
                    '-l', 'DEBUG',
                    '--base-path', CONTAINERS_BASE + '/' + self.mal_container_name + '/rootfs/'])
            


        except subprocess.CalledProcessError as e:
            print e
            print e.output

    def create_policy(self, policy_json):
        policy = None
        # if base policy path specified, use that, otherwise default to empty
        if args.base_policy_path:
            with open(args.base_policy_path, 'rb') as f:
                base_policy_str = f.read()

            policy = Parse(base_policy_str, policy_pb2.policy())
        else:
            policy = policy_pb2.policy()
            self.add_exe_name_policy(policy, 'fake');

       # redact_task_entry = policy.tasks.add()
        #redact_task_entry.match.magic = "banana"
        #raw_action = redact_task_entry.raw_actions.add()
        #raw_action.offset = 8
        #raw_action.replace_bytes = "apple"

        if (policy_json == None):
            print("warning: no policy specified, using default (empty)")
        elif (policy_json['trigger_type'] == 'snort'):
            print("adding destination IP address policy, blocks: " + policy_json['dst_ip'])
            self.add_tcp_policy(policy, policy_json['dst_ip'])
        elif (policy_json['trigger_type'] == 'clamav'):
            print("adding exe_name policy, blocks: " + policy_json['path'])
            self.add_exe_name_policy(policy, policy_json['path'])
        else:
            raise Exception("invalid trigger type")

        self.policy_path = self.cur_workspace + "policy.img"
        print("writing to " + self.policy_path)
        with open(self.policy_path, 'wb') as f:
            f.write(policy.SerializeToString())

    def add_tcp_policy(self, policy, match_val):
        tcp = policy.process_omit_matches.tcp_dest_ip_matches.add()
        tcp.match_str = match_val

    def add_exe_name_policy(self, policy, match_val):
        exe_match = policy.process_omit_matches.exe_name_matches.add()
        exe_match.match_str = match_val

    def dump_times(self):
        d = {
            "description" : DESCRIPTION,
            "prep_time" : self.time_preparation - self.time_start,
            "checkpoint_time" : self.time_checkpoint - self.time_preparation,
            "fsswap_time" : self.time_fsswap - self.time_checkpoint,
            "restore_time" : self.time_restore - self.time_fsswap,
            "total_time" : self.time_restore - self.time_start
        }
        j = json.dumps(d)
        with open(self.cur_workspace + "results.json", 'w') as f:
            json.dump(d, f)

#driver 
def listen() :
    r = Restorer()
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', PORT))
    serversocket.listen(5) # become a server socket, maximum 5 connections

    connection, address = serversocket.accept()
    #while True:
        # obvious race condition? we only need to handle one at a time
    buf = connection.recv(2048)
    j = json.loads(buf)
    print(j)
    r.restore_system(j)

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('action', choices=['listen', 'trigger', 'reinfect', 'ebtables-restore'],
    help='one of [listen, trigger]')
parser.add_argument("--policy-path", help="json file definining policy")
parser.add_argument("--discard-infected", action='store_true')
parser.add_argument("--base-policy-path", help="path to base policy (used for all restores)")

args = parser.parse_args()
if args.action == 'listen':
    print("listening")
    listen()
elif args.action == 'trigger':
    r = Restorer()
    policy_json = None
    if (args.policy_path):
        with open(args.policy_path, 'r') as f:
            policy_json = json.load(f)
    r.restore_system(policy_json)
elif args.action == 'reinfect':
    assert(os.path.exists(DISCARD_INFECTED_TARGET))
    assert(os.path.exists(CUR_ROOT_PATH))
    # need to restart so the filesystem changes take effect
    subprocess.check_call(['lxc-stop', '-n', LEGIT_CONTAINER_NAME])
    subprocess.check_call(['mv', CUR_ROOT_PATH, BACKUP_ROOT_PATH])
    subprocess.check_call(['mv', DISCARD_INFECTED_TARGET, CUR_ROOT_PATH])
    subprocess.check_call(['lxc-start', '-n', LEGIT_CONTAINER_NAME])
elif args.action == 'ebtables-restore':
    # restore ebtables to default
    subprocess.check_call(["ebtables", "-t", "nat", "-F"])
    # add back default routing rule
    subprocess.check_call(["ebtables", "-t", "nat", "-A", "PREROUTING", "-i", "enp0s3", "-p",  
        "IPv4", "-j", "dnat", "--to-destination", "00:16:3e:2b:00:03", "--log", "--log-prefix", "\"dnat default: \""])

else:
    print("invalid action");
