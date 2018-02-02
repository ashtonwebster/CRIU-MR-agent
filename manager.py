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
PORT=8991
DESCRIPTION = "linux_lady"
WORKSPACE ="/tmp/"
CONTAINERS_BASE = '/usr/local/var/lib/lxc/'
CONTAINER_NAME = 'c2'
CUR_ROOT_PATH = CONTAINERS_BASE + CONTAINER_NAME + '/rootfs'
BACKUP_ROOT_PATH = CONTAINERS_BASE + CONTAINER_NAME + '/rootfs.backup'
BACKUP_SAFE_PATH = CONTAINERS_BASE + CONTAINER_NAME + '/rootfs.backup.safe'
INFECTED_TARGET = CONTAINERS_BASE + CONTAINER_NAME + '/infectedfs'

class Restorer():
    def __init__(self):
        self.cur_workspace = None
        self.checkpoint_path = None
        self.policy_path = None
        self.container_name = CONTAINER_NAME
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
        assert(not os.path.exists(INFECTED_TARGET))

        self.time_start = timer()
        self.prepare_workspace();
        self.create_policy(policy_json);
        self.time_preparation = timer()

        self.exec_criu()
        self.dump_times()

        self.cleanup()

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
            subprocess.check_call(['rm', '-rf', INFECTED_TARGET])

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
            subprocess.check_call(['mv', CUR_ROOT_PATH, INFECTED_TARGET])
            subprocess.check_call(['mv', BACKUP_ROOT_PATH, CUR_ROOT_PATH])
            self.time_fsswap = timer()
            # checkpoint restore
            print("restoring...")
            subprocess.check_call(['lxc-checkpoint', '-r', '-v',
                '-D', self.checkpoint_path, 
                '-n', self.container_name,
                '-o', self.cur_workspace + '/lxc-restore.log',
                '-l', 'DEBUG',
                '--base-path', CONTAINERS_BASE + '/' + self.container_name + '/rootfs/'])
            self.time_restore = timer()
        except subprocess.CalledProcessError as e:
            print e
            print e.output

    def create_policy(self, policy_json):
        policy = policy_pb2.policy()
        self.add_exe_name_policy(policy, 'fake');
        # TODO: add base policy elements, like apache only having clones for kids
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
parser.add_argument('action', choices=['listen', 'trigger', 'reinfect'],
    help='one of [listen, trigger]')
parser.add_argument("--policy_path", help="json file definining policy")
parser.add_argument("--discard-infected", action='store_true')

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
    assert(os.path.exists(INFECTED_TARGET))
    assert(os.path.exists(CUR_ROOT_PATH))
    # need to restart so the filesystem changes take effect
    subprocess.check_call(['lxc-stop', '-n', CONTAINER_NAME])
    subprocess.check_call(['mv', CUR_ROOT_PATH, BACKUP_ROOT_PATH])
    subprocess.check_call(['mv', INFECTED_TARGET, CUR_ROOT_PATH])
    subprocess.check_call(['lxc-start', '-n', CONTAINER_NAME])




else:
    print("invalid action");
