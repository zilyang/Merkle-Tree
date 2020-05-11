# -*- coding: utf-8 -*-
"""
Created on Sat Apr 18 23:02:39 2020

@author: yangz
"""

import os
from binascii import hexlify, unhexlify
import hashlib


        
class Merkle_tree:
    def __init__(self):
        self.cert_id = {} #dictionary of certificates added to log and their ids
        self.size = 0 #Number of certificates in log
        self.root = None
        self.parent_height = {} #dict of parent's heights
        self.height = 1
    
    def make_tree(self, list_of_certs):
        # Add a list of certificates to the an empty or none empty log
        #handle case when there are odd number of certificates
        if len(list_of_certs)%2!= 0:
            list_of_certs.append(list_of_certs[-1])
        
        l = len(list_of_certs)
        power_two = find_max_power_two(l)[0]
        tree = make_sub_tree(list_of_certs[:power_two])
        self.cert_id = tree.cert_id
        self.size = tree.size
        self.root = tree.root
        self.parent_height = tree.parent_height
        self.height = tree.height 
        remainder = l - power_two
        list_of_certs = list_of_certs[power_two:]
        cum = power_two+1
        while remainder != 0:
            power_two = find_max_power_two(remainder)[0]
            sub_tree = make_sub_tree(list_of_certs[:power_two])
            for i in range(len(list_of_certs[:power_two])):
                self.cert_id[list_of_certs[i]] = cum
                cum = cum + 1
            list_of_certs = list_of_certs[power_two:]
            root = hashlib.sha256(unhexlify(self.root) +unhexlify(sub_tree.root)).hexdigest()
            self.root = root
            diff = self.height-sub_tree.height
            self.height = self.height+1
            self.parent_height[self.height] = [root]
            for i in range(1, sub_tree.height+1):
                self.parent_height[i+diff] = self.parent_height[i+diff]+sub_tree.parent_height[i]
            remainder = remainder - power_two            

def audit_path(log, cert):
    #return audit path given log and certificate
    path = []
    parent_height = log.parent_height
    ID = log.cert_id[cert]
    layer = parent_height[1]
    power_two = find_max_power_two(log.size)[0]
    interval = power_two
    ID - power_two
    displacement = find_max_power_two(power_two)[1]-2
    next_pos = ID-1
    i = 1
    while ID > interval:
        
        
        power_two = power_two//2
        subheight = find_max_power_two(power_two)[1] + 1
        i = log.height - subheight - displacement
        displacement = displacement - 1
        next_pos = len(log.parent_height[i])+(ID - interval - 1)-power_two

        interval = interval + (power_two)
    
    while i != log.height:
        if (next_pos+1)%2 != 0:
            layer = parent_height[i]
            v = next_pos+1
            path.append([i,v])
            next_pos = (((next_pos+1)//2))%len(layer)
            i = i+1
        if (next_pos+1)%2 == 0:
            layer = parent_height[i]
            v = next_pos-1
            path.append([i,v])
            next_pos = (((next_pos)//2))%len(layer)
            i = i+1
    return path

def make_sub_tree(list_of_certs):
    #Given a partial list_of_certs with size of power of two and constructs a balanced Merkel tree
    log = Merkle_tree()
    q1 = []
    for i in range (0, len(list_of_certs), 2):
        current = list_of_certs[i]
        current_hash = hashlib.sha256(list_of_certs[i]).hexdigest()
        q1.append(current_hash)
        log.size = log.size + 1
        log.cert_id[list_of_certs[i]] = log.size
            
        if (i + 1) != len(list_of_certs):
            log.size = log.size + 1
            log.cert_id[list_of_certs[i+1]] = log.size
            current_right = list_of_certs[i+1]
            current_right_hash = hashlib.sha256(current_right).hexdigest()
            q1.append(current_right_hash)
    
    q2 = []
    while len(q1) + len(q2) != 1:
        log.parent_height[log.height] = []
        while q1 != []:
            left = q1.pop(0)
            right = q1.pop(0)
            log.parent_height[log.height].append(left)
            log.parent_height[log.height].append(right)
            parent = hashlib.sha256(unhexlify(left) +unhexlify(right)).hexdigest()
            q2.append(parent)
    
                
        log.height = log.height +1 
        log.parent_height[log.height] = []
        if len(q1) + len(q2) == 1:
            break
        while q2 != []:
            left = q2.pop(0)
            right = q2.pop(0)
            log.parent_height[log.height].append(left)
            log.parent_height[log.height].append(right)
            parent = hashlib.sha256(unhexlify(left) + unhexlify(right)).hexdigest()
            q1.append(parent)
        log.height = log.height +1 

    if q1 != []:
        root = q1[0]
    if q2 != []:
        root = q2[0]  
        
    log.root = root
    log.parent_height[log.height] = [log.root]
    return log

def Create_cert(s, l):
   #Creates a list of length l with random certificates of s bits 
   return([os.urandom(s) for i in range(l)])
   
def find_max_power_two(l):
    #given integer, return maximum power of two and power
    power_two = 2
    i = 1
    while (power_two*2) <= l:
        power_two = power_two*2
        i = i+1
    return power_two, i

def test(s, pos):
    #takes input s as number of certificates on the log and pos as the position of certificate to audit
    assert(pos<s)
    log = Merkle_tree()
    cert = Create_cert(8, s)
    log.make_tree(cert)
    path = audit_path(log, cert[pos])
    h = hashlib.sha256(cert[pos]).hexdigest()
    for i in range(len(path)):
        l = log.parent_height[path[i][0]]
        if path[i][1]%2 == 0:
            h = hashlib.sha256(unhexlify(l[path[i][1]]) +unhexlify(h)).hexdigest()
        if path[i][1]%2 != 0:
            h = hashlib.sha256(unhexlify(h) +unhexlify(l[path[i][1]])).hexdigest()
    
    if (log.root == h):
        print('test passed')
    if log.root!=h:
        print('test failed')
    
def main():
    print('test 1: s = 4 pos = 1 \n')
    test(4, 1)
    print('\n')
    print('test 2: s = 7 pos = 6 \n')
    test(7, 6)
    print('\n')
    print('test 3: s = 16 pos = 0 \n')
    test(16, 0)
    print('\n')
    print('test 4: s = 22 pos = 6 \n')
    test(22, 6)
    print('\n')
    
    
if __name__ == '__main__':
     main()
    
    
    
    



