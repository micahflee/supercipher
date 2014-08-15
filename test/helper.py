import os, random

def delete_file(filename):
    "helper: delete a file, if it exists"
    if os.path.exists(filename):
        os.remove(filename)

def random_string(length):
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(length))


